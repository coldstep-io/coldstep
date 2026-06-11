import * as core from '@actions/core';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as https from 'https';
import * as os from 'os';
import * as path from 'path';

export const MAX_READY_STATUS_JSON_BYTES = 512 * 1024;

// Pinned coldstep agent release. Only the version is bumped at release time;
// the expected SHA-256 is fetched at runtime from the GitHub Releases API so we
// don't have to hardcode an asset digest the supply-chain-attest build produces
// only after the tag is pushed.
export const COLDSTEP_BINARY_VERSION = 'v0.5.3';
export const COLDSTEP_BINARY_ASSET_NAME = 'coldstep-linux-amd64';
export const COLDSTEP_BINARY_REPO = 'coldstep-io/coldstep';
export const COLDSTEP_BINARY_URL =
  `https://github.com/${COLDSTEP_BINARY_REPO}/releases/download/${COLDSTEP_BINARY_VERSION}/${COLDSTEP_BINARY_ASSET_NAME}`;

// JS actions never get GITHUB_ACTION_PATH (composite-only) and cwd() is the consumer workspace,
// so derive the action root from this bundle's location: dist/{pre,main,post}/index.js → root.
export function actionRootPath(): string {
  return path.resolve(__dirname, '..', '..');
}

// resolveUnderTrustedRoots canonicalises p (realpath, so symlinks cannot smuggle
// the target elsewhere) and asserts it lives under one of the trusted roots:
// GITHUB_WORKSPACE, RUNNER_TEMP, os.tmpdir(), or cwd. Mirrors the Go side's
// safepath.Workspace — used for release-path, whose bytes are executed under
// sudo. Returns the resolved path, or null when containment fails.
export function resolveUnderTrustedRoots(p: string): string | null {
  let resolved: string;
  try {
    resolved = fs.realpathSync(p);
  } catch {
    return null;
  }
  const roots: string[] = [];
  for (const raw of [process.env.GITHUB_WORKSPACE, process.env.RUNNER_TEMP, os.tmpdir(), process.cwd()]) {
    if (!raw) continue;
    try {
      roots.push(fs.realpathSync(raw));
    } catch {
      roots.push(path.resolve(raw));
    }
  }
  for (const root of roots) {
    const rel = path.relative(root, resolved);
    if (rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel))) {
      return resolved;
    }
  }
  return null;
}

export function inputBoolDefault(name: string, defaultVal: boolean): boolean {
  const v = core.getInput(name);
  if (v === '') return defaultVal;
  return ['true', '1', 'yes', 'on'].includes(v.toLowerCase());
}

// cachedColdstepBinaryPath returns the path to the already-downloaded agent
// binary if it is present in the per-version cache, else null. The start step
// downloads + SHA-256-verifies it (ensureColdstepBinary); the stop step uses
// this to render the report WITHOUT a fresh GitHub Releases API round-trip, so a
// transient API failure / unauthenticated rate-limit at the post step cannot
// drop the report. Falls back to ensureColdstepBinary only on a cache miss.
export function cachedColdstepBinaryPath(): string | null {
  const cacheRoot = process.env.RUNNER_TEMP || os.tmpdir();
  const binPath = path.join(cacheRoot, 'coldstep-action', COLDSTEP_BINARY_VERSION, 'coldstep');
  return fs.existsSync(binPath) ? binPath : null;
}

// Seeds the binary cache from a release-path staged binary so later phases
// (stop's report render) find it via cachedColdstepBinaryPath and never need
// the Releases API. Without this, a release PR — which pins the NEXT,
// not-yet-published COLDSTEP_BINARY_VERSION under the single-train flow —
// silently dropped the report at stop time (404 on the unpublished release).
// Best-effort: the source binary is already containment-checked by start.
export function seedColdstepBinaryCache(binPath: string): void {
  const cacheRoot = process.env.RUNNER_TEMP || os.tmpdir();
  const cacheDir = path.join(cacheRoot, 'coldstep-action', COLDSTEP_BINARY_VERSION);
  const dst = path.join(cacheDir, 'coldstep');
  try {
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.copyFileSync(binPath, dst);
    fs.chmodSync(dst, 0o755);
    core.info(`coldstep: seeded binary cache ${dst} from release-path`);
  } catch (e) {
    core.warning(`coldstep: failed to seed binary cache from release-path: ${e instanceof Error ? e.message : String(e)}`);
  }
}

export function agentStatusPath(): string {
  const baseDir = process.env.GITHUB_WORKSPACE || actionRootPath();
  return path.join(baseDir, '.coldstep-ready.json');
}

export function eventsLogPath(): string {
  const baseDir = process.env.GITHUB_WORKSPACE || actionRootPath();
  return path.join(baseDir, '.coldstep-events.jsonl');
}

function sha256File(p: string): string {
  const h = createHash('sha256');
  h.update(fs.readFileSync(p));
  return h.digest('hex');
}

interface GitHubReleaseAsset {
  name: string;
  digest?: string;
}

interface GitHubRelease {
  assets: GitHubReleaseAsset[];
}

async function fetchReleaseJSON(url: string, token: string, maxRedirects = 3): Promise<GitHubRelease> {
  const headers: Record<string, string> = {
    'User-Agent': 'coldstep-action',
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  return new Promise((resolve, reject) => {
    const visit = (current: string, remaining: number): void => {
      const req = https.get(current, { headers }, (res) => {
        const status = res.statusCode ?? 0;
        if ((status === 301 || status === 302 || status === 307 || status === 308) && res.headers.location) {
          res.resume();
          if (remaining <= 0) {
            reject(new Error(`too many redirects fetching ${url}`));
            return;
          }
          const next = new URL(res.headers.location, current).toString();
          visit(next, remaining - 1);
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          if (status !== 200) {
            reject(new Error(`GitHub API ${status} fetching ${current}: ${body.slice(0, 300)}`));
            return;
          }
          try {
            resolve(JSON.parse(body) as GitHubRelease);
          } catch (e) {
            reject(e instanceof Error ? e : new Error(String(e)));
          }
        });
      });
      req.on('error', reject);
      req.setTimeout(30_000, () => req.destroy(new Error(`timeout fetching ${current}`)));
    };
    visit(url, maxRedirects);
  });
}

async function fetchExpectedAssetSha256(token: string): Promise<string> {
  const apiURL = `https://api.github.com/repos/${COLDSTEP_BINARY_REPO}/releases/tags/${COLDSTEP_BINARY_VERSION}`;
  const release = await fetchReleaseJSON(apiURL, token);
  const asset = release.assets.find((a) => a.name === COLDSTEP_BINARY_ASSET_NAME);
  if (!asset) {
    throw new Error(
      `coldstep: release ${COLDSTEP_BINARY_VERSION} has no asset named ${COLDSTEP_BINARY_ASSET_NAME}`,
    );
  }
  const digest = asset.digest ?? '';
  if (!digest.startsWith('sha256:')) {
    throw new Error(
      `coldstep: asset ${COLDSTEP_BINARY_ASSET_NAME} on release ${COLDSTEP_BINARY_VERSION} is missing a sha256 digest (got: ${digest || '<none>'}). ` +
        `Re-run supply-chain-attest on the tag, or upgrade to a release whose asset has a digest.`,
    );
  }
  const sha = digest.slice('sha256:'.length).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(sha)) {
    throw new Error(`coldstep: asset digest is not a valid sha256 hex (got: ${digest})`);
  }
  return sha;
}

async function downloadToFile(url: string, destPath: string, maxRedirects = 5): Promise<void> {
  return new Promise((resolve, reject) => {
    const visit = (current: string, remaining: number): void => {
      const req = https.get(current, (res) => {
        const status = res.statusCode ?? 0;
        if ((status === 301 || status === 302 || status === 307 || status === 308) && res.headers.location) {
          res.resume();
          if (remaining <= 0) {
            reject(new Error(`too many redirects fetching ${url}`));
            return;
          }
          const next = new URL(res.headers.location, current).toString();
          visit(next, remaining - 1);
          return;
        }
        if (status !== 200) {
          res.resume();
          reject(new Error(`HTTP ${status} fetching ${current}`));
          return;
        }
        const tmp = `${destPath}.partial-${process.pid}-${Date.now()}`;
        const out = fs.createWriteStream(tmp, { mode: 0o755 });
        res.pipe(out);
        out.on('finish', () => {
          out.close((err) => {
            if (err) {
              try { fs.unlinkSync(tmp); } catch { /* ignore */ }
              reject(err);
              return;
            }
            try {
              fs.renameSync(tmp, destPath);
              resolve();
            } catch (e) {
              try { fs.unlinkSync(tmp); } catch { /* ignore */ }
              reject(e instanceof Error ? e : new Error(String(e)));
            }
          });
        });
        out.on('error', (err) => {
          try { fs.unlinkSync(tmp); } catch { /* ignore */ }
          reject(err);
        });
      });
      req.on('error', reject);
      req.setTimeout(60_000, () => req.destroy(new Error(`timeout fetching ${current}`)));
    };
    visit(url, maxRedirects);
  });
}

// Resolves a usable coldstep binary, downloading the pinned release asset on first use
// and caching it under RUNNER_TEMP/coldstep-action/<version>/coldstep. The expected
// SHA-256 is queried from the GitHub Releases API at runtime so we don't have to
// hardcode (and chase) a digest the supply-chain-attest build produces only after the
// tag has been pushed.
export async function ensureColdstepBinary(): Promise<string> {
  if (process.arch !== 'x64') {
    throw new Error(`coldstep: unsupported arch ${process.arch} — only linux/amd64 is published`);
  }

  const token = core.getInput('github-token') || process.env.GITHUB_TOKEN || '';
  const expectedSha = await fetchExpectedAssetSha256(token);

  const cacheRoot = process.env.RUNNER_TEMP || os.tmpdir();
  const cacheDir = path.join(cacheRoot, 'coldstep-action', COLDSTEP_BINARY_VERSION);
  const binPath = path.join(cacheDir, 'coldstep');
  fs.mkdirSync(cacheDir, { recursive: true });

  if (fs.existsSync(binPath)) {
    const got = sha256File(binPath);
    if (got === expectedSha) {
      try { fs.chmodSync(binPath, 0o755); } catch { /* ignore */ }
      core.info(`coldstep: reusing cached binary ${binPath} (${COLDSTEP_BINARY_VERSION})`);
      return binPath;
    }
    core.warning(`coldstep: cached binary sha mismatch (${got}); re-downloading`);
    try { fs.unlinkSync(binPath); } catch { /* ignore */ }
  }

  core.info(`coldstep: downloading ${COLDSTEP_BINARY_VERSION} from ${COLDSTEP_BINARY_URL}`);
  // Retry transient failures (GitHub Releases CDN 5xx, timeouts, network resets).
  // A single fetch failed CI on a transient HTTP 500; the download is now the
  // consumer path, so a flaky CDN must not fail the whole job. A 404 (asset not
  // published) is permanent — do not retry it.
  {
    const maxAttempts = 4;
    for (let attempt = 1; ; attempt++) {
      try {
        await downloadToFile(COLDSTEP_BINARY_URL, binPath);
        break;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        const permanent = /HTTP 4\d\d /.test(msg);
        if (permanent || attempt >= maxAttempts) throw e;
        const delayMs = 1000 * attempt;
        core.warning(`coldstep: download attempt ${attempt} failed (${msg}); retrying in ${delayMs}ms`);
        await new Promise((r) => setTimeout(r, delayMs));
      }
    }
  }
  const got = sha256File(binPath);
  if (got !== expectedSha) {
    try { fs.unlinkSync(binPath); } catch { /* ignore */ }
    throw new Error(
      `coldstep: downloaded binary sha256 mismatch — expected ${expectedSha} (from GitHub Releases API), got ${got} (url=${COLDSTEP_BINARY_URL})`,
    );
  }
  fs.chmodSync(binPath, 0o755);
  core.info(`coldstep: binary ready at ${binPath}`);
  return binPath;
}

export function readAgentReadyOk(statusPath: string): boolean {
  try {
    if (!fs.existsSync(statusPath)) return false;
    const buf = fs.readFileSync(statusPath);
    if (buf.length > MAX_READY_STATUS_JSON_BYTES) return false;
    const j = JSON.parse(buf.toString('utf8')) as { ok?: boolean };
    return j.ok === true;
  } catch {
    return false;
  }
}

// --- Allow-list parsing ---

function splitTokens(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((t) => t.replace(/#.*$/, '').trim())
    .filter((t) => t.length > 0);
}

// Caps mirroring the Go side (maxAllowlistFiles / maxAllowlistFileBytes in
// internal/actioncli): a pathological multi-GiB workspace file or a sprawling
// comma list must not OOM the runner before parsing even starts.
const MAX_ALLOW_FILES = 64;
const MAX_ALLOW_FILE_BYTES = 8 * 1024 * 1024;

function readFileTokensSafe(filePaths: string, baseDir: string): string[] {
  if (!filePaths.trim()) return [];
  const tokens: string[] = [];
  const paths = filePaths.split(',').map((s) => s.trim()).filter(Boolean);
  if (paths.length > MAX_ALLOW_FILES) {
    core.warning(`allow-file: ${paths.length} files exceeds maximum ${MAX_ALLOW_FILES}; ignoring the rest`);
    paths.length = MAX_ALLOW_FILES;
  }
  for (const fp of paths) {
    const absPath = path.isAbsolute(fp) ? fp : path.join(baseDir, fp);
    try {
      const stat = fs.statSync(absPath);
      if (stat.size > MAX_ALLOW_FILE_BYTES) {
        core.warning(`allow-file: ${absPath} is ${stat.size} bytes (max ${MAX_ALLOW_FILE_BYTES}); skipping`);
        continue;
      }
      tokens.push(...splitTokens(fs.readFileSync(absPath, 'utf8')));
    } catch (e) {
      core.warning(`allow-file: could not read ${absPath}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return tokens;
}

// IPv4 literal or CIDR: x.x.x.x or x.x.x.x/nn
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

interface ParsedTokens {
  allowedIPs: string[];
  ignoredNets: string[];
  allowedHosts: string[];
  allowedDomains: string[];
}

function classifyTokens(tokens: string[]): ParsedTokens {
  const allowedIPs: string[] = [];
  const ignoredNets: string[] = [];
  const allowedHosts: string[] = [];
  const allowedDomains: string[] = [];
  for (const token of tokens) {
    if (token.startsWith('!')) {
      const inner = token.slice(1);
      if (IPV4_RE.test(inner)) {
        ignoredNets.push(inner);
      } else {
        core.warning(`allow: unrecognized negation token "${token}" (expected !IPv4 or !CIDR); skipped`);
      }
    } else if (IPV4_RE.test(token)) {
      allowedIPs.push(token);
    } else {
      // Plain or wildcard domain — goes to both lists for full coverage
      allowedHosts.push(token);
      allowedDomains.push(token);
    }
  }
  return { allowedIPs, ignoredNets, allowedHosts, allowedDomains };
}

function mergeUnique(...arrays: string[][]): string {
  return [...new Set(arrays.flat().filter(Boolean))].join(',');
}

export interface AllowlistResult {
  allowedIPs: string;
  ignoredNets: string;
  allowedHosts: string;
  allowedDomains: string;
}

export function resolveAllowlist(baseDir: string): AllowlistResult {
  const tokens = [
    ...splitTokens(core.getInput('allow')),
    ...readFileTokensSafe(core.getInput('allow-file'), baseDir),
  ];
  const parsed = classifyTokens(tokens);

  // Ignored nets come solely from `!CIDR` entries in allow / allow-file
  // (classifyTokens routed them into parsed.ignoredNets). The ignored-nets,
  // ignored-nets-file, and bootstrap-allowlist inputs were removed.
  return {
    allowedIPs: mergeUnique(parsed.allowedIPs),
    ignoredNets: mergeUnique(parsed.ignoredNets),
    allowedHosts: mergeUnique(parsed.allowedHosts),
    allowedDomains: mergeUnique(parsed.allowedDomains),
  };
}

// warnRemovedAllowlistInputs emits a warning when a consumer still sets an
// input removed in the allowlist consolidation (ignored-nets, ignored-nets-file,
// bootstrap-allowlist), turning a silent breakage into an actionable message.
export function warnRemovedAllowlistInputs(): void {
  const removed: Array<[string, string]> = [
    ['ignored-nets', 'put `!CIDR` entries in `allow`'],
    ['ignored-nets-file', 'put `!CIDR` lines in an `allow-file`'],
    ['bootstrap-allowlist', 'copy the reference packs into your own `allow-file`'],
  ];
  for (const [name, repl] of removed) {
    if (core.getInput(name).trim() !== '') {
      core.warning(`coldstep: input \`${name}\` was removed in the allowlist consolidation; ${repl}`);
    }
  }
}

// --- Feature-gate resolution (detect-profile only) ---

export function resolveFeatureGates(): string {
  const detectProfile = (core.getInput('detect-profile') || 'standard').trim().toLowerCase();
  if (detectProfile !== 'enhanced') return '';
  return 'proc_tree=1,tls_sni=1,fs_events=1';
}

// --- fail-on-error with smart defend-mode default (Change 5) ---

export function resolveFailOnError(mode: string): boolean {
  const raw = core.getInput('fail-on-error');
  if (raw === '') {
    // Defend mode defaults to fail-on-error: true unless explicitly overridden
    return mode === 'defend';
  }
  return ['true', '1', 'yes', 'on'].includes(raw.toLowerCase());
}

// --- Report flags resolution (Change 4) ---

export interface ReportFlags {
  reportJobSummary: boolean;
  reportPRSummary: boolean;
}

export function resolveReportFlags(): ReportFlags {
  const report = (core.getInput('report') || 'job-summary').trim().toLowerCase();
  switch (report) {
    case 'pr-comment':
      return { reportJobSummary: false, reportPRSummary: true };
    case 'both':
      return { reportJobSummary: true, reportPRSummary: true };
    case 'none':
      return { reportJobSummary: false, reportPRSummary: false };
    default: // 'job-summary'
      return { reportJobSummary: true, reportPRSummary: false };
  }
}
