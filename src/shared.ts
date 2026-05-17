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
export const COLDSTEP_BINARY_VERSION = 'v0.2.4';
export const COLDSTEP_BINARY_ASSET_NAME = 'coldstep-linux-amd64';
export const COLDSTEP_BINARY_REPO = 'coldstep-io/coldstep';
export const COLDSTEP_BINARY_URL =
  `https://github.com/${COLDSTEP_BINARY_REPO}/releases/download/${COLDSTEP_BINARY_VERSION}/${COLDSTEP_BINARY_ASSET_NAME}`;

// JS actions never get GITHUB_ACTION_PATH (composite-only) and cwd() is the consumer workspace,
// so derive the action root from this bundle's location: dist/{pre,main,post}/index.js → root.
export function actionRootPath(): string {
  return path.resolve(__dirname, '..', '..');
}

export function inputBoolDefault(name: string, defaultVal: boolean): boolean {
  const v = core.getInput(name);
  if (v === '') return defaultVal;
  return ['true', '1', 'yes', 'on'].includes(v.toLowerCase());
}

export function detectLogPath(): string {
  const baseDir = process.env.GITHUB_WORKSPACE || actionRootPath();
  return path.join(baseDir, '.coldstep-detect.md');
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
  await downloadToFile(COLDSTEP_BINARY_URL, binPath);
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

function readFileTokensSafe(filePaths: string, baseDir: string): string[] {
  if (!filePaths.trim()) return [];
  const tokens: string[] = [];
  for (const fp of filePaths.split(',').map((s) => s.trim()).filter(Boolean)) {
    const absPath = path.isAbsolute(fp) ? fp : path.join(baseDir, fp);
    try {
      tokens.push(...splitTokens(fs.readFileSync(absPath, 'utf8')));
    } catch (e) {
      core.warning(`allow-file: could not read ${absPath}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return tokens;
}

function readSingleFileSafe(filePath: string): string[] {
  try {
    return splitTokens(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return [];
  }
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
  const actionPath = actionRootPath();

  const tokens = [
    ...splitTokens(core.getInput('allow')),
    ...readFileTokensSafe(core.getInput('allow-file'), baseDir),
  ];
  const parsed = classifyTokens(tokens);

  if (inputBoolDefault('bootstrap-allowlist', false)) {
    const bsDir = path.join(actionPath, 'scripts', 'coldstep_bootstrap');
    const bsDomains = readSingleFileSafe(path.join(bsDir, 'allowlist-domains-v1.txt'));
    parsed.allowedDomains.push(...bsDomains);
    parsed.allowedHosts.push(...bsDomains);
    const bsIPs = readSingleFileSafe(path.join(bsDir, 'allowlist-ips-v1.txt'));
    parsed.allowedIPs.push(...bsIPs);
  }

  const ignoredNetsTokens = [
    ...splitTokens(core.getInput('ignored-nets')),
    ...readFileTokensSafe(core.getInput('ignored-nets-file'), baseDir),
  ];

  return {
    allowedIPs: mergeUnique(parsed.allowedIPs),
    ignoredNets: mergeUnique(parsed.ignoredNets, ignoredNetsTokens),
    allowedHosts: mergeUnique(parsed.allowedHosts),
    allowedDomains: mergeUnique(parsed.allowedDomains),
  };
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
