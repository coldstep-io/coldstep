import * as core from '@actions/core';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as https from 'https';
import * as os from 'os';
import * as path from 'path';

export const MAX_READY_STATUS_JSON_BYTES = 512 * 1024;

// Pinned coldstep agent release. Bump these together when cutting a new release;
// the SHA256 must match the coldstep-linux-amd64 asset on the named tag.
export const COLDSTEP_BINARY_VERSION = 'v0.2.2';
export const COLDSTEP_BINARY_SHA256 = '49bae9f1d34fe1f9fa4a50a2bcc2604b7d485836e3046a3bd718199b74d4d355';
export const COLDSTEP_BINARY_URL =
  `https://github.com/coldstep-io/coldstep/releases/download/${COLDSTEP_BINARY_VERSION}/coldstep-linux-amd64`;

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
// and caching it under RUNNER_TEMP/coldstep-action/<version>/coldstep. SHA256-verified.
export async function ensureColdstepBinary(): Promise<string> {
  if (process.arch !== 'x64') {
    throw new Error(`coldstep: unsupported arch ${process.arch} — only linux/amd64 is published`);
  }
  const cacheRoot = process.env.RUNNER_TEMP || os.tmpdir();
  const cacheDir = path.join(cacheRoot, 'coldstep-action', COLDSTEP_BINARY_VERSION);
  const binPath = path.join(cacheDir, 'coldstep');
  fs.mkdirSync(cacheDir, { recursive: true });

  if (fs.existsSync(binPath)) {
    const got = sha256File(binPath);
    if (got === COLDSTEP_BINARY_SHA256) {
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
  if (got !== COLDSTEP_BINARY_SHA256) {
    try { fs.unlinkSync(binPath); } catch { /* ignore */ }
    throw new Error(
      `coldstep: downloaded binary sha256 mismatch — expected ${COLDSTEP_BINARY_SHA256}, got ${got} (url=${COLDSTEP_BINARY_URL})`,
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
