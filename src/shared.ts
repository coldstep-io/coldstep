import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';

export const MAX_READY_STATUS_JSON_BYTES = 512 * 1024;

export function inputBoolDefault(name: string, defaultVal: boolean): boolean {
  const v = core.getInput(name);
  if (v === '') return defaultVal;
  return ['true', '1', 'yes', 'on'].includes(v.toLowerCase());
}

export function detectLogPath(): string {
  const actionPath = process.env.GITHUB_ACTION_PATH || process.cwd();
  const baseDir = process.env.GITHUB_WORKSPACE || actionPath;
  return path.join(baseDir, '.coldstep-detect.md');
}

export function agentStatusPath(): string {
  const actionPath = process.env.GITHUB_ACTION_PATH || process.cwd();
  const baseDir = process.env.GITHUB_WORKSPACE || actionPath;
  return path.join(baseDir, '.coldstep-ready.json');
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
  const actionPath = process.env.GITHUB_ACTION_PATH || process.cwd();

  // New unified inputs
  const newTokens = [
    ...splitTokens(core.getInput('allow')),
    ...readFileTokensSafe(core.getInput('allow-file'), baseDir),
  ];
  const parsed = classifyTokens(newTokens);

  // Bootstrap allowlist — read vendored packs and merge
  if (inputBoolDefault('bootstrap-allowlist', false)) {
    const bsDir = path.join(actionPath, 'scripts', 'coldstep_bootstrap');
    const bsDomains = readSingleFileSafe(path.join(bsDir, 'allowlist-domains-v1.txt'));
    parsed.allowedDomains.push(...bsDomains);
    parsed.allowedHosts.push(...bsDomains);
    const bsIPs = readSingleFileSafe(path.join(bsDir, 'allowlist-ips-v1.txt'));
    parsed.allowedIPs.push(...bsIPs);
  }

  // Deprecated inputs — merged after new inputs
  const oldDomains = splitTokens(core.getInput('allowed-domains'));
  const oldDomainsFile = readFileTokensSafe(core.getInput('allowed-domains-file'), baseDir);
  const oldHosts = splitTokens(core.getInput('allowed-hosts'));
  const oldHostsFile = readFileTokensSafe(core.getInput('allowed-hosts-file'), baseDir);
  const oldIPs = splitTokens(core.getInput('allowed-ips'));
  const oldIPsFile = readFileTokensSafe(core.getInput('allowed-ips-file'), baseDir);

  // ignored-nets (new) and ignored-ip-nets (deprecated) — both work
  const ignoredNetsRaw = core.getInput('ignored-nets') || core.getInput('ignored-ip-nets');
  const ignoredNetsFileRaw = core.getInput('ignored-nets-file') || core.getInput('ignored-ip-nets-file');
  const oldIgnoredNets = splitTokens(ignoredNetsRaw);
  const oldIgnoredNetsFile = readFileTokensSafe(ignoredNetsFileRaw, baseDir);

  return {
    allowedIPs: mergeUnique(parsed.allowedIPs, oldIPs, oldIPsFile),
    ignoredNets: mergeUnique(parsed.ignoredNets, oldIgnoredNets, oldIgnoredNetsFile),
    allowedHosts: mergeUnique(parsed.allowedHosts, oldHosts, oldHostsFile),
    allowedDomains: mergeUnique(parsed.allowedDomains, oldDomains, oldDomainsFile),
  };
}

// --- Feature-gate resolution (detect-profile + feature-gates merge) ---

export function resolveFeatureGates(): string {
  const detectProfile = (core.getInput('detect-profile') || 'standard').trim().toLowerCase();
  const featureGatesRaw = core.getInput('feature-gates').trim();

  const gates = new Map<string, string>();
  if (featureGatesRaw) {
    for (const gate of featureGatesRaw.split(',').map((g) => g.trim()).filter(Boolean)) {
      const eq = gate.indexOf('=');
      if (eq >= 0) {
        gates.set(gate.slice(0, eq).trim(), gate.slice(eq + 1).trim());
      } else {
        gates.set(gate, '1');
      }
    }
  }

  if (detectProfile === 'enhanced') {
    for (const [k, v] of [['proc_tree', '1'], ['tls_sni', '1'], ['fs_events', '1']] as const) {
      if (!gates.has(k)) gates.set(k, v);
    }
  }

  return Array.from(gates.entries())
    .map(([k, v]) => `${k}=${v}`)
    .join(',');
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

  let reportJobSummary: boolean;
  let reportPRSummary: boolean;

  switch (report) {
    case 'pr-comment':
      reportJobSummary = false;
      reportPRSummary = true;
      break;
    case 'both':
      reportJobSummary = true;
      reportPRSummary = true;
      break;
    case 'none':
      reportJobSummary = false;
      reportPRSummary = false;
      break;
    default: // 'job-summary'
      reportJobSummary = true;
      reportPRSummary = false;
  }

  // Deprecated inputs override if explicitly set
  const oldJobSummary = core.getInput('report-job-summary');
  const oldPRSummary = core.getInput('report-pr-summary');
  if (oldJobSummary !== '') {
    reportJobSummary = ['true', '1', 'yes', 'on'].includes(oldJobSummary.toLowerCase());
  }
  if (oldPRSummary !== '') {
    reportPRSummary = ['true', '1', 'yes', 'on'].includes(oldPRSummary.toLowerCase());
  }

  return { reportJobSummary, reportPRSummary };
}
