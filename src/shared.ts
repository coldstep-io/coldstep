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
