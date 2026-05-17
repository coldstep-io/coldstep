import * as core from '@actions/core';
import * as github from '@actions/github';
import * as fs from 'fs';
import * as path from 'path';
import { actionRootPath, agentStatusPath, detectLogPath, eventsLogPath, readAgentReadyOk, resolveReportFlags } from './shared';

const MAX_DIGEST_LINE_UNITS = 4096;

// Caps on JSONL ingestion for suggested-allow: stop reading at MAX_EVENTS_BYTES so a
// pathological 10 GiB log can't OOM the runner, and at MAX_EVENTS_LINES so quadratic
// parsing cost stays bounded. Both are generous for realistic CI workloads.
const MAX_EVENTS_BYTES = 32 * 1024 * 1024;
const MAX_EVENTS_LINES = 500_000;
// Action outputs have a per-call size ceiling (envelope-encoded over the runner FD).
// Cap the suggested-allow string so a sprawling run doesn't break the output write.
const MAX_SUGGESTED_ALLOW_CHARS = 256 * 1024;

function truncateLineUtf16(line: string, maxUnits: number): string {
  if (line.length <= maxUnits) return line;
  let end = maxUnits;
  const c = line.charCodeAt(end - 1);
  if (c >= 0xd800 && c <= 0xdbff) end -= 1;
  return line.slice(0, end) + ' ...(truncated)';
}

function sanitizeDigestForMarkdown(body: string): string {
  if (body === '') return body;
  const stripped = body.replace(/^﻿/, '');
  const normalized = stripped.replace(/\r\n?/g, '\n');
  const cappedLines = normalized
    .split('\n')
    .map((line) => (line.length > MAX_DIGEST_LINE_UNITS ? truncateLineUtf16(line, MAX_DIGEST_LINE_UNITS) : line));
  const escaped = cappedLines
    .map((line) => line.replace(/\\/g, '\\\\'))
    .map((line) => line.replace(/</g, '&lt;'))
    .map((line) => line.replace(/`{3,}/g, (m) => '\\`'.repeat(m.length)))
    .map((line) => line.replace(/~{3,}/g, (m) => '\\~'.repeat(m.length)));
  return escaped.join('\n');
}

function readDetectDigest(): string {
  const logPath = detectLogPath();
  if (!fs.existsSync(logPath)) return '';
  try {
    return fs.readFileSync(logPath, 'utf8');
  } catch (e) {
    core.warning(`coldstep digest read failed (${e instanceof Error ? e.message : String(e)}); continuing with empty body`);
    return '';
  }
}

function discardDigestFileIfPresent(): void {
  const logPath = detectLogPath();
  if (!fs.existsSync(logPath)) return;
  try {
    fs.unlinkSync(logPath);
  } catch (e) {
    core.warning(`coldstep digest unlink failed (${e instanceof Error ? e.message : String(e)}): ${logPath}`);
  }
}

function flushDetectLogToJobSummary(body: string): void {
  if (body.trim() === '') {
    discardDigestFileIfPresent();
    return;
  }
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) {
    discardDigestFileIfPresent();
    return;
  }
  const block =
    '## Coldstep - digest (exec / network / defend)\n\n' +
    sanitizeDigestForMarkdown(body) +
    (body.endsWith('\n') ? '' : '\n');
  try {
    fs.appendFileSync(summaryPath, block, 'utf8');
  } catch (e) {
    core.warning(`GITHUB_STEP_SUMMARY append failed (${e instanceof Error ? e.message : String(e)}); digest file left at ${detectLogPath()}`);
    return;
  }
  try {
    fs.unlinkSync(detectLogPath());
  } catch (e) {
    core.warning(`coldstep digest unlink after summary flush (${e instanceof Error ? e.message : String(e)}): ${detectLogPath()}`);
  }
}

async function maybePostPRSummary(body: string, reportPRSummary: boolean): Promise<void> {
  if (!reportPRSummary) return;
  if (body.trim() === '') return;
  const token = (core.getInput('github-token') || process.env.GITHUB_TOKEN || '').trim();
  if (!token) {
    core.warning('report pr-comment: missing github-token');
    return;
  }
  const ctx = github.context;
  const pr = ctx.payload.pull_request;
  if (!pr || typeof pr.number !== 'number') {
    core.info('report pr-comment: not a pull_request event; skipping');
    return;
  }
  const max = 65000;
  const safe = sanitizeDigestForMarkdown(body);
  const snippet = safe.length > max ? safe.slice(0, max) + '\n\n_(truncated)_\n' : safe;
  const octokit = github.getOctokit(token);
  const ghMs = 60_000;
  const abort = new AbortController();
  const timeoutId = setTimeout(() => abort.abort(), ghMs);
  try {
    await octokit.rest.issues.createComment({
      owner: ctx.repo.owner,
      repo: ctx.repo.repo,
      issue_number: pr.number,
      body: '## Coldstep digest\n\n' + snippet,
      request: { signal: abort.signal },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (abort.signal.aborted) throw new Error(`GitHub API timeout after ${ghMs / 1000}s`);
    throw new Error(msg);
  } finally {
    clearTimeout(timeoutId);
  }
}

interface ObservedDestinations {
  hosts: Set<string>;
  ipsWithoutHost: Set<string>;
}

// Hostnames seen via DNS lookup, SNI, or HTTP Host header are preferred over the raw IP they
// resolved to: a domain entry survives DNS rotation, while an IP entry pins the runner to whatever
// load-balanced address the resolver returned on this run. So when an event line carries both a
// hostname and a dst IP, we record the hostname and mark that IP as "covered" (not added on its own).
// Lines that carry only a dst IP (no fqdn cache hit, no SNI, no Host header) contribute the IP.
export function buildSuggestedAllowlist(jsonl: string): string {
  const observed = collectObservedDestinations(jsonl);
  const entries = [
    ...[...observed.hosts].map((h) => h.toLowerCase()),
    ...observed.ipsWithoutHost,
  ];
  const unique = [...new Set(entries)].filter((e) => e.length > 0).sort();
  return unique.join(',');
}

function collectObservedDestinations(jsonl: string): ObservedDestinations {
  const hosts = new Set<string>();
  const ipsAll = new Set<string>();
  const ipsCoveredByHost = new Set<string>();

  if (jsonl === '') return { hosts, ipsWithoutHost: ipsAll };

  const lines = jsonl.split('\n');
  const max = Math.min(lines.length, MAX_EVENTS_LINES);
  for (let i = 0; i < max; i++) {
    const line = lines[i];
    if (line === '' || line.charCodeAt(0) !== 0x7b /* '{' */) continue;
    let ev: Record<string, unknown> | undefined;
    try {
      ev = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (!ev || typeof ev !== 'object') continue;
    const host = pickHost(ev);
    const dst = pickString(ev.dst);
    if (host !== undefined) {
      hosts.add(host);
      if (dst !== undefined) ipsCoveredByHost.add(dst);
    }
    if (dst !== undefined) ipsAll.add(dst);
  }

  const ipsWithoutHost = new Set<string>();
  for (const ip of ipsAll) {
    if (!ipsCoveredByHost.has(ip)) ipsWithoutHost.add(ip);
  }
  return { hosts, ipsWithoutHost };
}

function pickHost(ev: Record<string, unknown>): string | undefined {
  // Order matters: HTTP Host header is the most user-meaningful, SNI is the next-best signal for
  // TLS traffic, and fqdn (TCP/UDP DNS-cache hit) is the fallback when no L7 metadata was captured.
  const httpHost = pickString(ev.host);
  if (httpHost !== undefined) return normalizeHost(httpHost);
  const sni = pickString(ev.sni);
  if (sni !== undefined) return normalizeHost(sni);
  const fqdn = pickString(ev.fqdn);
  if (fqdn !== undefined) return normalizeHost(fqdn);
  return undefined;
}

function pickString(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const t = v.trim();
  if (t === '') return undefined;
  return t;
}

function normalizeHost(h: string): string {
  // Strip ":port" suffix (HTTP Host may include it) without breaking bracketed IPv6 literals.
  // IPv6 literals never enter the suggested allowlist today (agent is IPv4-only) but the guard is
  // cheap insurance against future schema drift.
  if (h.startsWith('[')) return h.toLowerCase();
  const colon = h.indexOf(':');
  const trimmed = colon === -1 ? h : h.slice(0, colon);
  return trimmed.toLowerCase();
}

function readEventsJSONLCapped(): string {
  const p = eventsLogPath();
  if (!fs.existsSync(p)) return '';
  try {
    const stat = fs.statSync(p);
    if (stat.size <= MAX_EVENTS_BYTES) return fs.readFileSync(p, 'utf8');
    // Read only the first MAX_EVENTS_BYTES so this stays bounded. Truncate at the last newline
    // so we don't hand half a JSON line to the parser.
    const fd = fs.openSync(p, 'r');
    try {
      const buf = Buffer.alloc(MAX_EVENTS_BYTES);
      const n = fs.readSync(fd, buf, 0, MAX_EVENTS_BYTES, 0);
      const text = buf.slice(0, n).toString('utf8');
      const lastNL = text.lastIndexOf('\n');
      core.warning(
        `suggested-allow: events log ${stat.size} bytes exceeds cap ${MAX_EVENTS_BYTES}; truncating at last newline`,
      );
      return lastNL === -1 ? '' : text.slice(0, lastNL + 1);
    } finally {
      fs.closeSync(fd);
    }
  } catch (e) {
    core.warning(`suggested-allow: read failed (${e instanceof Error ? e.message : String(e)})`);
    return '';
  }
}

function emitSuggestedAllowlist(): void {
  const mode = (core.getInput('mode') || 'detect').trim().toLowerCase();
  if (mode !== 'detect') {
    core.setOutput('suggested-allow', '');
    return;
  }
  const jsonl = readEventsJSONLCapped();
  if (jsonl === '') {
    core.setOutput('suggested-allow', '');
    return;
  }
  let allow = buildSuggestedAllowlist(jsonl);
  if (allow === '') {
    core.setOutput('suggested-allow', '');
    return;
  }
  let truncated = false;
  if (allow.length > MAX_SUGGESTED_ALLOW_CHARS) {
    // Cut at the last comma so the output is still a valid allow-list with no half-entry trailing.
    const cap = allow.lastIndexOf(',', MAX_SUGGESTED_ALLOW_CHARS);
    allow = cap === -1 ? allow.slice(0, MAX_SUGGESTED_ALLOW_CHARS) : allow.slice(0, cap);
    truncated = true;
    core.warning(`suggested-allow: list exceeded ${MAX_SUGGESTED_ALLOW_CHARS} chars; truncated`);
  }
  core.setOutput('suggested-allow', allow);

  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;
  const entries = allow.split(',').filter((e) => e.length > 0);
  const block =
    '## Suggested allowlist\n\n' +
    'Copy these to your coldstep `allow:` input. Hostnames observed via DNS/SNI/HTTP take ' +
    'priority over raw IPs.\n\n' +
    '```\n' +
    allow +
    '\n```\n\n' +
    `_${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}` +
    (truncated ? ' (truncated)' : '') +
    '_\n\n';
  try {
    fs.appendFileSync(summaryPath, block, 'utf8');
  } catch (e) {
    core.warning(`suggested-allow: GITHUB_STEP_SUMMARY append failed (${e instanceof Error ? e.message : String(e)})`);
  }
}

async function finalizeDigestAndNotifications(reportJobSummary: boolean, reportPRSummary: boolean): Promise<void> {
  const digestBody = readDetectDigest();
  if (reportJobSummary) {
    flushDetectLogToJobSummary(digestBody);
  } else {
    discardDigestFileIfPresent();
  }
  try {
    await maybePostPRSummary(digestBody, reportPRSummary);
  } catch (e) {
    core.warning(`report pr-comment: ${e instanceof Error ? e.message : String(e)}`);
  }
  emitSuggestedAllowlist();
}

function parseAgentPidFromFile(contents: string): number | null {
  const trimmed = contents.trim();
  if (trimmed === '' || !/^\d+$/.test(trimmed)) return null;
  const n = Number(trimmed);
  if (!Number.isInteger(n) || n <= 0) return null;
  return n;
}

// process.kill(pid, 0) returns true iff pid is alive (or returns EPERM, which still implies alive).
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e: unknown) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === 'EPERM') return true;
    return false;
  }
}

// Wait up to timeoutMs for pid to exit. Polls cheaply on a fixed cadence so in-flight ringbuf
// events have time to drain through readDenyRing's per-wakeup burst loop and reach JSONL before
// finalizeDigestAndNotifications reads the file.
async function waitForProcessExit(pid: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!isProcessAlive(pid)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
}

export async function stopAgent(): Promise<void> {
  const { reportJobSummary, reportPRSummary } = resolveReportFlags();

  const failOnError =
    core.getInput('fail-on-error') !== ''
      ? ['true', '1', 'yes', 'on'].includes(core.getInput('fail-on-error').toLowerCase())
      : false;

  if (failOnError && core.getState('coldstep_wait_ready_ok') !== 'true') {
    const st = agentStatusPath();
    if (!readAgentReadyOk(st)) {
      core.setFailed('coldstep agent did not report ready (operational fail-on-error)');
    }
  }

  const baseDir = process.env.GITHUB_WORKSPACE || actionRootPath();
  // PID file is in the workspace (matches start.ts) so bash steps can read it too.
  const pidFile = path.join(baseDir, '.coldstep.pid');
  if (!fs.existsSync(pidFile)) {
    core.warning('pid file missing; agent may not have started');
    await finalizeDigestAndNotifications(reportJobSummary, reportPRSummary);
    return;
  }
  let pidContents = '';
  try {
    pidContents = fs.readFileSync(pidFile, 'utf8');
  } catch {
    core.warning('pid file disappeared before read; skipping SIGTERM (agent may still be running)');
    await finalizeDigestAndNotifications(reportJobSummary, reportPRSummary);
    return;
  }
  const pid = parseAgentPidFromFile(pidContents);
  if (pid === null) {
    core.warning('pid file has invalid contents; skipping SIGTERM (agent may still be running)');
    await new Promise((r) => setTimeout(r, 400));
  } else {
    let signaled = true;
    try {
      process.kill(pid, 'SIGTERM');
    } catch (e: unknown) {
      const err = e as NodeJS.ErrnoException;
      signaled = false;
      if (err.code !== 'ESRCH') core.warning(`failed to signal pid ${pid}: ${e}`);
    }
    if (signaled) {
      // Wait for the agent to actually exit (or up to 3s) so in-flight ringbuf
      // events flush through readDenyRing and land in JSONL before we read it.
      await waitForProcessExit(pid, 3000);
    } else {
      await new Promise((r) => setTimeout(r, 400));
    }
  }
  await finalizeDigestAndNotifications(reportJobSummary, reportPRSummary);
}
