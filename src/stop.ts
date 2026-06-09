import * as core from '@actions/core';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { actionRootPath, agentStatusPath, cachedColdstepBinaryPath, ensureColdstepBinary, eventsLogPath, readAgentReadyOk, resolveFailOnError, resolveReportFlags } from './shared';

// Caps on JSONL ingestion for suggested-allow: stop reading at MAX_EVENTS_BYTES so a
// pathological 10 GiB log can't OOM the runner, and at MAX_EVENTS_LINES so quadratic
// parsing cost stays bounded. Both are generous for realistic CI workloads.
const MAX_EVENTS_BYTES = 32 * 1024 * 1024;
const MAX_EVENTS_LINES = 500_000;
// Action outputs have a per-call size ceiling (envelope-encoded over the runner FD).
// Cap the suggested-allow string so a sprawling run doesn't break the output write.
const MAX_SUGGESTED_ALLOW_CHARS = 256 * 1024;

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

// SP-3: a paste-ready, grouped allow-file body — hostnames (preferred, survive
// DNS rotation) in one section, bare IPs (no hostname observed) in another, with
// `#` comments. Written to .coldstep-suggested-allow.txt for download/review and
// drop-in as an `allow-file`. Empty sections are omitted; returns '' when nothing
// was observed.
export function buildSuggestedAllowFile(jsonl: string): string {
  const observed = collectObservedDestinations(jsonl);
  const hosts = [...observed.hosts].map((h) => h.toLowerCase()).filter((h) => h.length > 0).sort();
  const ips = [...observed.ipsWithoutHost].filter((ip) => ip.length > 0).sort();
  if (hosts.length === 0 && ips.length === 0) return '';
  const out: string[] = ['# coldstep suggested allowlist — copy into your `allow:` input or commit as an allow-file.'];
  if (hosts.length > 0) {
    out.push('# Hostnames (preferred — survive DNS rotation):');
    out.push(...hosts);
  }
  if (ips.length > 0) {
    out.push('# Bare IPs (no hostname observed this run — pin only if a stable host is unavailable):');
    out.push(...ips);
  }
  return out.join('\n') + '\n';
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

  // SP-3: write a grouped, paste-ready artifact for download / drop-in as an
  // allow-file. Best-effort — a write failure must not fail the post step.
  const baseDir = process.env.GITHUB_WORKSPACE || actionRootPath();
  const allowFilePath = path.join(baseDir, '.coldstep-suggested-allow.txt');
  let artifactWritten = false;
  const fileBody = buildSuggestedAllowFile(jsonl);
  if (fileBody !== '') {
    try {
      fs.writeFileSync(allowFilePath, fileBody, 'utf8');
      artifactWritten = true;
    } catch (e) {
      core.warning(`suggested-allow: artifact write failed (${e instanceof Error ? e.message : String(e)})`);
    }
  }

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
    '_\n\n' +
    (artifactWritten
      ? 'A grouped, paste-ready copy was written to `.coldstep-suggested-allow.txt` (commit it as an `allow-file`).\n\n'
      : '');
  try {
    fs.appendFileSync(summaryPath, block, 'utf8');
  } catch (e) {
    core.warning(`suggested-allow: GITHUB_STEP_SUMMARY append failed (${e instanceof Error ? e.message : String(e)})`);
  }
}

async function finalizeDigestAndNotifications(_reportJobSummary: boolean, _reportPRSummary: boolean): Promise<void> {
  // Reporting is delegated to the combined coldstep binary: `coldstep stop`
  // renders both reports from .coldstep-events.jsonl (the agent writes data only)
  // and posts the PR comment via the GitHub REST API. The binary is the same
  // version this action downloaded at start (COLDSTEP_BINARY_VERSION) and carries
  // the stop subcommand. The TS layer keeps only the suggested-allow output.
  const report = (core.getInput('report') || 'job-summary').trim();
  const token = (core.getInput('github-token') || process.env.GITHUB_TOKEN || '').trim();
  const detectProfile = (core.getInput('detect-profile') || 'standard').trim();
  try {
    // Prefer the binary the start step already downloaded + SHA-verified. The
    // report must not depend on a fresh GitHub Releases API call at post time
    // (a transient rate-limit/5xx would otherwise drop the report). Fall back to
    // a full download only when the cache is absent (e.g. mixed entrypoints).
    const bin = cachedColdstepBinaryPath() ?? (await ensureColdstepBinary());
    const args = ['stop', '--report', report, '--detect-profile', detectProfile];
    if (token) args.push('--github-token', token);
    execFileSync(bin, args, { stdio: 'inherit' });
  } catch (e) {
    core.warning(`coldstep stop (report render): ${e instanceof Error ? e.message : String(e)}`);
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

  // Must mirror start.ts: resolveFailOnError defaults to true in defend mode
  // when the input is unset, so the readiness backstop below stays armed there.
  const failOnError = resolveFailOnError((core.getInput('mode') || 'detect').trim().toLowerCase());

  if (failOnError && core.getState('coldstep_wait_ready_ok') !== 'true') {
    const st = agentStatusPath();
    if (!readAgentReadyOk(st)) {
      core.setFailed('coldstep agent did not report ready (operational fail-on-error)');
    }
  }

  const baseDir = process.env.GITHUB_WORKSPACE || actionRootPath();
  // Bug #9: PID file must match start.ts and cmd/coldstep-action's
  // runStart — workspace location is the public, documented contract.
  // Mixed-entrypoint use (e.g. Go start + TS stop) otherwise reads a
  // different file, no-ops SIGTERM, and the agent is SIGKILLed instead.
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
