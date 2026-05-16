import * as core from '@actions/core';
import * as github from '@actions/github';
import * as fs from 'fs';
import * as path from 'path';
import { agentStatusPath, detectLogPath, readAgentReadyOk, resolveReportFlags } from './shared';

const MAX_DIGEST_LINE_UNITS = 4096;

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
    core.warning('report-pr-summary: missing github-token');
    return;
  }
  const ctx = github.context;
  const pr = ctx.payload.pull_request;
  if (!pr || typeof pr.number !== 'number') {
    core.info('report-pr-summary: not a pull_request event; skipping');
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
    core.warning(`report-pr-summary: ${e instanceof Error ? e.message : String(e)}`);
  }
}

function parseAgentPidFromFile(contents: string): number | null {
  const trimmed = contents.trim();
  if (trimmed === '' || !/^\d+$/.test(trimmed)) return null;
  const n = Number(trimmed);
  if (!Number.isInteger(n) || n <= 0) return null;
  return n;
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

  const actionPath = process.env.GITHUB_ACTION_PATH || process.cwd();
  const baseDir = process.env.GITHUB_WORKSPACE || actionPath;
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
  } else {
    try {
      process.kill(pid, 'SIGTERM');
    } catch (e: unknown) {
      const err = e as NodeJS.ErrnoException;
      if (err.code !== 'ESRCH') core.warning(`failed to signal pid ${pid}: ${e}`);
    }
  }
  await new Promise((r) => setTimeout(r, 400));
  await finalizeDigestAndNotifications(reportJobSummary, reportPRSummary);
}
