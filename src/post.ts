import * as core from '@actions/core';
import * as github from '@actions/github';
import * as fs from 'fs';
import * as path from 'path';

function detectLogPath(): string {
  const actionPath = process.env.GITHUB_ACTION_PATH || process.cwd();
  const baseDir = process.env.GITHUB_WORKSPACE || actionPath;
  return path.join(baseDir, '.coldstep-detect.md');
}

function agentStatusPath(): string {
  const actionPath = process.env.GITHUB_ACTION_PATH || process.cwd();
  const baseDir = process.env.GITHUB_WORKSPACE || actionPath;
  return path.join(baseDir, '.coldstep-ready.json');
}

function inputBoolDefault(name: string, defaultVal: boolean): boolean {
  const v = core.getInput(name);
  if (v === '') {
    return defaultVal;
  }
  return ['true', '1', 'yes', 'on'].includes(v.toLowerCase());
}

/** Accepts only Slack Incoming Webhook URLs to avoid SSRF via arbitrary fetch targets. */
function parseSlackIncomingWebhookURL(raw: string): URL | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:') {
    return null;
  }
  if (u.username !== '' || u.password !== '') {
    return null;
  }
  if (u.hostname.toLowerCase() !== 'hooks.slack.com') {
    return null;
  }
  if (!u.pathname.toLowerCase().startsWith('/services/')) {
    return null;
  }
  return u;
}

function parseAgentPidFromFile(contents: string): number | null {
  const trimmed = contents.trim();
  if (trimmed === '' || !/^\d+$/.test(trimmed)) {
    return null;
  }
  const n = Number(trimmed);
  if (!Number.isInteger(n) || n <= 0) {
    return null;
  }
  return n;
}

function readDetectDigest(): string {
  const logPath = detectLogPath();
  if (!fs.existsSync(logPath)) {
    return '';
  }
  return fs.readFileSync(logPath, 'utf8');
}

function flushDetectLogToJobSummary(body: string): void {
  const logPath = detectLogPath();
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;

  if (body.trim() === '') {
    if (fs.existsSync(logPath)) {
      fs.unlinkSync(logPath);
    }
    return;
  }

  if (!summaryPath) {
    // No step summary file (non-Actions or misconfigured): still consume digest so it is not left stale.
    if (fs.existsSync(logPath)) {
      fs.unlinkSync(logPath);
    }
    return;
  }

  const block =
    '## Coldstep · digest (exec / network / enforcement)\n\n' +
    body +
    (body.endsWith('\n') ? '' : '\n');
  fs.appendFileSync(summaryPath, block, 'utf8');
  fs.unlinkSync(logPath);
}

async function maybePostPRSummary(body: string): Promise<void> {
  if (!inputBoolDefault('report-pr-summary', false)) {
    return;
  }
  if (body.trim() === '') {
    return;
  }
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
  const snippet = body.length > max ? body.slice(0, max) + '\n\n_(truncated)_\n' : body;
  const octokit = github.getOctokit(token);
  await octokit.rest.issues.createComment({
    owner: ctx.repo.owner,
    repo: ctx.repo.repo,
    issue_number: pr.number,
    body: '## Coldstep digest\n\n' + snippet,
  });
}

async function maybeSlackWebhook(body: string): Promise<void> {
  const urlRaw = (core.getInput('slack-webhook-endpoint') || '').trim();
  if (!urlRaw || body.trim() === '') {
    return;
  }
  const urlParsed = parseSlackIncomingWebhookURL(urlRaw);
  if (!urlParsed) {
    core.warning(
      'slack-webhook-endpoint: must be a Slack Incoming Webhook (https://hooks.slack.com/services/...); skipping send',
    );
    return;
  }
  const max = 35000;
  const text =
    body.length > max
      ? body.slice(0, max) + '\n…(truncated for Slack)'
      : body;
  const r = await fetch(urlParsed, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text: 'Coldstep digest\n\n' + text }),
  });
  if (!r.ok) {
    core.warning(`slack-webhook-endpoint: POST failed (${r.status})`);
  }
}

async function post(): Promise<void> {
  const failOnError = inputBoolDefault('fail-on-error', false);
  const reportJobSummary = inputBoolDefault('report-job-summary', true);

  if (failOnError && core.getState('coldstep_wait_ready_ok') !== 'true') {
    const st = agentStatusPath();
    let ok = false;
    try {
      if (fs.existsSync(st)) {
        const j = JSON.parse(fs.readFileSync(st, 'utf8')) as { ok?: boolean };
        ok = j.ok === true;
      }
    } catch {
      ok = false;
    }
    if (!ok) {
      core.setFailed('coldstep agent did not report ready (operational fail-on-error)');
    }
  }

  const actionPath = process.env.GITHUB_ACTION_PATH || process.cwd();
  const pidFile = path.join(actionPath, '.coldstep.pid');
  if (!fs.existsSync(pidFile)) {
    core.warning('pid file missing; agent may not have started');
    const digestEarly = readDetectDigest();
    if (reportJobSummary) {
      flushDetectLogToJobSummary(digestEarly);
    }
    await maybePostPRSummary(digestEarly);
    await maybeSlackWebhook(digestEarly);
    return;
  }
  const pid = parseAgentPidFromFile(fs.readFileSync(pidFile, 'utf8'));
  if (pid === null) {
    core.warning('pid file has invalid contents; skipping SIGTERM (agent may still be running)');
  } else {
    try {
      process.kill(pid, 'SIGTERM');
    } catch (e: unknown) {
      const err = e as NodeJS.ErrnoException;
      if (err.code !== 'ESRCH') {
        core.warning(`failed to signal pid ${pid}: ${e}`);
      }
    }
  }
  await new Promise((r) => setTimeout(r, 400));
  const digestBody = readDetectDigest();
  if (reportJobSummary) {
    flushDetectLogToJobSummary(digestBody);
  }
  try {
    await maybePostPRSummary(digestBody);
  } catch (e) {
    core.warning(`report-pr-summary: ${e instanceof Error ? e.message : String(e)}`);
  }
  try {
    await maybeSlackWebhook(digestBody);
  } catch (e) {
    core.warning(`slack-webhook-endpoint: ${e instanceof Error ? e.message : String(e)}`);
  }
}

post().catch((e) => {
  core.setFailed(e instanceof Error ? e.message : String(e));
});
