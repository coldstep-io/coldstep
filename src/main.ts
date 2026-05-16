// main.js — runs at the position of the `uses:` step.
//
// New-style (phase not set): pre already started the agent; post will stop it.
// This step checks agent liveness and prints status.
//
// Old-style backward compat:
//   phase: start → run start logic (pre was a no-op)
//   phase: stop  → run stop logic  (post will be a no-op)
import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';
import { actionRootPath, agentStatusPath, readAgentReadyOk } from './shared';
import { startAgent } from './start';
import { stopAgent } from './stop';

async function statusCheck(): Promise<void> {
  const baseDir = process.env.GITHUB_WORKSPACE || actionRootPath();
  const pidFile = path.join(baseDir, '.coldstep.pid');
  if (!fs.existsSync(pidFile)) {
    core.warning('coldstep: pid file not found — agent may not have started in pre hook');
    return;
  }
  const pid = Number(fs.readFileSync(pidFile, 'utf8').trim());
  let alive = false;
  try {
    process.kill(pid, 0);
    alive = true;
  } catch {
    /* not running */
  }
  const ready = readAgentReadyOk(agentStatusPath());
  core.info(`coldstep monitoring: pid=${pid} alive=${alive} ready=${ready}`);
}

async function run(): Promise<void> {
  const phase = core.getInput('phase').trim().toLowerCase();
  if (phase === 'start') {
    await startAgent();
  } else if (phase === 'stop') {
    await stopAgent();
  } else if (core.getState('coldstep_defer_to_main') === 'true') {
    // Pre deferred because release-path wasn't available yet; binary should exist now.
    core.info('coldstep main: starting agent (deferred from pre — release-path now expected to be available)');
    await startAgent();
  } else {
    await statusCheck();
  }
}

run().catch((e) => core.setFailed(e instanceof Error ? e.message : String(e)));
