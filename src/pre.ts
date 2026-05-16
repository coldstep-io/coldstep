// pre.js — runs at job start (before any step).
// New-style (phase not set): runs start logic.
// Old-style (phase: start or stop): no-op; main.js handles it.
import * as core from '@actions/core';
import { startAgent } from './start';

const phase = core.getInput('phase').trim().toLowerCase();
if (phase === '') {
  startAgent().catch((e) => core.setFailed(e instanceof Error ? e.message : String(e)));
}
// Any explicit phase value → backward-compat mode; main.js takes over.
