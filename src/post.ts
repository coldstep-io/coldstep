// post.js — runs at job end (after all steps).
// New-style (phase not set): runs stop logic.
// Old-style (phase: start or stop): no-op; main.js already handled the stop.
import * as core from '@actions/core';
import { stopAgent } from './stop';

const phase = core.getInput('phase').trim().toLowerCase();
if (phase === '') {
  stopAgent().catch((e) => core.setFailed(e instanceof Error ? e.message : String(e)));
}
// Any explicit phase value → backward-compat mode; main.js already ran stop.
