// pre.js — runs at job start (before any step).
// New-style (phase not set): starts agent, unless release-path isn't available yet.
// Old-style (phase: start or stop): no-op; main.js handles it.
//
// Deferred start: if release-path is set but the binary doesn't exist yet (e.g. because a
// download step runs later), we save state and let main.js start the agent after the binary
// becomes available. This keeps the single `uses:` block interface while supporting workflows
// that download the binary as a separate step.
import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';
import { actionRootPath } from './shared';
import { startAgent } from './start';

const phase = core.getInput('phase').trim().toLowerCase();
if (phase !== '') {
  // Old-style backward-compat mode: pre is a no-op; main.js takes over.
} else {
  // New-style: check whether we can start now or must defer.
  const releasePath = core.getInput('release-path').trim();
  if (releasePath) {
    const baseDir = process.env.GITHUB_WORKSPACE || actionRootPath();
    const src = path.isAbsolute(releasePath) ? releasePath : path.join(baseDir, releasePath);
    if (!fs.existsSync(src)) {
      // Binary isn't available yet (pre runs before checkout / download steps).
      // Save state so main.js starts the agent after the binary has been provisioned.
      core.info(
        `coldstep pre: release-path "${releasePath}" not yet available — deferring agent start to main step. ` +
          `Ensure the binary is downloaded/built before the coldstep step in the job.`,
      );
      core.saveState('coldstep_defer_to_main', 'true');
    } else {
      startAgent().catch((e) => core.setFailed(e instanceof Error ? e.message : String(e)));
    }
  } else {
    startAgent().catch((e) => core.setFailed(e instanceof Error ? e.message : String(e)));
  }
}
