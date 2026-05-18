import * as core from '@actions/core';
import { execFileSync, spawn, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import {
  MAX_READY_STATUS_JSON_BYTES,
  actionRootPath,
  ensureColdstepBinary,
  inputBoolDefault,
  resolveAllowlist,
  resolveFeatureGates,
  resolveFailOnError,
} from './shared';

function tailUtf8File(filePath: string, maxChars: number): string {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return raw.length <= maxChars ? raw : raw.slice(-maxChars);
  } catch {
    return '';
  }
}

function headUtf8File(filePath: string, maxChars: number): string {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return raw.length <= maxChars ? raw : raw.slice(0, maxChars);
  } catch {
    return '';
  }
}

function pidLooksAlive(pid: number | undefined): boolean | undefined {
  if (pid === undefined || pid <= 0) return undefined;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

type ReadyPollOutcome =
  | 'ready'
  | 'timeout'
  | 'child_exit'
  | 'explicit_not_ready'
  | 'malformed_status';

async function waitForAgentReady(
  statusPath: string,
  timeoutMs: number,
  child?: ChildProcess,
  opts?: { progressEveryMs?: number },
): Promise<ReadyPollOutcome> {
  let exitedEarly = false;
  let exitCode: number | null = null;
  let exitSignal: NodeJS.Signals | null = null;
  const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
    exitedEarly = true;
    exitCode = code;
    exitSignal = signal;
  };
  if (child) child.on('exit', onExit);

  let malformedSince: number | null = null;
  const malformedBudgetMs = 45_000;

  try {
    const waitStart = Date.now();
    const deadline = waitStart + timeoutMs;
    let lastProgressLog = waitStart;
    while (Date.now() < deadline) {
      if (fs.existsSync(statusPath)) {
        let buf: Buffer | undefined;
        try {
          buf = fs.readFileSync(statusPath);
        } catch {
          malformedSince = null;
        }
        if (buf !== undefined) {
          if (buf.length > MAX_READY_STATUS_JSON_BYTES) {
            malformedSince ??= Date.now();
            if (Date.now() - malformedSince >= malformedBudgetMs) return 'malformed_status';
          } else {
            const raw = buf.toString('utf8').trim();
            let parsed: { ok?: unknown } | undefined;
            try {
              parsed = JSON.parse(raw) as { ok?: unknown };
            } catch {
              malformedSince ??= Date.now();
              if (Date.now() - malformedSince >= malformedBudgetMs) return 'malformed_status';
            }
            if (parsed !== undefined) {
              malformedSince = null;
              if (parsed.ok === true) return 'ready';
              if (parsed.ok === false) return 'explicit_not_ready';
              if (parsed.ok !== undefined && parsed.ok !== null) {
                core.error(`coldstep-ready.json has unexpected ok type (${typeof parsed.ok}); refusing to poll until timeout`);
                return 'explicit_not_ready';
              }
            }
          }
        }
      } else {
        malformedSince = null;
      }

      if (exitedEarly) {
        core.error(`coldstep agent exited before reporting ready (code=${exitCode}, signal=${exitSignal ?? 'none'})`);
        return 'child_exit';
      }

      const progressEvery = opts?.progressEveryMs ?? 0;
      if (progressEvery > 0) {
        const now = Date.now();
        if (now - lastProgressLog >= progressEvery) {
          lastProgressLog = now;
          const elapsedSec = Math.round((now - waitStart) / 1000);
          const budgetSec = Math.round(timeoutMs / 1000);
          const hasFile = fs.existsSync(statusPath);
          let okHint = '';
          try {
            if (hasFile) {
              const b = fs.readFileSync(statusPath);
              if (b.length > MAX_READY_STATUS_JSON_BYTES) {
                okHint = 'status file exceeds size limit';
              } else {
                const j = JSON.parse(b.toString('utf8')) as { ok?: unknown };
                okHint = typeof j.ok === 'boolean' ? `parsed ok=${j.ok}` : `parsed ok field=${JSON.stringify(j.ok)}`;
              }
            }
          } catch {
            okHint = 'parse failed (truncated JSON?)';
          }
          const alive = pidLooksAlive(child?.pid);
          core.info(
            `fail-on-error: still waiting for ready (${elapsedSec}s / ${budgetSec}s): status file ${hasFile ? 'present' : 'missing'}${hasFile ? ` — ${okHint}` : ''}; sudo child pid=${child?.pid ?? 'none'} ${alive === undefined ? '' : alive ? '(alive)' : '(not running)'}`,
          );
        }
      }

      await new Promise((r) => setTimeout(r, 150));
    }
    return 'timeout';
  } finally {
    if (child) child.off('exit', onExit);
  }
}

function parseReadyTimeoutMs(): number {
  const raw = core.getInput('ready-timeout-seconds').trim();
  const fallback = 25 * 60;
  if (raw === '') return fallback * 1000;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) {
    core.warning(`ready-timeout-seconds invalid (${raw}); using ${fallback}s`);
    return fallback * 1000;
  }
  const clamped = Math.min(Math.max(n, 60), 45 * 60);
  if (clamped !== n) {
    core.warning(`ready-timeout-seconds clamped from ${n} to ${clamped}s (bounds 60–${45 * 60})`);
  }
  return clamped * 1000;
}

export async function startAgent(): Promise<void> {
  if (process.platform !== 'linux') {
    core.setFailed('coldstep requires a Linux runner (use runs-on: ubuntu-latest)');
    return;
  }

  let mode = (core.getInput('mode') || 'detect').trim().toLowerCase();
  if (mode === 'enforce') {
    core.setFailed('coldstep: input mode "enforce" is not supported; use "defend" for blocking egress (see README / action.yml).');
    return;
  }
  if (mode !== 'detect' && mode !== 'defend') {
    core.setFailed(`coldstep: invalid mode "${mode}"; use "detect" or "defend".`);
    return;
  }

  const failOnError = resolveFailOnError(mode);
  const logLevel = core.getInput('log-level') || 'info';
  const smokeTestEgress = inputBoolDefault('smoke-test-egress', false);
  const ioUringDisable = inputBoolDefault('io-uring-disable', true);
  const signingKey = core.getInput('signing-key') || '';
  const releasePath = core.getInput('release-path').trim();
  const detectProfile = (core.getInput('detect-profile') || 'standard').trim().toLowerCase();
  const featureGates = resolveFeatureGates();

  if (ioUringDisable) {
    try {
      execFileSync('sudo', ['sysctl', '-w', 'kernel.io_uring_disabled=2'], { stdio: 'inherit' });
      core.info('io_uring disabled via sysctl (kernel.io_uring_disabled=2) — closes io_uring eBPF bypass vector');
    } catch (e) {
      core.warning(
        `io-uring-disable: sysctl kernel.io_uring_disabled=2 failed (${e instanceof Error ? e.message : String(e)}); ` +
          'io_uring-based syscall bypasses may not be blocked on this runner',
      );
    }
  }

  const actionPath = actionRootPath();
  const baseDir = process.env.GITHUB_WORKSPACE || actionPath;
  const detectLog = path.join(baseDir, '.coldstep-detect.md');
  // PID file lives in the workspace so bash steps can read it without knowing the action path.
  const pidFile = path.join(baseDir, '.coldstep.pid');
  const agentStatus = path.join(baseDir, '.coldstep-ready.json');
  const eventsLog = path.join(baseDir, '.coldstep-events.jsonl');

  fs.writeFileSync(detectLog, '', 'utf8');
  if (fs.existsSync(agentStatus)) fs.unlinkSync(agentStatus);

  const stderrLog = path.join(baseDir, '.coldstep-agent.stderr.log');
  if (failOnError && fs.existsSync(stderrLog)) fs.unlinkSync(stderrLog);

  let binPath: string;
  if (releasePath) {
    const src = path.isAbsolute(releasePath) ? releasePath : path.join(baseDir, releasePath);
    if (!fs.existsSync(src)) {
      core.setFailed(`release-path not found: ${src}`);
      return;
    }
    binPath = src;
    try { fs.chmodSync(binPath, 0o755); } catch { /* best-effort */ }
    core.info(`coldstep: using release-path binary ${src}`);
  } else {
    binPath = await ensureColdstepBinary();
  }

  const allowlist = resolveAllowlist(baseDir);
  const noDefaultIgnoredNets = inputBoolDefault('no-default-ignored-nets', false);

  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    GITHUB_WORKSPACE: baseDir,
    COLDSTEP_DETECT_LOG: detectLog,
    COLDSTEP_ALLOWED_HOSTS: allowlist.allowedHosts,
    COLDSTEP_ALLOWED_IPS: allowlist.allowedIPs,
    COLDSTEP_IGNORED_IP_NETS: allowlist.ignoredNets,
    COLDSTEP_NO_DEFAULT_IGNORED_NETS: noDefaultIgnoredNets ? 'true' : 'false',
    COLDSTEP_ALLOWED_DOMAINS: allowlist.allowedDomains,
    COLDSTEP_FEATURE_GATES: featureGates,
    COLDSTEP_DETECT_PROFILE: detectProfile,
    CI_GUARD_MODE: mode,
    COLDSTEP_LOG_LEVEL: logLevel,
    COLDSTEP_AGENT_STATUS: agentStatus,
    COLDSTEP_SIGNING_KEY: signingKey,
  };
  if (smokeTestEgress) {
    childEnv.COLDSTEP_EVENTS_LOG = eventsLog;
  }

  let stderrFd: number | undefined;
  let stdio: 'ignore' | ['ignore', 'ignore', number] = 'ignore';
  if (failOnError) {
    stderrFd = fs.openSync(stderrLog, 'w', 0o600);
    stdio = ['ignore', 'ignore', stderrFd];
  }
  let spawnErr: Error | undefined;
  const child = spawn('sudo', ['-E', binPath, 'run'], {
    cwd: actionPath,
    env: childEnv,
    detached: true,
    stdio,
  });
  // Wait for either a successful 'spawn' or an 'error' event, with a 200 ms
  // fallback so a slow kernel error path doesn't stall startup indefinitely.
  await new Promise<void>((resolve) => {
    child.once('spawn', resolve);
    child.once('error', (err: Error) => {
      spawnErr = err;
      resolve();
    });
    setTimeout(resolve, 200);
  });
  if (stderrFd !== undefined) {
    try {
      fs.closeSync(stderrFd);
    } catch {
      /* ignore */
    }
  }
  if (spawnErr !== undefined) {
    core.setFailed(`coldstep: failed to spawn agent (${spawnErr.message})`);
    return;
  }
  if (child.pid === undefined) {
    core.setFailed('coldstep: failed to spawn agent (no pid — check sudo and that the binary exists)');
    return;
  }
  if (child.exitCode !== null) {
    core.setFailed(`coldstep: agent exited immediately with code ${child.exitCode}`);
    return;
  }
  child.unref();
  fs.writeFileSync(pidFile, String(child.pid), 'utf8');
  core.info(`coldstep started pid=${child.pid} mode=${mode}`);

  if (!failOnError) {
    core.warning(
      'fail-on-error is false: workflow steps run immediately without waiting for .coldstep-ready.json — short jobs may observe incomplete BPF attach.',
    );
  }

  if (smokeTestEgress) {
    const probeScript = [
      'set +e',
      'sleep 1',
      'timeout 10 bash -c \'printf "x" >/dev/udp/1.1.1.1/53\' >/dev/null 2>&1 || true',
      'timeout 10 bash -c \'printf "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n" >/dev/tcp/example.com/80\' >/dev/null 2>&1 || true',
    ].join('\n');
    const probe = spawn('bash', ['-c', probeScript], { detached: true, stdio: 'ignore' });
    probe.unref();
    core.info('smoke-test-egress: background UDP :53 + HTTP :80 probes started (opt-in; smoke-test-egress defaults to false)');
  }

  if (failOnError) {
    const readyBudgetMs = parseReadyTimeoutMs();
    core.info(
      `fail-on-error: waiting up to ${readyBudgetMs / 1000}s for ${agentStatus} (agent BPF load + cgroup attach before ready file); adjust ready-timeout-seconds input if needed`,
    );
    core.info(`fail-on-error: agent stderr logged to ${stderrLog}`);
    const outcome = await waitForAgentReady(agentStatus, readyBudgetMs, child, { progressEveryMs: 45_000 });
    if (outcome !== 'ready') {
      if (fs.existsSync(agentStatus)) {
        const head = headUtf8File(agentStatus, 220);
        if (head.trim() !== '') {
          core.error(`coldstep-ready snapshot (${agentStatus}, first 220 chars):\n${head}${head.length >= 220 ? '…' : ''}`);
        }
      }
      const tail = tailUtf8File(stderrLog, 14_000);
      if (tail.trim() !== '') core.error(`coldstep agent stderr (tail, ${stderrLog}):\n${tail}`);

      if (outcome === 'explicit_not_ready') {
        core.setFailed(
          'coldstep agent reported not ready (.coldstep-ready.json ok:false or invalid shape — defend mode often means syscall egress tracing failed to attach after cgroup programs). See stderr tail and COLDSTEP_BPF_VERBOSE_VERIFY in README.',
        );
      } else if (outcome === 'malformed_status') {
        core.setFailed(`${agentStatus} exists but is not valid JSON for ~45s (partial write or corruption). Check disk/workspace path and agent logs.`);
      } else if (outcome === 'child_exit') {
        core.setFailed('coldstep agent exited before reporting ready (see stderr tail above if present).');
      } else {
        core.setFailed(
          `coldstep agent did not become ready in time (${readyBudgetMs / 1000}s — BPF verifier/load/DNS/cgroup attach). Increase ready-timeout-seconds if loads are legitimately slow; see COLDSTEP_BPF_VERBOSE_VERIFY in README.`,
        );
      }
      try {
        process.kill(child.pid!, 'SIGTERM');
      } catch {
        /* ignore */
      }
    } else {
      core.saveState('coldstep_wait_ready_ok', 'true');
    }
  }
}
