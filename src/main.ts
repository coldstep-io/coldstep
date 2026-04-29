import * as core from '@actions/core';
import { execFileSync, spawn, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

function tailUtf8File(filePath: string, maxChars: number): string {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    if (raw.length <= maxChars) {
      return raw;
    }
    return raw.slice(-maxChars);
  } catch {
    return '';
  }
}

function headUtf8File(filePath: string, maxChars: number): string {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    if (raw.length <= maxChars) {
      return raw;
    }
    return raw.slice(0, maxChars);
  } catch {
    return '';
  }
}

function inputBoolDefault(name: string, defaultVal: boolean): boolean {
  const v = core.getInput(name);
  if (v === '') {
    return defaultVal;
  }
  return ['true', '1', 'yes', 'on'].includes(v.toLowerCase());
}

function pidLooksAlive(pid: number | undefined): boolean | undefined {
  if (pid === undefined || pid <= 0) {
    return undefined;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Outcome for fail-on-error readiness polling — avoids burning runner minutes when the file exists but never becomes ok:true. */
type ReadyPollOutcome =
  | 'ready'
  | 'timeout'
  | 'child_exit'
  /** Agent wrote explicit operational failure into the status file (e.g. enforce syscall stack did not attach). */
  | 'explicit_not_ready'
  /** Status file exists but JSON is invalid for too long (partial write or corruption). */
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
  if (child) {
    child.on('exit', onExit);
  }

  /** Clock start when JSON.parse repeatedly fails on a non-empty file (atomic write grace window). */
  let malformedSince: number | null = null;
  const malformedBudgetMs = 45_000;

  try {
    const waitStart = Date.now();
    const deadline = waitStart + timeoutMs;
    let lastProgressLog = waitStart;
    while (Date.now() < deadline) {
      // Readiness must be checked before exit status: defend mode can write ok:true then hit a
      // kernel deny event immediately; fail-fast deny handling used to exit the process while the
      // status file still contained ok:true, and checking exitedEarly first made us miss it.
      if (fs.existsSync(statusPath)) {
        const raw = fs.readFileSync(statusPath, 'utf8').trim();
        let parsed: { ok?: unknown } | undefined;
        try {
          parsed = JSON.parse(raw) as { ok?: unknown };
        } catch {
          malformedSince ??= Date.now();
          if (Date.now() - malformedSince >= malformedBudgetMs) {
            return 'malformed_status';
          }
          /* keep polling — likely mid-write */
        }

        if (parsed !== undefined) {
          malformedSince = null;
          if (parsed.ok === true) {
            return 'ready';
          }
          if (parsed.ok === false) {
            return 'explicit_not_ready';
          }
          if (parsed.ok !== undefined && parsed.ok !== null) {
            core.error(
              `coldstep-ready.json has unexpected ok type (${typeof parsed.ok}); refusing to poll until timeout`,
            );
            return 'explicit_not_ready';
          }
          /* ok missing — likely incomplete write; keep polling */
        }
      } else {
        malformedSince = null;
      }

      if (exitedEarly) {
        core.error(
          `coldstep agent exited before reporting ready (code=${exitCode}, signal=${exitSignal ?? 'none'})`,
        );
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
              const j = JSON.parse(fs.readFileSync(statusPath, 'utf8')) as { ok?: unknown };
              okHint =
                typeof j.ok === 'boolean'
                  ? `parsed ok=${j.ok}`
                  : `parsed ok field=${JSON.stringify(j.ok)}`;
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
    if (child) {
      child.off('exit', onExit);
    }
  }
}

function parseReadyTimeoutMs(): number {
  const raw = core.getInput('ready-timeout-seconds').trim();
  const fallback = 25 * 60;
  if (raw === '') {
    return fallback * 1000;
  }
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

async function run(): Promise<void> {
  if (process.platform !== 'linux') {
    core.setFailed('coldstep requires a Linux runner (use runs-on: ubuntu-latest)');
    return;
  }

  const allowedHosts = core.getInput('allowed-hosts') || '';
  const allowedIPs = core.getInput('allowed-ips') || '';
  const ignoredIpNets = core.getInput('ignored-ip-nets') || '';
  const noDefaultIgnoredNets = inputBoolDefault('no-default-ignored-nets', false);
  const allowedDomains = core.getInput('allowed-domains') || '';
  const featureGates = core.getInput('feature-gates') || '';
  const releasePath = core.getInput('release-path').trim();
  let mode = (core.getInput('mode') || 'detect').trim().toLowerCase();
  if (mode === 'enforce') {
    core.setFailed(
      'coldstep: input mode "enforce" is not supported; use "defend" for blocking egress (see README / action.yml).',
    );
    return;
  }
  if (mode !== 'detect' && mode !== 'defend') {
    core.setFailed(`coldstep: invalid mode "${mode}"; use "detect" or "defend".`);
    return;
  }
  const failOnError = inputBoolDefault('fail-on-error', false);
  const logLevel = core.getInput('log-level') || 'info';
  const reportJobSummary = inputBoolDefault('report-job-summary', true);
  const smokeTestEgress = inputBoolDefault('smoke-test-egress', false);
  const ioUringDisable = inputBoolDefault('io-uring-disable', true);
  const signingKey = core.getInput('signing-key') || '';

  if (ioUringDisable) {
    try {
      execFileSync('sudo', ['sysctl', '-w', 'io_uring_disabled=2'], { stdio: 'inherit' });
      core.info('io_uring disabled via sysctl (io_uring_disabled=2) — closes io_uring eBPF bypass vector');
    } catch (e) {
      core.warning(
        `io-uring-disable: sysctl io_uring_disabled=2 failed (${e instanceof Error ? e.message : String(e)}); ` +
          'io_uring-based syscall bypasses may not be blocked on this runner',
      );
    }
  }

  const actionPath = process.env.GITHUB_ACTION_PATH || process.cwd();
  const baseDir = process.env.GITHUB_WORKSPACE || actionPath;
  const detectLog = path.join(baseDir, '.coldstep-detect.md');
  const pidFile = path.join(actionPath, '.coldstep.pid');
  const binPath = path.join(actionPath, 'bin', 'coldstep');
  const script = path.join(actionPath, 'public_scripts', 'build-agent-linux.sh');
  const agentStatus = path.join(baseDir, '.coldstep-ready.json');
  const eventsLog = path.join(baseDir, '.coldstep-events.jsonl');

  fs.mkdirSync(path.join(actionPath, 'bin'), { recursive: true });
  fs.writeFileSync(detectLog, '', 'utf8');
  if (fs.existsSync(agentStatus)) {
    fs.unlinkSync(agentStatus);
  }
  const stderrLog = path.join(baseDir, '.coldstep-agent.stderr.log');
  if (failOnError && fs.existsSync(stderrLog)) {
    fs.unlinkSync(stderrLog);
  }

  if (releasePath) {
    const src = path.isAbsolute(releasePath) ? releasePath : path.join(baseDir, releasePath);
    if (!fs.existsSync(src)) {
      core.setFailed(`release-path not found: ${src}`);
      return;
    }
    fs.copyFileSync(src, binPath);
    fs.chmodSync(binPath, 0o755);
    core.info(`coldstep: using release-path binary ${src}`);
  } else {
    execFileSync('bash', [script, actionPath], { stdio: 'inherit' });
  }

  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    // Pin workspace for the sudo child so Go defaults (digest/JSONL paths) match the
    // paths this action uses under GITHUB_WORKSPACE (sudo env filtering can drop vars).
    GITHUB_WORKSPACE: baseDir,
    COLDSTEP_DETECT_LOG: detectLog,
    COLDSTEP_ALLOWED_HOSTS: allowedHosts,
    COLDSTEP_ALLOWED_IPS: allowedIPs,
    COLDSTEP_IGNORED_IP_NETS: ignoredIpNets,
    COLDSTEP_NO_DEFAULT_IGNORED_NETS: noDefaultIgnoredNets ? 'true' : 'false',
    COLDSTEP_ALLOWED_DOMAINS: allowedDomains,
    COLDSTEP_FEATURE_GATES: featureGates,
    CI_GUARD_MODE: mode,
    COLDSTEP_LOG_LEVEL: logLevel,
    COLDSTEP_AGENT_STATUS: agentStatus,
    COLDSTEP_REPORT_JOB_SUMMARY: reportJobSummary ? 'true' : 'false',
    COLDSTEP_SIGNING_KEY: signingKey,
  };
  if (smokeTestEgress) {
    childEnv.COLDSTEP_EVENTS_LOG = eventsLog;
  }

  // Use numeric fds (not WriteStream): with detached:true the stream may still have fd=null and
  // spawn rejects stdio (see Node child_process validation).
  let stderrFd: number | undefined;
  let stdio: 'ignore' | ['ignore', 'ignore', number] = 'ignore';
  if (failOnError) {
    stderrFd = fs.openSync(stderrLog, 'w', 0o600);
    stdio = ['ignore', 'ignore', stderrFd];
  }
  const child = spawn('sudo', ['-E', binPath, 'run'], {
    cwd: actionPath,
    env: childEnv,
    detached: true,
    stdio,
  });
  if (stderrFd !== undefined) {
    try {
      fs.closeSync(stderrFd);
    } catch {
      /* ignore */
    }
  }
  child.on('error', (err) => {
    core.error(`coldstep: failed to spawn agent (${err.message})`);
  });
  if (child.pid === undefined) {
    // `spawn` can fail asynchronously (e.g. missing sudo); avoid writing `undefined` into the pid file.
    core.setFailed('coldstep: failed to spawn agent (no pid — check sudo and that the binary exists)');
    return;
  }
  child.unref();
  fs.writeFileSync(pidFile, String(child.pid), 'utf8');
  core.info(`coldstep started pid=${child.pid} mode=${mode}`);

  if (smokeTestEgress) {
    const probeScript = [
      'set +e',
      'sleep 1',
      'if command -v python3 >/dev/null 2>&1; then',
      '  python3 <<\'UDPY\'',
      'import socket',
      's = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)',
      's.sendto(b"x", ("1.1.1.1", 53))',
      's.close()',
      'UDPY',
      '  python3 <<\'PY\'',
      'import socket',
      'addr = ("example.com", 80)',
      'req = b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n"',
      's = socket.socket(socket.AF_INET, socket.SOCK_STREAM)',
      's.connect(addr)',
      's.sendall(req)',
      's.close()',
      'PY',
      'fi',
    ].join('\n');
    const probe = spawn('bash', ['-c', probeScript], {
      detached: true,
      stdio: 'ignore',
    });
    probe.unref();
    core.info(
      'smoke-test-egress: background UDP :53 + HTTP :80 probes started (opt-in; smoke-test-egress defaults to false)',
    );
  }

  if (failOnError) {
    // Hosted runners: allowlist DNS (bounded), then BPF loads. Defend mode writes ready only after
    // traceenforce + cgroup attach; verifier can be slow. If the status file exists with ok:false,
    // fail immediately (do not burn runner minutes until max wait).
    const readyBudgetMs = parseReadyTimeoutMs();
    core.info(
      `fail-on-error: waiting up to ${readyBudgetMs / 1000}s for ${agentStatus} (agent BPF load + cgroup attach before ready file); adjust ready-timeout-seconds input if needed`,
    );
    core.info(`fail-on-error: agent stderr logged to ${stderrLog}`);
    const outcome = await waitForAgentReady(agentStatus, readyBudgetMs, child, {
      progressEveryMs: 45_000,
    });
    if (outcome !== 'ready') {
      if (fs.existsSync(agentStatus)) {
        const head = headUtf8File(agentStatus, 220);
        if (head.trim() !== '') {
          core.error(
            `coldstep-ready snapshot (${agentStatus}, first 220 chars):\n${head}${head.length >= 220 ? '…' : ''}`,
          );
        }
      }
      const tail = tailUtf8File(stderrLog, 14_000);
      if (tail.trim() !== '') {
        core.error(`coldstep agent stderr (tail, ${stderrLog}):\n${tail}`);
      }
      if (outcome === 'explicit_not_ready') {
        core.setFailed(
          'coldstep agent reported not ready (.coldstep-ready.json ok:false or invalid shape — defend mode often means syscall egress tracing failed to attach after cgroup programs). See stderr tail and COLDSTEP_BPF_VERBOSE_VERIFY in README.',
        );
      } else if (outcome === 'malformed_status') {
        core.setFailed(
          `${agentStatus} exists but is not valid JSON for ~45s (partial write or corruption). Check disk/workspace path and agent logs.`,
        );
      } else if (outcome === 'child_exit') {
        core.setFailed(
          'coldstep agent exited before reporting ready (see stderr tail above if present).',
        );
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
      // Persist for post: the agent may clear/update `.coldstep-ready.json` after this step returns
      // if a later BPF attach fails (see agent_linux syscall-trace enforcement).
      core.saveState('coldstep_wait_ready_ok', 'true');
    }
  }
}

run().catch((e) => {
  core.setFailed(e instanceof Error ? e.message : String(e));
});
