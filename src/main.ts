import * as core from '@actions/core';
import { execFileSync, spawn, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

function inputBoolDefault(name: string, defaultVal: boolean): boolean {
  const v = core.getInput(name);
  if (v === '') {
    return defaultVal;
  }
  return ['true', '1', 'yes', 'on'].includes(v.toLowerCase());
}

async function waitForAgentReady(
  statusPath: string,
  timeoutMs: number,
  child?: ChildProcess,
): Promise<boolean> {
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

  try {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (exitedEarly) {
        core.error(
          `coldstep agent exited before reporting ready (code=${exitCode}, signal=${exitSignal ?? 'none'})`,
        );
        return false;
      }
      try {
        if (fs.existsSync(statusPath)) {
          const raw = fs.readFileSync(statusPath, 'utf8');
          const j = JSON.parse(raw) as { ok?: boolean };
          if (j.ok === true) {
            return true;
          }
        }
      } catch {
        /* retry */
      }
      await new Promise((r) => setTimeout(r, 150));
    }
    return false;
  } finally {
    if (child) {
      child.off('exit', onExit);
    }
  }
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
  const mode = (core.getInput('mode') || 'detect').trim().toLowerCase();
  const failOnError = inputBoolDefault('fail-on-error', false);
  const logLevel = core.getInput('log-level') || 'info';
  const reportJobSummary = inputBoolDefault('report-job-summary', true);
  const smokeTestEgress = inputBoolDefault('smoke-test-egress', false);

  const actionPath = process.env.GITHUB_ACTION_PATH || process.cwd();
  const baseDir = process.env.GITHUB_WORKSPACE || actionPath;
  const detectLog = path.join(baseDir, '.coldstep-detect.md');
  const pidFile = path.join(actionPath, '.coldstep.pid');
  const binPath = path.join(actionPath, 'bin', 'coldstep');
  const script = path.join(actionPath, 'scripts', 'build-agent-linux.sh');
  const agentStatus = path.join(baseDir, '.coldstep-ready.json');
  const eventsLog = path.join(baseDir, '.coldstep-events.jsonl');

  fs.mkdirSync(path.join(actionPath, 'bin'), { recursive: true });
  fs.writeFileSync(detectLog, '', 'utf8');
  if (fs.existsSync(agentStatus)) {
    fs.unlinkSync(agentStatus);
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
  };
  if (smokeTestEgress) {
    childEnv.COLDSTEP_EVENTS_LOG = eventsLog;
  }

  const child = spawn('sudo', ['-E', binPath, 'run'], {
    cwd: actionPath,
    env: childEnv,
    detached: true,
    stdio: 'ignore',
  });
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
      's.sendto(req, 0, addr)',
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
    // Hosted runners sometimes spend >60s on apt/kernel churn before the agent starts; enforce
    // mode also resolves allowlist domains sequentially (context timeout is enforced in Go).
    const ok = await waitForAgentReady(agentStatus, 180_000, child);
    if (!ok) {
      core.setFailed(
        'coldstep agent did not become ready (BPF/load/DNS); see job logs and ensure ubuntu-latest.',
      );
      try {
        process.kill(child.pid!, 'SIGTERM');
      } catch {
        /* ignore */
      }
    }
  }
}

run().catch((e) => {
  core.setFailed(e instanceof Error ? e.message : String(e));
});
