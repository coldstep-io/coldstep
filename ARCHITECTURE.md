# Coldstep Architecture

Coldstep is a GitHub Actions composite action that runs a lightweight eBPF egress telemetry agent on `ubuntu-latest` CI runners. It observes (detect mode) or blocks (defend mode) outbound network connections made during a workflow job, and emits structured JSONL telemetry for inspection, allowlist building, and alerting.

## High-level flow

```
GitHub Actions job
  └── uses: coldstep-io/coldstep@main
        ├── src/start.ts   (pre-hook)  → downloads agent binary, writes config, launches agent
        ├── user's job steps run       → agent observes / blocks egress via eBPF
        └── src/stop.ts    (post-hook) → signals agent to stop, collects JSONL report
```

## Components

### Action entrypoints (`src/`)

TypeScript (compiled to `dist/`) running under Node 20 via the `pre` / `post` lifecycle of a `using: node20` action.

- **`start.ts`** — resolves the correct agent binary for the runner kernel (downloaded from a GitHub release or built in CI), writes `coldstep-config.json`, spawns `coldstep-agent` in the background, and waits for `.coldstep-ready.json` to confirm BPF attach before returning control to the user's job steps.
- **`stop.ts`** — sends `SIGTERM` to the agent PID, polls for process exit (up to 3 s), reads `coldstep-report.jsonl`, and surfaces the egress summary as a step summary and an output variable.

### Agent (`cmd/coldstep-action/`, `internal/agent/`)

A Go binary compiled for `linux/amd64`. It loads BPF programs, attaches them to the runner, streams events from kernel to userspace via BPF ring buffers, and writes structured JSONL telemetry.

- **`internal/agent/agent_linux.go`** — main agent lifecycle: load BPF skeleton → attach programs → launch ring-buffer readers → write `.coldstep-ready.json` → drain events until `SIGTERM` → flush report.
- **`internal/agent/agent_linux_digest.go`** — baseline digest logic used in detect mode to compute a per-run fingerprint of observed connections for allowlist diffing.
- **`internal/bpf/`** — generated BPF skeleton wrappers produced by `bpf2go` (CO-RE, BTF-enabled).

### BPF programs (`bpf/`)

eBPF C programs compiled with `clang` + CO-RE. Two attachment points:

| Program | Hook type | Purpose |
|---|---|---|
| `defend_cgroup_sock_addr_ipv4` | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | Primary egress control — runs at `connect(2)` in the runner cgroup; returns `EPERM` for blocked connections in defend mode. Also writes deny events to the `deny_events` ring buffer. |
| `trace_connect` | kprobe / tracepoint | Observes `connect(2)` and related syscalls to capture connection metadata (IP, port, SNI, process). |
| LSM hooks (optional) | `BPF_PROG_TYPE_LSM` | Secondary deny path on kernels that support BPF LSM (`CONFIG_BPF_LSM`). Drains to `lsm_deny_events` ring buffer when attached. |

The cgroup program is always loaded and attached regardless of kernel LSM support. The `deny_events` ring buffer is the primary deny telemetry path; `lsm_deny_events` is drained on a secondary goroutine when the LSM hook is also attached.

### Policy / allowlist (`internal/policy/`, `internal/config/`)

- **`internal/config/`** — parses `coldstep-config.json` written by `start.ts`. Validates inputs, classifies allowlist entries (IP literals, CIDRs, plain domains, wildcard domains) and merges them from inline `allow`, `allow-file`, and legacy per-type inputs.
- **`internal/policy/`** — evaluates connection events against the policy at runtime. Returns allow/deny and the matching rule for telemetry annotation.

### Telemetry pipeline (`internal/telemetry/`, `internal/report/`)

- **`internal/telemetry/`** — defines the event schema. Ring-buffer events are decoded from BPF structs and enriched with process tree context (`internal/proctree/`), DNS reverse lookup, and TLS SNI extraction before emission.
- **`internal/report/`** — aggregates allow/deny events and serialises the final JSONL report consumed by `stop.ts`.

### Supporting packages

| Package | Role |
|---|---|
| `internal/proctree/` | Walks `/proc` to attribute connections to the originating process and its ancestors |
| `internal/safepath/` | Path traversal guard used when reading proc entries |
| `internal/atomicwrite/` | Atomic file write (write-to-tmp + rename) for report and ready files |
| `internal/cgroup/` | Locates the runner cgroup v2 path for BPF attachment |
| `cmd/coldstep/` | Standalone CLI for local testing and allowlist validation |
| `cmd/coldstep-report/` | Offline report post-processing tool |

## Data flow

```
kernel connect(2)
  │
  ├── cgroup BPF program (always attached)
  │     ├── defend mode: EPERM for blocked IPs → deny_events ringbuf
  │     └── detect mode: pass-through → allow_events ringbuf
  │
  └── LSM BPF hook (if kernel supports BPF_LSM)
        └── lsm_deny_events ringbuf (secondary)

userspace agent goroutines
  ├── readAllowRing()   ← allow_events
  ├── readDenyRing()    ← deny_events       (always)
  └── readLSMDenyRing() ← lsm_deny_events   (conditional)
        │
        ▼
  event enrichment (proctree, DNS, SNI)
        │
        ▼
  policy evaluation
        │
        ▼
  JSONL telemetry → coldstep-report.jsonl
```

## Modes

| Mode | Egress behaviour | Use case |
|---|---|---|
| `detect` | All connections allowed; fully observed | Baseline profiling, allowlist building |
| `defend` | Connections not on allowlist receive EPERM | Enforce known-good egress in production CI |

The word `enforce` is legacy and not used anywhere in the codebase. The two modes are `detect` and `defend` only.

## Build

The agent binary is cross-compiled inside a Docker container (`docker/Dockerfile.agent`) that has `clang`, `llvm`, `libbpf-dev`, and `bpftool` available. BPF C programs are compiled to BTF-annotated object files, then wrapped by `bpf2go` which generates the Go skeleton. The resulting binary embeds the BPF object and loads it via `cilium/ebpf` at runtime.

For pure-Go packages, the standard Go toolchain suffices (`/usr/bin/go` in WSL Ubuntu).

## Key design decisions

**Why cgroup sock_addr rather than TC/XDP?** The cgroup hook fires synchronously inside the calling process's context at `connect(2)`, giving reliable per-process attribution and the ability to return `EPERM` without packet manipulation. TC and XDP operate at a lower layer and can't block syscalls directly.

**Why ring buffers over perf buffers?** BPF ring buffers (kernel 5.8+) provide ordered, lossless delivery with lower overhead than per-CPU perf buffers, which is important for high-connection-rate jobs.

**Why a Go agent rather than pure BPF userspace?** The enrichment pipeline (process tree walk, DNS, SNI reassembly, JSON report) is complex enough to warrant a real language with a garbage collector. The binary is self-contained and downloaded at action runtime so consuming repos need no build tooling.
