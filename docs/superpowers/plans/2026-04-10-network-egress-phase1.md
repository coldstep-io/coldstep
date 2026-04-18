# Network egress phase 1 (TCP / UDP / cleartext HTTP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing nightstalker detect-only agent on GitHub-hosted `ubuntu-latest` so egress **TCP connects**, **UDP** (DNS-shaped traffic first), and **cleartext HTTP** interactions produce **real** log lines in `.nightstalker-detect.md` (and thus the job Summary via the existing post step), validated by **live** `nc` / workflow probes—**no mocked sockets** for the canonical example path.

**Repository state (2026-04-12):** Phase 1 as written here is **complete on `main`** (TCP/UDP/HTTP BPF + JSONL + digest + nightstalker-demo). Use this file as a **closed checklist**; **next** egress work is tracked in **`2026-04-10-egress-full-stack-monitor-report-ui.md`** (optional TLS/SNI, richer tuples), **`AGENTS.md`**, and any newer phase-2 plans you add.

**Architecture:** Add one or more CO-RE BPF programs using **stable tracepoints** (same lesson as `sched_process_exec`: avoid unsupported `fentry` on Azure kernels). Emit compact events on a **BPF ring buffer** (same pattern as `trace_exec.bpf.c`). Go **userspace** loads objects with `bpf2go`, reads records, formats markdown lines, and appends via the existing detect-log path. **DNS:** parse responses in userspace (or minimal BPF payload capture) and maintain a **TTL-bounded cache** to annotate TCP lines with `fqdn=` when known. **HTTP:** phase 1 treats **port 80** and/or leading `HTTP/1.` bytes as signal; **no TLS decryption**. If a hook is missing on a kernel, **skip that program** and log a warning (graceful degrade).

**Tech stack:** Go 1.23+, `github.com/cilium/ebpf` / `bpf2go`, Clang, `libbpf` headers, existing `scripts/build-agent-linux.sh`, Node action unchanged except longer build if needed, GitHub Actions `ubuntu-latest`.

---

## File map

| Path | Responsibility |
|------|----------------|
| `bpf/trace_connect.bpf.c` | BPF: **`raw_tp/sys_enter`** multiplexer — TCP `connect`, UDP `sendto`, cleartext HTTP/80 sniff → shared ringbuf path (as shipped) |
| `bpf/trace_dns.bpf.c` | BPF: DNS reply sniff → ringbuf (`internal/bpf/tracedns`) |
| `internal/bpf/traceconnect/` | `gen.go` + bpf2go for `trace_connect.bpf.c` |
| `internal/bpf/tracedns/` | `gen.go` + bpf2go for `trace_dns.bpf.c` |
| `internal/agent/agent_linux.go` | Load collections; multiplex ringbuf readers; JSONL + digest |
| `internal/agent/dns_wire.go`, `dns_cache.go` | Parse DNS **A** responses, TTL + bounded cache, lookup by IPv4 |
| `internal/config/config.go` | Mode, allowlists, smoke probes, feature gates, etc. |
| `scripts/build-agent-linux.sh` | Generates **traceexec**, **traceconnect**, **traceenforce**, **tracedns** |
| `.github/workflows/nightstalker-demo.yml` | Real TCP / UDP :53 / HTTP :80 / `dig` / `curl` probes + greps |
| `internal/agent/*_integration_test.go` | Linux integration: real `net.Dial` / sendto after BPF attach |
| `README.md` | Egress + forensics semantics; representative examples |

---

### Task 1: Kernel hook spike (document + probe)

**Files:**
- Create: `docs/superpowers/specs/2026-04-10-network-hook-notes.md` (short: which tracepoints exist / chosen)

- [x] **Step 1:** On `ubuntu-latest` (local container or CI one-off job), run `bpftrace -l '*connect*'` or `ls /sys/kernel/debug/tracing/events/syscalls` / read BTF to list candidates (`sys_enter_connect`, `inet_sock_set_state`, etc.).

- [x] **Step 2:** Pick **one** primary hook for IPv4 TCP destination (addr+port) + pid/tgid/comm; document rejection reasons for alternatives.

- [x] **Step 3:** Commit the hook-notes doc only. (See [`docs/superpowers/specs/2026-04-10-network-hook-notes.md`](../specs/2026-04-10-network-hook-notes.md).)

---

### Task 2: BPF — TCP connect event

**Files:**
- Create: `bpf/trace_connect.bpf.c`
- Create: `internal/bpf/traceconnect/gen.go`
- Generated: `internal/bpf/traceconnect/traceconnect_bpfel.go` (gitignored today — align with repo policy)
- Modify: `scripts/build-agent-linux.sh` if include paths need new file

- [x] **Step 1:** Copy patterns from `bpf/trace_exec.bpf.c` (maps, ringbuf, `SEC("tp/...")`, CO-RE types from `vmlinux.h`).

- [x] **Step 2:** Define struct: `kind`, `pid`, `tgid`, `comm[16]`, `daddr`, `dport`, `proto` (fixed values).

- [x] **Step 3:** `go generate` in `internal/bpf/traceconnect` on Linux with `vmlinux.h` present; fix compile errors.

- [x] **Step 4:** Commit BPF + `gen.go` (not generated `.go` if gitignored).

---

### Task 3: Go — load TCP program and append lines

**Files:**
- Modify: `internal/agent/agent_linux.go`
- Modify: `cmd/ci-runtime-guard` only if wiring needed

- [x] **Step 1:** Load `traceconnect` objects alongside `traceexec` (two collections OK for phase 1).

- [x] **Step 2:** Run a second ringbuf read loop (goroutine + shared shutdown) or merge with `select`-style fan-in; **do not** block exec path indefinitely.

- [x] **Step 3:** Append detect rows via GFM table (`report.FormatDetectTCPRow`) + JSONL telemetry (supersedes plain `kind=tcp` text-only lines).

- [x] **Step 4:** `go test ./...` (non-integration) passes on dev OS.

- [x] **Step 5:** Commit.

---

### Task 4: Integration test (real TCP)

**Files:**
- Modify: `internal/agent/agent_integration_test.go` or add `agent_network_integration_test.go` with `//go:build integration && linux`

- [x] **Step 1:** After attach, `net.DialTimeout("tcp", "1.1.1.1:443", …)` (or another stable address) from test.

- [x] **Step 2:** Assert detect log contains `**tcp**` / remote IP and policy text (Markdown table format).

- [x] **Step 3:** Document in plan if runner blocks outbound (unlikely for 1.1.1.1:443).

- [x] **Step 4:** Commit.

---

### Task 5: UDP + DNS cache (phase 1b)

**Files (as shipped):**
- `internal/agent/dns_wire.go`, `dns_cache.go` + tests
- `bpf/trace_connect.bpf.c` (UDP **`sendto`** path) + `bpf/trace_dns.bpf.c` + `internal/bpf/tracedns/`

- [x] **Step 1:** Implement minimal DNS response parser (**A** in v1; **AAAA** ignored for IPv4 TCP) + **TTL-bounded** cache with **max entry** cap (`internal/agent/dns_wire.go`, `dns_cache.go`).

- [x] **Step 2:** BPF `tracedns` + ringbuf samples; userspace parses responses.

- [x] **Step 3:** TCP **Notes** column includes `fqdn` when cache hit.

- [x] **Step 4:** Unit tests: `dns_wire_test.go`, `dns_cache_test.go`; integration remains live network.

- [x] **Step 5:** Commit.

---

### Task 6: Cleartext HTTP signal

**Files (as shipped):**
- `bpf/trace_connect.bpf.c` (HTTP/80 sniff), `internal/telemetry/event.go` (**`http`** JSONL type), `internal/report/digest.go` (HTTP KPI + rows)

- [x] **Step 1:** Port **80** produces dedicated **`http`** JSONL rows (bounded request prefix) and digest rows; TCP **Notes** may still tag cleartext context where relevant.

- [x] **Step 2:** nightstalker-demo runs **curl** to `http://$d/`, **`nc`** with a minimal **GET** to `example.com:80`, plus **dig** for resolver traffic.

- [x] **Step 3:** Commit.

---

### Task 7: nightstalker-demo + README (real examples)

**Files:**
- Modify: `.github/workflows/nightstalker-demo.yml`
- Modify: `README.md`

- [x] **Step 1:** nightstalker-demo **`nc`** step sends raw **HTTP/1.1** request bytes to **example.com:80**.

- [x] **Step 2:** nightstalker-demo **`dig +short … A`** per domain (capped).

- [x] **Step 3:** README uses **representative** Markdown table rows (not verbatim CI paste; avoids stale runner-specific IPs).

- [x] **Step 4:** Commit.

---

### Task 8: CI + branch hygiene

- [x] **Step 1:** Ensure `.github/workflows/ci.yml` still runs `go test` + integration + `npm run build`.

- [x] **Step 2:** Verify with **`bash scripts/docker-ubuntu-test.sh`** (and optional `NIGHTSTALKER_INTEGRATION=1`) before push.

- [x] **Step 3:** Land via **`main`** when explicitly requested; otherwise use a feature branch + PR.

---

## Non-goals (phase 1)

- TLS decryption; egress blocking; cgroup-only filtering on shared runners; QUIC; full HTTP body capture.

---

## Execution note

Phase 1 landed on **`main`** after review. For **new** large BPF or verifier-risky changes, still prefer a **feature branch** or **git worktree** (see **`AGENTS.md`**).
