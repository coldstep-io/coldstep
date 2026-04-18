# Runner DNS / TLS Visibility Extras (Plan D) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Incrementally improve **visibility** for DNS and TLS paths already partially covered by **`bpf/trace_dns.bpf.c`** and **`bpf/trace_tls_write.inc`**, without turning the agent into a full DPI tool: add **explicit counters** for lossy stages and document **limits** (TCP DNS / DoH remain out of scope for v1 unless explicitly unlocked later).

**Architecture:** **DNS:** add BPF **ARRAY** counter map `dns_ringbuf_reserve_failures` incremented when `bpf_ringbuf_reserve` fails for DNS events (mirror Plan E UDP pattern). **TLS:** add counter `tls_clienthello_truncated` when sniff buffer shorter than required ClientHello minimum (optional, only if a clean predicate exists in `trace_tls_write.inc`). **Userspace:** read new maps at shutdown and extend **`telemetry.Summary`** (`internal/telemetry/telemetry.go`) with `omitempty` integers.

**Tech Stack:** BPF C, Go summary JSON, Docker tests.

---

## File Structure / Responsibility Map

- Modify: `bpf/trace_dns.bpf.c` — failure counter map + increment on failed reserve in DNS emit path.
- Modify: `bpf/trace_tls_write.inc` or `trace_connect.bpf.c` — TLS truncation counter (only if branch identified without large refactor).
- Regenerate: `internal/bpf/tracedns/*` (and `traceconnect` if TLS map lives there).
- Modify: `internal/telemetry/telemetry.go` — new summary fields.
- Modify: `internal/agent/agent_linux.go` — map readers at shutdown.

---

### Task 1: DNS ringbuf reserve failures

**Files:**
- Modify: `bpf/trace_dns.bpf.c`
- Regenerate: `internal/bpf/tracedns/*`

- [ ] **Step 1: Add ARRAY map + note function**

Same pattern as Plan E:

```c
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} dns_ringbuf_reserve_failures SEC(".maps");
```

Increment where DNS ringbuf reserve fails.

- [ ] **Step 2: Rebuild + Go reader**

Add `DNSRingbufReserveFailures int` to `telemetry.Summary`, read in agent from `tracedns` objects map.

- [ ] **Step 3: Commit**

```bash
git commit -m "feat(dns): count DNS ringbuf reserve failures for runner telemetry"
```

---

### Task 2: TLS truncation counter (optional branch)

**Files:**
- Modify: `bpf/trace_tls_write.inc`

- [ ] **Step 1: Locate ClientHello parse entry**

At the earliest point the code **returns early** due to `len < MIN_CH_LEN`, increment a new ARRAY map `tls_sniff_short_circuit` (name stable for bpf2go).

- [ ] **Step 2: Summary + commit**

Extend `telemetry.Summary` with `TLSSniffShortCircuit int` `json:"tls_sniff_short_circuit,omitempty"`.

---

## Self-Review

- Plan D intentionally avoids **TCP DNS stream reassembly** (would be separate plan).
- Spec coverage: counters + summary fields map 1:1 to tasks.
