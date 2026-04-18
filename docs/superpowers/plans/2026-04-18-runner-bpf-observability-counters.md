# Runner BPF Observability Counters (Plan E) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose **ringbuf reserve failure** and similar **lossy-path counters** from `traceconnect` (and optionally `traceenforce`) BPF maps into the **agent shutdown JSON summary** (`internal/telemetry.Summary`) and digest/Meta JSONL so operators can see overload or map pressure on GitHub-hosted runners.

**Architecture:** Follow the existing pattern for `connect4_tuple_update_failures`: add a **32-bit array map** in `bpf/trace_connect.bpf.c`, increment with `__sync_fetch_and_add` when `bpf_ringbuf_reserve` for `udp_events` (and optionally `http_events` / `tls_events`) returns NULL. Regenerate `internal/bpf/traceconnect/*_bpfel.go` via bpf2go. Read maps at shutdown in `internal/agent/agent_linux.go` alongside `readConnect4TupleUpdateFailureCount`, merge into `telemetry.Summary` new fields.

**Tech Stack:** BPF C, cilium ebpf loader, Go, `docker` + `scripts/build-agent-linux.sh`.

---

## File Structure / Responsibility Map

- Modify: `bpf/trace_connect.bpf.c` — add `udp_ringbuf_reserve_failures` (and optionally `http_` / `tls_`) ARRAY maps; increment in `trace_udp_obs.inc` (and HTTP/TLS reserve sites) **only on reserve failure**.
- Modify: `bpf/trace_udp_obs.inc` — change `handle_udp_obs_emit` to count failed reserve before return (split reserve + submit path).
- Modify: `bpf/trace_http_obs.inc`, `bpf/trace_tls_write.inc` — same pattern only if plan scoped to UDP-only first (Step 1 UDP-only reduces blast radius).
- Modify: `internal/agent/agent_linux.go` — readers for new map(s), populate `telemetry.Summary`.
- Modify: `internal/telemetry/telemetry.go` — add JSON fields on `Summary` struct (backward compatible `omitempty`).
- Regenerate: `internal/bpf/traceconnect/*.go` after BPF change (bpf2go).
- Test: extend `internal/agent/agent_linux_test.go` if a pure Go helper exists for summary numbers; otherwise integration documentation in plan Step verification only.

---

### Task 1: BPF counters for UDP ringbuf reserve failures

**Files:**
- Modify: `bpf/trace_connect.bpf.c`
- Modify: `bpf/trace_udp_obs.inc`

- [ ] **Step 1: Add ARRAY map + inline note (before `trace_udp_obs.inc`)**

In `bpf/trace_connect.bpf.c`, after `connect4_tuple_update_failures` map block, add `udp_ringbuf_reserve_failures` ARRAY map, then add `static __always_inline void note_udp_ringbuf_reserve_failed(void)` that atomically increments index `0` in that map (same pattern as `note_connect4_tuple_update_failed`). **Placement:** define this **above** `#include "trace_udp_obs.inc"` so the `.inc` file can call it.

```c
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} udp_ringbuf_reserve_failures SEC(".maps");
```

- [ ] **Step 2: Reserve/submit pattern with failure accounting**

Replace inline `bpf_ringbuf_reserve` in `bpf/trace_udp_obs.inc` with:

```c
static __always_inline void handle_udp_obs_emit(__be16 sin_port, __be32 sin_addr, __u32 len)
{
	struct udp_send_event *ue =
		bpf_ringbuf_reserve(&udp_events, sizeof(*ue), 0);
	if (!ue) {
		note_udp_ringbuf_reserve_failed();
		return;
	}
	/* ... existing fill + submit ... */
}
```

(copy existing struct fill lines from current `handle_udp_obs_emit` body below the `if (!ue)` branch).

- [ ] **Step 3: Rebuild BPF objects**

Run (host or Docker per repo norms): `bash scripts/build-agent-linux.sh` from repo root (or documented container entry).  
Expected: regenerated `internal/bpf/traceconnect/*_bpfel.go` and `*_bpfeb.go` include `UdpRingbufReserveFailures` map.

---

### Task 2: Go agent reads map and writes Summary

**Files:**
- Modify: `internal/telemetry/telemetry.go`
- Modify: `internal/agent/agent_linux.go`

- [ ] **Step 1: Extend Summary**

Add to `Summary` in `internal/telemetry/telemetry.go`:

```go
UDPRingbufReserveFailures int `json:"udp_ringbuf_reserve_failures,omitempty"`
```

- [ ] **Step 2: Read helper**

In `internal/agent/agent_linux.go`, add `readUDPRingbufReserveFailureCount(objs *traceconnect.TraceconnectObjects) uint32` analogous to `readConnect4TupleUpdateFailureCount`, reading index `0` from `objs.UdpRingbufReserveFailures`.

Wire into `stats.snapshotSummary` / defer path where `Connect4TupleUpdateFailures` is already set.

- [ ] **Step 3: Verification**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./... -count=1`  
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add bpf/trace_connect.bpf.c bpf/trace_udp_obs.inc internal/bpf/traceconnect internal/telemetry/telemetry.go internal/agent/agent_linux.go
git commit -m "feat(telemetry): expose UDP ringbuf reserve failure counter"
```

---

## Self-Review

- Spec: Plan E delivers operational visibility — Task 1–2 cover BPF + Summary.
- No `TBD` placeholders.
- Map name matches bpf2go regenerated identifiers (`UdpRingbufReserveFailures`).
