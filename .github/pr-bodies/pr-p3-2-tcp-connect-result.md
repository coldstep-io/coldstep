## Summary

Implements **P3-2** — paired `kprobe`/`kretprobe` on `tcp_v4_connect`, so the agent can distinguish established TCP connections from timed-out, refused, or unreachable ones.

Before this change every TCP event was recorded at `connect(2)` syscall *entry*, before the kernel had even attempted the handshake. The detect digest already documented this limitation (`TCP semantics: rows reflect connect(2) attempts at syscall enter, not confirmed established sockets`). After this change the kretprobe captures the kernel return code, the JSONL stream gains a supplementary `tcp_result` event correlated by `pid_tgid`, and the digest renders a new **TCP connections** KPI row — e.g. `18 established · 3 refused · 1 timeout · 2 unreachable`.

## What changed

- **`bpf/trace_tcp_connect_kprobe.inc`** *(new)* — declares the `tcp_v4_connect_inflight` HASH map (key=`pid_tgid` u64, value=u8 marker, 4096 entries), a 32-byte `connect_result_event` wire struct with a `0xC0EE0001` magic prefix, plus the entry kprobe and the kretprobe. The pair runs synchronously in the caller's task context so `pid_tgid` is a sufficient correlation key. The kretprobe uses `PT_REGS_RC(ctx)` for the kernel return value (0 on success, negative errno otherwise), then emits the result event into the existing `connect_events` ringbuf. `BPF_NOEXIST` on the insert avoids stomping a prior in-flight entry on a nested invocation.

- **`bpf/trace_connect.bpf.c`** — pulls in the new include alongside the other `trace_*_obs.inc` files. No other BPF source changed.

- **`internal/agent/agent_linux_bpf_start.go`** — new `attachTCPConnectKprobes` helper that wraps `link.Kprobe` + `link.Kretprobe` for the pair, with paired cleanup on partial failure. We do **not** strip the kprobe programs from the BPF spec on unsupported kernels (unlike defend's LSM stripping): `BPF_PROG_TYPE_KPROBE` is universally available on every Linux kernel coldstep supports, so `prog_load` cannot fail. The realistic failure mode is attach-time when `tcp_v4_connect` isn't exposed via the kprobe machinery — extremely rare (would require `CONFIG_KPROBES=n`, which no hosted Ubuntu kernel ships with). When attach fails we log + carry on; the entry-side `connect_event` still records the attempt, just without a paired result.

- **`internal/agent/agent_linux.go`** — calls `attachTCPConnectKprobes` after `startSyscallTrace` succeeds, registers a new BPF hook status row `kprobe tcp_v4_connect (connect_result)`, and `defer`s both links' `Close`.

- **`internal/agent/agent_linux_decode.go`**, **`agent_linux_state_sections.go`** — `decodeConnectResultEvent` + `connectResultMagic`/`connectResultEventWireSize` constants. Wire size is locked to the BPF C struct via `_Static_assert` on the BPF side and a new entry in `TestNetworkAndAuditWireSizes` on the Go side.

- **`internal/agent/agent_linux_ring_read.go`** — magic-prefix dispatch in `readConnectRing`: `CANARY_MAGIC` still goes to the canary state, the new `CONNECT_RESULT_MAGIC` decodes into a `telemetry.TCPResultEvent`, anything else is a regular `connect_event`. Linux PIDs are bounded by `PID_MAX_LIMIT` (4194304) so neither magic can collide with a real `tgid`.

- **`internal/agent/agent_linux_state.go`** — `runStats.addTCPResult(bucket)` + `snapshotTCPResultCounts()` so the digest can render the breakdown.

- **`internal/telemetry/event.go`** — new `TCPResultEvent` JSONL record (`type: "tcp_result"`) with `result` (int32, 0 = success, negative errno otherwise) and `result_str` (coarse classification).

- **`internal/telemetry/connect_result.go`** — `ConnectResultString` maps the int32 to one of `established` / `refused` / `timeout` / `unreachable` / `in_progress` / `denied` / `other`. Errno values are the architecture-independent generic uapi numbers (same on x86_64 and arm64).

- **`internal/report/digest.go`** + **`digest_aggregation.go`** + **`digest_types.go`** — new `TCPResultCounts` field on `DigestInput`, `formatTCPResultBreakdown` helper, new "TCP connections" KPI row rendered when the kretprobe produced any events. The "TCP semantics" footnote swaps between the new wording and a fallback that points at the BPF hook status table when the kretprobe didn't attach.

- **`internal/bpf/traceconnect/abi_test.go`** — new map-shape assertion for `tcp_v4_connect_inflight` (Hash, 4096 entries, 8-byte key, 1-byte value).

- **Tests** — `connect_result_test.go` covers every bucket in `ConnectResultString`; `digest_tcp_result_test.go` covers ordering, empty, all-zero, unknown-bucket suppression; `agent_linux_test.go`'s `stableRingDropKinds` grows two entries (`tcp_result_decode`, `tcp_result_jsonl`).

- **`CHANGELOG.md`** — `[Unreleased]` entry describing the feature.

## Constraints honored

- **No `enforce` references** introduced; mode strings stay `detect` / `defend`.
- **No generated BPF files** committed (`internal/bpf/**/*_bpfel.go` / `*_bpfeb.go` and `bpf/vmlinux.h` remain gitignored).
- **`//go:build linux` guards** — all kprobe / kretprobe wiring sits behind the existing Linux-only build tags; non-Linux stubs unchanged.
- **gofmt** — clean across all touched files.
- **Encoding** — `scripts/check-encoding.sh` clean.
- **Wire-size ABI guard** — `_Static_assert` on the BPF side + `TestNetworkAndAuditWireSizes` on the Go side both pin `sizeof(connect_result_event) == 32`.

## Failure modes

- **Kretprobe attach fails** → log + continue, BPF hook status row marked degraded, digest falls back to the legacy "TCP connect attempts" wording. No JSONL changes.
- **`tcp_v4_connect_inflight` map full** → silently drop the result event for the offending invocation. The entry-side `connect_event` still records.
- **`connect_events` ringbuf full** → existing `note_connect_ringbuf_reserve_failed()` counter increments, surfaced in the KPI table.

## Validation

- `bash scripts/check-gofmt.sh` — pass.
- `bash scripts/check-encoding.sh` — pass.
- `go test ./internal/telemetry/... ./internal/report/...` — pass locally (Windows host).
- BPF compile + verifier load + kretprobe attach are validated by CI's `coldstep-ci-runner.yml` (`unit`, `unit-arm64`, `integration`, `detect-mode`, `defend-mode`).

## Follow-ups (out of scope)

- Defend-mode equivalent (kretprobe in defend would let the policy decision be aware of the kernel verdict — but defend already blocks pre-`tcp_v4_connect` so this is mostly informational).
- IPv6 (`tcp_v6_connect`) — repo is IPv4-only by design; tracked outside P3.
