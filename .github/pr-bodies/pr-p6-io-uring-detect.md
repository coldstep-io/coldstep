## Summary

Implements **P6 Phase 1** — io_uring write-class submission detection via `SEC("raw_tp/io_uring_submit_sqe")` (kernel 5.14+). io_uring submissions bypass the syscall hooks used elsewhere in detect mode; the existing `io-uring-disable` sysctl gate is the primary defense, and this is the runtime fallback that surfaces SQEs when the gate is bypassed or off.

## What changed

- **`bpf/trace_connect_obs.h`** — `struct io_uring_send_event` (40 bytes, `_Static_assert`-locked: 8 ts + 4 pid + 4 fd + 4 daddr + 2 dport + 1 op + 1 _pad + 16 comm).
- **`bpf/trace_connect.bpf.c`** — `io_uring_events` ringbuf (64 KiB), `io_uring_ringbuf_reserve_failures` per-cpu counter, and `SEC("raw_tp/io_uring_submit_sqe")` handler. Filter is `IORING_OP_SENDMSG` (9) and `IORING_OP_SEND` (26) — both unambiguously network sends, so emission does not need fd→socket resolution. The C source touches only `req->opcode`, so it compiles against any vmlinux.h that exposes `struct io_kiocb` (5.1+). `IORING_OP_WRITE` / `IORING_OP_WRITEV` arrive in Phase 2 alongside fd resolution (struct `io_cqe` is post-5.15 and not stable in older vmlinux BTF).
- **`internal/telemetry/event.go`** — `IOUringSendEvent` JSONL type (`type: "io_uring_send"`).
- **`internal/telemetry/telemetry.go`** — `Summary.IoUringSendTotal` and `IoUringRingbufReserveFailures`.
- **`internal/agent/agent_linux_bpf_start.go`** — `startIoUringTrace` does a best-effort attach on the already-loaded traceconnect collection; failure (older kernel, missing tracepoint) yields a degraded `BPFStatus` row rather than failing the agent.
- **`internal/agent/agent_linux.go`** — registers the new ringbuf reader, defer block for stats sampling, and reader goroutine wiring.
- **`internal/agent/agent_linux_ring_read.go`** — `readIoUringRing` drains the ringbuf, decodes via `decodeIOUringSendEvent`, maps the raw IORING_OP_ byte → string label, and appends JSONL.
- **`internal/agent/agent_linux_decode.go`** — `decodeIOUringSendEvent` + `ioUringOpName` (`2 → WRITEV`, `9 → SENDMSG`, `23 → WRITE`, `26 → SEND`, else UNKNOWN — values forward-compat for Phase 2).
- **`internal/agent/agent_linux_state*.go`** — `ioUringSendN` + `ioUringRingbufReserveFailuresN` counters, accessors, snapshot wiring.
- **`internal/agent/agent_linux_policy_maps.go`** — `readIoUringRingbufReserveFailureCount`.
- **`internal/report/digest_types.go`** — `DigestInput.IoUringSendTotal` and `IoUringRingbufReserveFailures`.
- **`internal/report/digest.go`** — KPI row (`**io_uring writes** | N network sends observed (SNI extraction not possible)`), gap-parts entry in the triage ribbon, Technical-details narrative. All hidden when zero.
- **`action.yml`** — `io-uring-disable` description notes the Phase 1 detection fallback; sysctl disable remains the primary defense.

## Phase 1 scope (deliberate)

- **SEND/SENDMSG only.** Both opcodes are unambiguously socket sends. Emit without fd→socket resolution.
- **No payload sniff.** The SQE submission point holds no userspace buffer state; SNI / HTTP cannot be extracted here. This is detection visibility only.
- **Graceful kernel-version fallback.** Attach failure (kernel < 5.14) marks the new BPFStatus row degraded; the agent continues. Detected via `link.AttachRawTracepoint` returning `ENOENT`.
- **No feature gate.** The probe is narrowly filtered (two socket opcodes), so it stays cheap on workloads that don't use io_uring; always-attempt avoids the operator-flag complexity of `tls_sni` / `fs_events`.

## Constraints honored

- Two modes only (`detect`, `defend`) — no `enforce` references introduced.
- Generated BPF artifacts (`bpf/vmlinux.h`, `internal/bpf/**/*_bpfel.go`, `*_bpfeb.go`) not committed.
- gofmt clean, encoding scan clean.
- `go vet` + cross-platform tests pass locally; Linux BPF compile + integration covered by `coldstep-ci-runner.yml`.

## Tests

- `internal/agent/abi_wire_linux_test.go` — `io_uring_send_event` wire size guard (`8+4+4+4+2+1+1+16 == 40`), paired with `_Static_assert(sizeof(struct io_uring_send_event) == 40)` in `bpf/trace_connect_obs.h`.
- `internal/agent/decode_network_linux_test.go` — `decodeIOUringSendEvent` round-trip (all fields), too-short rejection, op-byte → string mapping for all four future opcodes plus UNKNOWN.
- `internal/report/digest_test.go` — KPI row hidden when `IoUringSendTotal == 0`, visible (with triage-ribbon gap-parts entry) when non-zero.

## Follow-ups (out of scope)

- **P6 Phase 2** — extend to `IORING_OP_WRITE` / `IORING_OP_WRITEV`, paired with fd→socket resolution (requires `struct io_cqe` BTF or an alternate fd-lookup path) so file I/O does not flood.
- Defend-mode enforcement of io_uring egress (separate track; Phase 1 is detect-only).
