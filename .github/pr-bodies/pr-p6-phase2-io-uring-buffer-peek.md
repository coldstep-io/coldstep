## Summary

Implements **P6 Phase 2** of the io_uring write-bypass detection track: a bounded `bpf_probe_read_user` peek of the SQE user buffer for `IORING_OP_SEND` (26) and `IORING_OP_SENDMSG` (9), TLS ClientHello signature match, payload capture, and userspace SNI extraction. Gated behind `COLDSTEP_DETECT_PROFILE=enhanced` so standard-profile runs keep the same wire format and zero per-SQE overhead.

`io_uring_setup(2)` detection + sysctl disable remain the primary defenses; this hook surfaces a high-fidelity attribution signal (SNI) when async I/O is actually being used to bypass syscall-class tracepoints.

## What changed

### BPF (`bpf/`)

- **`bpf/trace_connect.bpf.c`** — new `SEC("raw_tp/io_uring_submit_sqe")` program. Reads the io_kiocb opcode via CO-RE, filters to OP_SEND / OP_SENDMSG, reads the user-buffer pointer at `io_kiocb + 8` (`cmd` union's `data[0]` on kernels 5.14+), then:
  - `bpf_probe_read_user` of 128 bytes into a stack scratch buffer (constant size — verifier-safe). `// audit(5f): checked` — return value gates every subsequent use.
  - TLS ClientHello signature check (`0x16` / `0x03` / `_` / `_` / `_` / `0x01` at indices 0/1/5). `// audit(5c): bounds checked` — all indices within the 128-byte read.
  - On magic match, a second `bpf_probe_read_user` of 256 bytes (`TLS_PAYLOAD_MAX`) into the ringbuf event payload window. If the wider read fails, the 128 already-peeked bytes are kept and `payload_len = 128`.
  - On any read failure, `peek_failed = 1` is set and the event is still submitted so userspace observes the SQE happened.
- **`bpf/trace_connect_obs.h`** — new `struct io_uring_tls_event` (292 B, alignment-locked via `_Static_assert`).
- **New maps**:
  - `io_uring_events` — 64 KiB ringbuf.
  - `io_uring_peek_cfg` — singleton `__u8` gate, written from userspace to 1 only when enhanced profile is requested.
  - `io_uring_ringbuf_reserve_failures` — `PERCPU_ARRAY` reserve-failure counter.

### Go (`internal/`)

- **`internal/telemetry/event.go`** — new `IOUringTLSEvent` JSONL type (`"io_uring_tls"`) with `SNI`, `Confidence` (`full` | `partial` | `unknown`), `PeekFailed`, `DstIP`, `DstPort`, `Op`.
- **`internal/telemetry/tls_clienthello.go`** — new pure-Go helper `IsTLSClientHelloMagic([]byte) bool` mirrors the BPF signature check so unit tests can exercise it without root. `ParseClientHelloSNI` is reused on the ring-reader path to populate `SNI` from the captured payload.
- **`internal/agent/agent_linux*.go`** — best-effort attach (degrades to a `BPFStatus` row on kernels < 5.14 instead of failing the agent), new ringbuf reader goroutine, gate-map flip when `COLDSTEP_DETECT_PROFILE=enhanced`, shutdown drain of the reserve-failure counter, new `runStats` fields for events + SNI-extracted + reserve failures.
- **`internal/telemetry/telemetry.go`** — `Summary` carries `IoUringTLSEvents`, `IoUringTLSSNIExtracted`, `IoUringRingbufReserveFailures` (omitempty).
- **`internal/report/digest.go`** — adds `| **io_uring TLS SNI: N extracted (enhanced profile)** | M events |` to the technical-details table, hidden when zero.

### Tests

- **`internal/telemetry/tls_clienthello_test.go`** — exhaustive table-driven coverage for `IsTLSClientHelloMagic`.
- **`internal/telemetry/event_test.go`** — three-arm JSONL round-trip for `IOUringTLSEvent` (full / peek-failed / partial confidence).
- **`internal/report/digest_test.go`** — three subtests: row hidden at zero events, row visible with `7 extracted (enhanced profile)`, and ringbuf reserve-failure row rendering.
- **`internal/bpf/traceconnect/abi_test.go`** — map-shape assertions for the three new maps.

## Constraints honored

- **Gate-by-default** — `io_uring_peek_cfg[0]` defaults to 0 (map creation zeroes it). Standard-profile runs never call `bpf_probe_read_user` on the SQE buffer.
- **Bounded reads only** — 128-byte magic peek and 256-byte payload capture are compile-time constants. No length variables on the read-size register; same pattern as `trace_tls_write.inc`.
- **Every `bpf_probe_read_user` return value is checked** before any subsequent use of the buffer. Annotated inline with `// audit(5f): checked`.
- **Index bounds are constant** — `peek[0]`, `peek[1]`, `peek[5]` all within the 128-byte stack buffer. Annotated `// audit(5c): bounds checked`.
- **Never crash on failure** — `peek_failed = 1`, base event still emitted. No `return` between `bpf_ringbuf_reserve` and `bpf_ringbuf_submit` after a successful reservation.
- **IPv4-only scope** preserved; no IPv6 claim anywhere.
- **No `enforce` references** introduced.

## Validation

- `bash scripts/check-gofmt.sh` — pass.
- `bash scripts/check-encoding.sh` — pass.
- `go vet ./internal/telemetry/... ./internal/report/...` — pass.
- `go test ./internal/agent/... ./internal/telemetry/... ./internal/report/... -count=1` — pass (cross-platform packages; the agent has a non-Linux stub so unit tests run on any host).
- BPF compile + verifier load + integration are validated by CI (`coldstep-ci-runner.yml`: `unit`, `unit-arm64`, `integration`, `detect-mode`).

## Follow-ups (out of scope)

- **fd → socket tuple resolution** for `IORING_OP_SEND` / `OP_SENDMSG` so `dst_ip` / `dst_port` are populated. Phase 3.
- **`IORING_OP_WRITE` / `OP_WRITEV`** support, which requires distinguishing socket vs file fd (struct io_cqe post-5.15).
- **`OP_SENDMSG` msghdr → iov[0] indirection** for kernels where the user buffer pointer in the SQE points to `struct msghdr` rather than the payload directly.
