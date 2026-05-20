## Summary

- Extends the Phase 1 `raw_tp/io_uring_submit_sqe` probe with a best-effort `bpf_probe_read_user` peek at the SQE's user-space buffer to detect TLS ClientHello prefixes.
- Gated behind `COLDSTEP_DETECT_PROFILE=enhanced` via a new `io_uring_peek_cfg` array map; the standard-profile fast path stays unchanged (single CO-RE opcode read).
- Surfaces hits in the JSONL stream (`has_tls_hello` on `io_uring_send` events) and as a high-signal **🚨 io_uring TLS ClientHello prefixes** digest row + narrative bullet.

## Why this matters

io_uring submissions bypass every syscall-based BPF arm; the sysctl gate is the primary defense. Phase 1 surfaced that the bypass path is being used. Phase 2 adds the strongest signal that's possible from the SQE submission point alone — outbound TLS handshakes initiated over io_uring. The 6-byte TLS record signature has effectively zero collision rate against random data, so a non-zero count is high-confidence evidence of TLS-over-io_uring egress that escapes syscall-based hooks.

SNI extraction is still out of reach (the record header peek doesn't reach the SNI extension), and `IORING_OP_WRITE` / `IORING_OP_WRITEV` still need fd→socket resolution before they can join the probe without flooding on regular file I/O.

## What changed

### BPF

- `bpf/trace_connect.bpf.c` — added `io_uring_peek_cfg` (1-entry array) and `io_uring_tls_hello_observed` (PERCPU array) maps, plus the bounded `bpf_probe_read_user` peek inside `trace_io_uring_submit_sqe`. The hard-coded `cmd.data[0]` offset (`io_kiocb + 8`) is documented; older kernels with a different layout read unrelated bytes and the strict TLS signature check filters the noise out.
- `bpf/trace_connect_obs.h` — repurposed the trailing `_pad` byte of `io_uring_send_event` as `has_tls_hello`. Wire size unchanged at 40 B so the existing `_Static_assert` and Go-side ABI guard test continue to pass.

### Go agent

- `internal/agent/agent_linux_bpf_start.go` — `startIoUringTrace` now takes an `enhancedPeek bool` and flips `io_uring_peek_cfg[0] = 1` when the detect profile is `enhanced`. Returns a `peekCfgFailed` signal that degrades the BPF status row when the map update fails.
- `internal/agent/agent_linux.go` — wires `cfg.DetectProfile == "enhanced"` through to the new flag, reads the new per-CPU TLS hello counter into `runStats` at shutdown.
- `internal/agent/agent_linux_decode.go` / `agent_linux_ring_read.go` — decode `has_tls_hello` from the wire, surface it on the JSONL event.
- `internal/agent/agent_linux_state.go` / `agent_linux_digest.go` — `ioUringTLSHelloN` carried into `telemetry.Summary` + `DigestInput`.

### Telemetry + digest

- `internal/telemetry/event.go` — `IOUringSendEvent.HasTLSHello bool`.
- `internal/telemetry/telemetry.go` — `Summary.IoUringTLSHelloObserved int`.
- `internal/report/digest.go` + `digest_types.go` — gap-parts ribbon entry, technical-details table row, narrative bullet.

### Tests

- `internal/agent/decode_network_linux_test.go` — round-trip test gains a `has_tls_hello=1` case; existing tests adapted to the new return signature.
- `internal/report/digest_test.go` — new `TestBuildDetectMarkdown_IoUringTLSHelloRow` covers both the hidden-when-zero and visible-when-set paths.
- `internal/bpf/traceconnect/abi_test.go` — adds `io_uring_peek_cfg`, `io_uring_ringbuf_reserve_failures`, and `io_uring_tls_hello_observed` to the BPF map shape guards.

### Docs

- `action.yml` — `io-uring-disable` description documents the enhanced-profile peek behavior.

## Test plan

- [ ] CI `gofmt` + encoding scan
- [ ] CI `go test ./...` (unit, including the new `TestBuildDetectMarkdown_IoUringTLSHelloRow`)
- [ ] CI `go test -race` on `internal/agent/...`
- [ ] CI integration leg (matrix, root, BPF) — verifies the BPF C still compiles and loads on kernels with `io_uring_submit_sqe` exposed.
- [ ] `detect-mode` end-to-end demo (workflow) — confirms ABI wire-size guard still holds.
- [ ] `defend-mode` end-to-end demo — unaffected, but verifies no regression in the shared `traceconnect` collection.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
