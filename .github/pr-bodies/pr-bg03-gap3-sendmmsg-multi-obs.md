## Summary

- **BPF:** `COLDSTEP_NR_SENDMMSG` previously only delegated message 0 to `handle_udp_obs_sendmsg`; messages 1..N-1 were silently dropped (only counted at `sendmmsg_multi_message_observed`). This PR adds a stripped-down `handle_udp_obs_sendmsg_extra` in `bpf/trace_udp_sendmsg.inc` that emits destination + datagram_len only (no iov[1] TLS/HTTP peek so per-slot verifier complexity stays bounded), and walks messages 1..7 from `bpf/trace_connect.bpf.c` via `#pragma unroll`. `bpf_loop()` requires kernel >= 5.17, which excludes our ubuntu-22.04 (5.15) CI lane, so the unroll must be compile-time.
- **New counter:** `sendmmsg_unobserved_extra` PERCPU_ARRAY (1 entry) sums individual extra messages beyond index 7 that the unrolled loop could not reach (vlen >= 9). Distinct from `sendmmsg_multi_message_observed` which counts *calls* with vlen > 1.
- **Go agent:** `readSendmmsgUnobservedExtraCount` in `internal/agent/agent_linux_policy_maps.go` sums the new map across CPUs; wired through `runStats.sendmmsgUnobservedExtraN`, `telemetry.Summary.SendmmsgUnobservedExtra` (JSON: `sendmmsg_unobserved_extra`), and `report.DigestInput.SendmmsgUnobservedExtra`. Surfaced in the detect digest's capture-gaps row and UDP KPI table when non-zero.
- **Tests:** `internal/bpf/traceconnect/abi_test.go` adds a shape assertion for the new PERCPU_ARRAY map.

## Defend mode

Unaffected — `cgroup/sendmsg4` fires per-message inside the kernel's `__sys_sendmmsg` loop and already enforces against every message. This PR is observation-only.

## Hard constraints (followed)

- No use of the word "enforce" introduced anywhere.
- No commit of `bpf/vmlinux.h`, `internal/bpf/**/*_bpfel.go` / `*_bpfeb.go` (generated artifacts).
- New map is a bounded PERCPU_ARRAY (1 entry); the unroll loop is compile-time bounded (8 iterations).
- Existing message-0 path through `handle_udp_obs_sendmsg` is unchanged — extra-message coverage is purely additive.

## Validation

- `bash scripts/check-gofmt.sh` — pass
- `bash scripts/check-encoding.sh` — pass
- `go vet ./internal/report/... ./internal/telemetry/...` — pass
- `go test ./internal/report/... ./internal/telemetry/... -count=1` — pass
- BPF compile + verifier acceptance + `internal/agent` integration matrix — relies on Linux CI (`coldstep-ci-runner.yml`); no Docker available locally.

## Notes for reviewers

- Generated bpf2go stubs (`internal/bpf/traceconnect/*_bpfel.go`, `*_bpfeb.go`) regenerate via `build-agent-linux.sh` in CI. The new `SendmmsgUnobservedExtra` field on the generated `TraceconnectObjects` only materializes after `go generate` runs in the Linux job; until then `readSendmmsgUnobservedExtraCount` carries a `// TODO: regenerate after building on Linux` marker per the BG-03 plan handoff notes.
- Counter is named `sendmmsg_unobserved_extra` (messages we could not observe) — orthogonal to `sendmmsg_multi_message_observed` (call counter, unchanged). Both stay PERCPU_ARRAY for write-side contention.
- The unroll bound (`SENDMMSG_EXTRA_MAX = 7`) is a balance between coverage and verifier complexity; the typical sendmmsg caller (QUIC/UDP send batching) batches 1–16 messages and the first 8 cover the common case. Operators with vlen > 8 workloads see the `sendmmsg_unobserved_extra` counter rise.
