## Summary

- **BPF:** Replaced the dead aggregate `unobserved_egress_syscalls_observed` ARRAY (no increment sites since the pwrite* sniff arms were added; always read 0) with a 4-slot `partial_egress_observed` PERCPU_ARRAY in `bpf/trace_connect.bpf.c`. Slots: `sendfile`/`sendfile64`, `splice`, `sendmmsg` (first-message-only), plus one reserved slot.
- **Hot path:** Added `note_partial_egress(slot)` and wired one constant-key bump into each of the `NR_SENDFILE`, `NR_SPLICE`, and `NR_SENDMMSG` arms. No change to the existing sniff / `handle_udp_obs_*` paths — just an extra `__sync_fetch_and_add` against a bounded PERCPU_ARRAY (lock-free per-CPU; verifier-friendly fixed key).
- **Go agent:** New `readPartialEgressCounts` reader (`internal/agent/agent_linux_policy_maps.go`) sums each slot across CPUs and feeds three new `runStats` fields (`sendfileObservedN`, `spliceObservedN`, `sendmmsgFirstOnlyN`). The defer in `Run` (`internal/agent/agent_linux.go`) writes the snapshot at shutdown, mirroring the existing partial-visibility counters.
- **Digest + telemetry:** `DigestInput`, the triage ribbon's "Capture gaps" row, the KPI table, the long explanatory sub-paragraph, and `telemetry.Summary` (JSON keys `sendfile_observed`, `splice_observed`, `sendmmsg_first_only`) all surface the three paths independently. Each KPI row only appears when its counter is non-zero (same convention as `udp_sendmsg_multi_iovec_observed` et al.). The aggregate `UnobservedEgressSyscalls` field was removed end-to-end since it now had no source (the BPF map produced it).
- **Tests:** `internal/bpf/traceconnect/abi_test.go` drops the singleton `unobserved_egress_syscalls_observed` shape and adds a `partial_egress_observed` shape assertion (PerCPUArray, MaxEntries=4, KeySize=4, ValueSize=4). `internal/report/digest_test.go` `TruthfulnessInterpretation` test exercises all three new fields.
- **Changelog:** `[Unreleased]` entry under **Changed**.

## Motivation (BG-01)

After BG-04 the `sendfile`, `splice`, and `sendmmsg` paths still only emit destination/length telemetry — no HTTP/TLS payload sniff. The old aggregate counter was the only signal that any of those paths fired, but since the dispatch arms were rewritten to use `handle_udp_obs_emit_pt` it had no increment sites — operators read 0 even when traffic was flowing. BG-01 replaces the dead aggregate with a per-syscall breakdown so users can see *which* syscall drove the visibility gap and decide whether to invest in full sniff arms for it.

## Hard constraints (followed)

- No use of the word "enforce" introduced anywhere.
- No commit of `plans/`, `docs/`, `AGENTS.md`, `ARCHITECTURE.md`, `bpf/vmlinux.h`, or `internal/bpf/**/*_bpfel.go` / `*_bpfeb.go`.
- BPF map stays bounded (4 ≤ 8 slots), constant compile-time keys, `__sync_fetch_and_add` on PERCPU_ARRAY values.
- Existing sniff paths untouched; behavior change is additive (one new counter bump per relevant dispatch arm).

## Validation

- `bash scripts/check-gofmt.sh` — pass
- `bash scripts/check-encoding.sh` — pass
- `go vet ./internal/report/... ./internal/telemetry/... ./internal/config/... ./internal/policy/...` — pass (Linux-tagged BPF packages need generated bpf2go files; CI handles)
- `go test ./internal/report/... ./internal/telemetry/... ./internal/config/... ./internal/policy/... -count=1` — pass (cross-platform suites)
- BPF compile + integration suite — relies on Linux CI (`coldstep-ci-runner.yml` unit + integration matrix); no Docker available locally.

## Notes for reviewers

- Generated bpf2go artifacts (`internal/bpf/traceconnect/*_bpfel.go`, etc.) regenerate via `build-agent-linux.sh` in CI; they're gitignored and so the new `PartialEgressObserved` field on the generated `TraceconnectObjects` only materializes after `go generate` runs in the Linux job.
- The PR keeps `note_partial_egress` callsite layout matching the surrounding arms (sendfile/splice bump *after* the emit so a verifier rejection of the bump wouldn't have changed prior digest counts; sendmmsg bumps *before* the first-message handler since the count is meant to reflect every multi-message call).
