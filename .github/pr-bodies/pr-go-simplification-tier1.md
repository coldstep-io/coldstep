## Summary

Tier-1 Go simplification pass across the agent, report, policy, config, and action layers. Pure refactor -- no behaviour change, no new tests required. Net **~219 LOC removed** across 9 files (100 insertions, 319 deletions).

Each numbered item is its own GPG-signed commit:

1. **`internal/agent/agent_linux_policy_maps.go` + `internal/agent/agent_linux.go`** -- drop 17 thin BPF counter-read wrappers (`readDenyReserveFailureCount`, `readUDPRingbufReserveFailureCount`, ...). They only nil-checked `*Objects` and forwarded to the existing `readUint32CounterMap` / `readUint32PerCPUArraySum` helpers; every call site already guards the nullable pointer (or passes `&stackvar`). Also factor `loadDefendMaps` and `loadLSMDefendMaps` into one `loadDefendMapsForBackend` parameterised by a `defendMapSet` -- cgroup vs LSM differ only in which `*ebpf.Map` fields they expose.

2. **`internal/report/digest_aggregation.go` + `internal/report/digest.go`** -- collapse the four identical `tcpEmptyReason` / `udpEmptyReason` / `httpEmptyReason` / `tlsEmptyReason` funcs into a single `sectionEmptyReason(degraded, readerErrors)`; call sites pass the per-section bool/int directly.

3. **`internal/policy/ignore.go` + `cmd/coldstep-action/allowlist_files.go`** -- dedupe comma+whitespace token splitters. `ParseIgnoredIPNets` drops the duplicate `splitIgnoredRawFields` in favour of the package-private `splitFields`; `cmd/coldstep-action` extracts a single `splitTrimNonEmpty` helper used by `splitCommaPaths`, `splitAllowInlineTokens`, and `parseAllowlistFileBody`.

4. **`internal/policy/allowlist.go` + `internal/config/config.go`** -- consolidate domain normalisation into `internal/policy` (new `NormalizeDomainsFromRaw`); `internal/config` deletes its near-identical `normalizeDomains` and calls the policy helper instead.

5. **`internal/config/config.go` + `cmd/coldstep-action/main.go`** -- drop the redundant explicit legacy-mode rejection branch in both `LoadFromEnv` and `normalizeCompositeMode`. The follow-up "mode not in {detect, defend}" check produces the same error message and was already covering it.

## Out of scope

Per the task brief, **`bpf/`**, **`internal/bpf/`**, and **`scripts/`** are untouched -- BPF work is in flight on other branches.

## Verification

- `bash scripts/check-gofmt.sh`
- `bash scripts/check-encoding.sh`
- `go build ./...`
- `go test ./...` (Windows host: passes for all packages with build tag `!windows`; `internal/bpf/*` test failures are pre-existing on Windows because generated stubs only exist after `go generate` on Linux -- unchanged by this PR)
- CI on hosted Linux will exercise the agent + integration matrix
