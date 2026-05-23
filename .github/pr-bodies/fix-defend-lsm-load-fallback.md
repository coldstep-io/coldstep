## Summary

- When `prog_load` rejects the LSM section of the defend collection for any reason **other than** the kernel-6.5+ `lsm_socket_sendpage` removal (which is already handled), `LoadDefendObjectsForKernel` now strips every LSM program + LSM-only map and reloads the cgroup-only collection — instead of bubbling the error up and disabling defend entirely.
- Surface the degradation via a new `defend.LoadResult{LSMFellBack, LSMFallbackErr}` return value. The agent caller in `internal/agent/agent_linux.go` consumes it, flips local `haveLSM` to false so the LSM attach block is skipped, and emits a `lsm_load_failed_fallback_cgroup` `BPFStatus` row carrying the original `prog_load` error in `Detail`.
- Factor the LSM strip into a shared `stripAllLSM(*ebpf.CollectionSpec)` helper used by both the initial `wantLSM=false` path and the new fallback retry, so the two stay in sync.
- Update the function's caller-contract comment with the new return shape and what the caller MUST do on `LSMFellBack=true`.
- Pin behaviour with two unit tests in `internal/bpf/defend/loader_test.go`: `TestStripAllLSM` (every LSM section gone, cgroup/shared sections intact) and `TestLoadResultZeroValueSafe` (caller-visible zero-value invariants).

## Why

Bug #2 from the post-v0.4.0 bug hunt. The pre-existing code only retried after a sendpage-specific `prog_load` rejection. Any other LSM-related failure — `CONFIG_BPF_LSM` absent despite `features.HaveProgramType(ebpf.LSM)` returning ok, kernel `lsm=` boot chain without `bpf`, BTF mismatch on `socket_connect` / `socket_sendmsg`, etc. — propagated to the caller and aborted defend mode. The cgroup `connect4` / `sendmsg4` hooks are independent of LSM, so losing LSM should degrade the backend to `defend+cgroup`, not the whole agent.

Pairs with bug #3 (downgrade the backend label when LSM attaches but never fires) — together they make the LSM path opportunistic rather than load-bearing for defend mode.

## Test plan

- [ ] `go test ./internal/bpf/defend/... -count=1` on Linux — including the new `TestStripAllLSM` and `TestLoadResultZeroValueSafe`
- [ ] `go test ./internal/agent/... -count=1` — caller-side compilation + non-defend tests stay green
- [ ] `go build ./...` — caller in `agent_linux.go` consumes the new return signature
- [ ] `bash scripts/check-gofmt.sh`
- [ ] CI sweep on Linux (gofmt, encoding, vet, staticcheck, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode) — the defend-mode job is the one that actually exercises `prog_load` against the running kernel
