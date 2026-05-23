## Summary

- After the cgroup `connect4` probe confirms the cgroup hook is enforcing, run the same dial-loop-and-drain pattern against the LSM deny ringbuf (`probeLSMSilent` in `internal/agent/agent_linux_probe.go`). If no matching deny event arrives within `lsmProbeTimeout` (1500ms), the LSM programs are attached but the kernel never invokes them.
- When silent, downgrade `defendState.mode` from `defend+lsm` to `defend+cgroup` via a new `defendState.downgradeMode(mode)` accessor and emit an `lsm_attached_but_silent` `BPFStatus` row with the Ubuntu 24.04 `lsm=` boot chain hint in `Detail`.
- The LSM ringbuf reader stays alive for any events that may still fire — we just stop *claiming* LSM defense in the digest when it's observably absent.
- Document the Ubuntu 24.04 default `lsm=lockdown,yama,apparmor` situation (no `bpf` token in the boot chain) in code comments on both the probe helper and the call site.
- Pin behaviour with two unit tests: `TestProbeLSMSilent_NilReaderReturnsSilent` (nil reader short-circuits to silent) and `TestDefendStateDowngradeModePreservesAllowlistCounters` (the downgrade must not clobber allowlist sizes captured by `setModeAndAllowlist`).

## Why

Bug #3 from the post-v0.4.0 bug hunt. Symptom: digests on Ubuntu 24.04 runners advertised `defend+lsm` even though `security_socket_connect` never dispatched to `lsm/socket_connect`, because the default boot chain (`lsm=lockdown,yama,apparmor`) omits the `bpf` token. AttachLSM returns success, the program loads, and BPFStatus shows OK — but enforcement is actually 100% cgroup. The digest was misleading users and CI gates into thinking LSM was contributing to defense.

Pairs with bug #2 (fall back to cgroup-only on non-sendpage LSM load failure). Together they make the LSM path opportunistic rather than load-bearing: the agent advertises LSM defense only when it actually fires, and never refuses to start because LSM is missing or silent.

## Test plan

- [ ] `go test ./internal/agent/... -count=1` on Linux — including the new `TestProbeLSMSilent_NilReaderReturnsSilent` and `TestDefendStateDowngradeModePreservesAllowlistCounters`
- [ ] `go build ./...` — clean cross-package compile
- [ ] `bash scripts/check-gofmt.sh`
- [ ] `bash scripts/check-encoding.sh`
- [ ] CI sweep on Linux (gofmt, encoding, vet, staticcheck, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode) — the defend-mode job exercises the post-attach probe against a real kernel; on `ubuntu-latest` (24.04) we expect the new `lsm_attached_but_silent` row to surface in the telemetry artifact
