## Summary

- Reorder `cfg.Mode == config.ModeDefend` attach sequence in `internal/agent/agent_linux.go` so cgroup hooks (`cgroup/connect4`, `cgroup/sendmsg4`) attach **before** LSM hooks (`lsm/socket_connect`, `lsm/socket_sendmsg`, `lsm/socket_sendpage`, `lsm/io_uring_cmd`).
- Move `probeDefendEnforcement` so it confirms cgroup is actively denying *before* the LSM attach attempts run. The cgroup-readiness probe now also acts as the closing-edge of the Bug #14 race window — by the time the kernel might race a connect through during the LSM attach phase, cgroup is already verified-enforcing.
- Defer `defendState.setModeAndAllowlist(backend, ...)` to after both attach phases complete, since `backend` depends on `lsmAttachErr`.
- Add an inline comment explaining the ordering rationale and the specific Ubuntu 24.04 boot-chain scenario that surfaced the race.

## Why

Bug #14 from the post-v0.4.0 bug hunt. On kernels where LSM programs `prog_load` + `AttachLSM` succeed but the kernel never dispatches BPF into the LSM hook chain (Ubuntu 24.04 default boots with `lsm=lockdown,yama,apparmor` — no `bpf` token), the previous LSM-first order created a ~50-500 ms window where:

- LSM had attached, but was silent — the kernel never invoked our program.
- cgroup had not attached yet — its sequence runs after LSM in the old code.

Outbound connections initiated during that window passed through unfiltered. Workflow steps that ran very early (e.g. `npm ci` before the action's readiness probe, in repos that don't gate behind `fail-on-error: true`) could egress to non-allowlisted destinations without being blocked or even logged. Cgroup-first eliminates the window: it is the reliable always-on defense path on every kernel ≥ 5.5 with cgroupv2, and its enforcement is *positively confirmed* via `probeDefendEnforcement` before the agent reports ready. LSM remains as defense-in-depth on top — when it attaches and fires, it covers the io_uring + sendfile gaps cgroup cannot see; when it attaches and stays silent, `probeLSMSilent` downgrades the digest label from `defend+lsm` to `defend+cgroup` without disturbing the already-confirmed cgroup defense.

The reorder is semantics-preserving for the happy path (both hooks attach and fire) — the digest is unchanged. It is strictly stronger for the LSM-silent failure mode that motivated the previous fix (#225's downgrade label) — that fix made the *digest* honest about LSM not firing, but the underlying attach-window race remained.

## Test plan

- [ ] `go test ./internal/agent/... -count=1` — unit (Linux, requires `bash scripts/build-agent-linux.sh` to generate BPF stubs first)
- [ ] `sudo go test -tags=integration ./internal/agent/... -count=1` — integration with BPF load (Linux + root)
- [ ] `bash scripts/check-gofmt.sh`
- [ ] `staticcheck ./internal/agent/...`
- [ ] CI sweep: gofmt, encoding, vet, staticcheck, unit, unit-arm64, **integration**, action_bundle, detect-mode, **defend-mode**
- [ ] Defend-mode integration on `coldstep-kernel-matrix.yml` (5.15 / 6.1 / 6.6 / 6.8) — primary signal that the reorder didn't regress any kernel version
