## Summary

- Replace the fixed 400ms sleep after `SIGTERM` in `runStop` (`cmd/coldstep-action/main.go`) with a `pidAlive` poll loop: tick every 100ms, time out after 10s.
- Add a `waitForAgentExit(pid, timeout, tick) bool` helper that logs the exit verdict — `"agent pid=N exited cleanly after Tms"` vs. `"agent pid=N still alive after 10s; proceeding with digest read anyway"` — so post-step output distinguishes a clean drain from a hung agent.
- Add three unit tests (`TestWaitForAgentExit_*`) covering the fast-exit, timeout, and bad-input branches. The timeout test lives in a new `main_linux_test.go` because `Signal(0)` against the current PID is portable liveness only on Linux.

## Why

Bug #8 from the post-v0.4.0 bug hunt. Symptom: on defend-mode runs the agent's shutdown drain (BPF ringbuf flush + digest write) regularly exceeded the hard-coded 400ms window, and `runStop` would race ahead to read `.coldstep-detect.md` while the file was still being written — surfacing truncated digests in the Job Summary and PR comment. The 10s upper bound matches the existing defend-mode drain budget (the integration tests' `10*time.Second` deadlines and the LSM ringbuf reader's shutdown window), so we wait long enough on slow runners without hanging forever on a stuck agent.

## Test plan

- [ ] `go test ./cmd/coldstep-action/... -count=1` — including the new `TestWaitForAgentExit_*` cases
- [ ] `bash scripts/check-gofmt.sh`
- [ ] CI sweep on Linux (gofmt, encoding, vet, staticcheck, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode)
