## Summary

- **Bug #9 (pidFile path mismatch)** — `cmd/coldstep-action/main.go` wrote/read `.coldstep.pid` under `$GITHUB_ACTION_PATH`; `src/start.ts` and `src/stop.ts` use `$GITHUB_WORKSPACE`. Mixed-entrypoint use (Go start → TS stop, or vice versa) silently no-ops the stop SIGTERM — agent runs until SIGKILL on runner teardown, no digest flush, no integrity marker. Standardize on `$GITHUB_WORKSPACE` in Go and document the contract in both languages.
- **Bug #15 (sudo PID vs agent PID)** — `cmd.Process.Pid` (and `child.pid` in TS) is the sudo process, not the agent. On most PAM stacks sudo forks before exec'ing the agent: `pidAlive(sudoPid)` returns true while the agent has already crashed, and `SIGTERM` to sudo does not propagate to the agent. Add `findAgentPID` (Go) / `findAgentPidViaProc` (TS) that BFS-walks `/proc/<pid>/task/<pid>/children` looking for a descendant whose `/proc/<pid>/comm` is `coldstep`. Fall back to sudoPid on no-match so we never end up with a zero PID. Store the discovered PID in `.coldstep.pid`, use it for `waitForReady`, `stopAgent`, and the error-path SIGTERM.
- Add three Linux-only unit tests for the new helper: zero-PID guard, fallback behaviour when no coldstep descendant exists, and the happy path of locating a known child by its comm.
- Rebuild `dist/{pre,main,post}/index.js` from `src/` (CI's `dist/ matches src/` gate enforces this).

## Why

P2 bugs from the post-v0.4.0 hunt. The two are bundled because both are silent failures in the same composite-action lifecycle path — the pidfile contract is meaningless if the PID inside it is wrong, and vice versa. Symptoms in the field:

- **#9**: A workflow that ran TS-only `pre` (legacy entrypoint) and Go `phase: stop` (in-repo CI) would print `pid file missing; agent may not have started` from stop.ts despite the agent being alive. The agent was then SIGKILLed on runner teardown — `.coldstep-detect.md` and `.coldstep-events.jsonl` were truncated and the integrity marker was absent.
- **#15**: On defend-mode runs with a transient BPF map-load failure, the agent process exited but sudo remained alive in `wait4`. `pidAlive(sudoPid)` returned `true`, so `waitForReady` never produced `child_exit` — it ran to the full 1500s timeout. The `child_exit` heuristic that fix #8 introduced was effectively dead code on every PAM stack that forks.

## Test plan

- [ ] `go test ./cmd/coldstep-action/... -count=1` — including new `TestFindAgentPID_*` cases (Linux)
- [ ] `bash scripts/check-gofmt.sh`
- [ ] `staticcheck ./cmd/coldstep-action/...`
- [ ] `npm run typecheck && npm run build` — verify the `dist/ matches src/` CI gate passes
- [ ] CI sweep: gofmt, encoding, vet, staticcheck, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode, dist-up-to-date
