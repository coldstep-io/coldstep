## Stub / placeholder elimination (pass 1)

Removes dishonest stubs and dead skip-guards surfaced by a full review of every
`t.Skip` / "not implemented" / silent-no-op in the tree. Most `t.Skip`s are
legitimate environment gates (no root/CAP_BPF, missing tool) and are left alone;
this PR fixes the ones that assert nothing or hide real regressions.

### Changes
- **Remove virustotal + passivedns stub backends** — both accepted API config
  (`COLDSTEP_VIRUSTOTAL_API_KEY` / `COLDSTEP_PASSIVEDNS_SERVER`) but returned
  `(nil, nil)` with no network call: a "configured but does nothing" lie. Dropped
  the backends, their loader registration, and the env reads. The real OTX
  backend, `NoOpEnricher` (for unconfigured slots), and the public reputation
  interface are unchanged.
- **defend loader: fail-closed on missing IPv6 enforcement** — `defend_cgroup_connect6`
  / `defend_cgroup_sendmsg6` / `allowed_ipv6` became enforcement primitives in
  H14 and are always present in the embedded spec, yet were loaded with
  `*IfPresent` (silently tolerate absence) — a silent IPv6 defend-bypass on a
  stale stub. Now required via `detachProgram`/`detachMap` like the IPv4 path.
  Observe-only counters and kernel-feature-gated LSM hooks (sendpage, io_uring,
  legitimately stripped per kernel) stay tolerant.
- **defend ABI test: hard-fail instead of skip** — the five `t.Skipf("defend
  stubs not regenerated yet …")` branches were dead defensive code (the package
  cannot compile without its generated bindings, and CI regenerates them), so a
  missing map/program skipped green instead of failing. Converted to `t.Fatalf`.
- **Convention** — CLAUDE.md: test skips gate on environment capability, never
  on unbuilt features; a `t.Skipf` on an "absent" generated artifact must be a
  hard fail.

### Follow-ups (tracked, deliberately not in this PR)
- Convert the stale `t.Skip("Hxx not merged")` red-team integration tests
  (H7 `tcp6`/`udp6`, H19 `possible_quic`, H8 `io_uring_send` — all merged) into
  real assertions. They need CI to validate and the runners are currently
  degraded; doing them blind risks more red.
- `internal/report/integrity/evaluator.go` `correlationScore := 100` placeholder
  feeds `BalancedScore`; replacing it touches the integrity-scoring CI gate and
  needs careful design + validation.

### Verification
`gofmt`, `go vet`, `staticcheck`, `go test ./...`, encoding scan — all green
locally. (`defend-mode` CI cancels at its 45-min timeout repo-wide, including on
main — non-blocking.)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
