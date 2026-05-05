## Summary

Expands unit tests across the Go surface area Linux CI cares about: composite action helpers (including `postPRComment` via stub transport), `coldstep` CLI `runCLI` with injectable `agentMain`, `atomicwrite` edge cases, cgroup attach-path helpers on Linux and non-Linux, `safepath` with `RUNNER_TEMP`, and telemetry `NewSigner` / nil signer behavior.

Also extends `.gitignore` for `coverage*.out` profiles.

## Verification

- `go test ./... -short` (local; Windows agent tests may differ from Linux CI)
- `origin/dev` includes signed commits; merge via this PR to `main`.

## Risk / notes

Does not attempt repo-wide 95% coverage; `internal/agent` and BPF loader packages remain integration-heavy.
