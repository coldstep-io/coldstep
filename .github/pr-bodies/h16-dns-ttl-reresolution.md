## Summary

Implements **H16** (DNS allowlist trust hardening — live re-resolution) from the v0.4.0 hardening roadmap, completing the trust surface that **H4** (v0.2.9, startup logging of unresolved domains) and **H9** (v0.3.0, `AllowlistCompileTime` + ⚠️ staleness warning) began. A background goroutine now periodically re-resolves the startup allowlist and emits a `dns_drift` JSONL event when IPv4 addresses change relative to the snapshot programmed into the BPF map.

**Warning-only by design.** The live BPF enforce policy is intentionally **not** updated mid-run. Adding freshly-resolved CDN tenant IPs to the allowlist between the lookup and the egress attempt is a TOCTOU risk (per the H16 risk note in the hardening plan); the snapshot remains the source of truth for enforcement, and the goroutine's job is purely advisory — so operators of long-running jobs see CDN tenant or LB pool rotation as a digest warning instead of a silent gap.

## What changed

- **`internal/policy/allowlist.go`** — new `DriftReport` struct (`AddedIPs`, `RemovedIPs`, `CheckedAt`); pure `Diff(original, updated CompileResult) DriftReport` that returns sorted IPv4 set differences (IPv6 deferred to H14); `ReResolve(ctx, original, resolver, maxAttempts)` re-runs `CompileDomainAllowlist` against the original domain list, sharing the existing concurrency/timeout limits (`coldstepDomainLookupConcurrencyLimit=32`, `coldstepDomainLookupAttemptTimeout=25s`).

- **`internal/telemetry/event.go`** — new `DNSDriftEvent` (json type `"dns_drift"`) and `EventTypeDNSDrift` constant. Fields: `ts`, `added_ips`, `removed_ips`, `domain_count`, `checked_at`. Signed in the same canonical-marshal path as every other event type.

- **`internal/agent/dns_drift.go`** (new, portable) — `runDNSDriftWatch(ctx, original, resolver, maxAttempts, interval, onDrift, onClean)` is the agent's H16 watchdog: ticks every `allowlistReCheckInterval` (5 minutes, mirroring the H9 staleness threshold), calls `policy.ReResolve` + `policy.Diff`, fires `onDrift` on non-empty drift and `onClean` otherwise, and returns promptly on `ctx.Done()`. Dependencies are injected so the loop is unit-testable from Windows without touching BPF or runtime DNS.

- **`internal/agent/agent_linux.go`** — when `defendCompiled.Domains` is non-empty, launch the watch goroutine inside `Run`'s wait group. `onDrift` bumps `runStats.dnsDriftN` and appends a `DNSDriftEvent` JSONL line under the existing `jsonlMu`; `onClean` logs at debug level.

- **`internal/agent/agent_linux_state.go`** — add `runStats.dnsDriftN` plus `addDNSDrift()` / `dnsDriftTotal()` accessors (lock-protected like every other run counter).

- **`internal/agent/agent_linux_digest.go`** — surface `stats.dnsDriftTotal()` into `DigestInput.DNSDriftCount`.

- **`internal/report/digest_types.go`** — add `DNSDriftCount int` to `DigestInput`.

- **`internal/report/digest.go`** — `writeAllowlistTrust` now emits a fourth box when `DNSDriftCount > 0`: `> ⚠️ **DNS drift detected** — allowlist IPs changed N time(s) during this run. Enforcement was not updated mid-job.` The advisory composes with the existing unresolved / wildcard / staleness / entry-count rows.

- **`SECURITY.md`** — extend the "Coverage Boundaries" → "Operational implications" bullets to call out the new advisory-only re-resolution behavior: the snapshot is fixed at startup, drift surfaces as JSONL + digest, and long-running jobs that need fresh CDN coverage must restart the agent (or pin literal IPs / CIDRs).

- **`internal/policy/dns_drift_test.go`** (new) — `Diff` cases (no-change, added-only, removed-only, both, deterministic sort), and a `ReResolve` smoke test that flips the resolver between calls.

- **`internal/agent/dns_drift_test.go`** (new) — exercises `runDNSDriftWatch` end-to-end: drift emission with added IPs, drift with removed IPs, table-driven add/remove/clean ticks, immediate-return on cancelled context, immediate-return on empty domain list, and clean-callback firing when DNS is stable.

## Constraints honored

- **No mid-job allowlist expansion.** Per the H16 risk note in the hardening plan, drift never feeds back into the BPF `allowed_ipv4` LPM trie — only JSONL + digest. Comments on `policy.DriftReport`, `runDNSDriftWatch`, and `DNSDriftEvent` repeat this so future readers don't try to "fix" the absence of a map update.
- **No new BPF programs or maps** — pure Go + digest + telemetry surface.
- **Concurrency budget** is the original compile's (`coldstepDomainLookupConcurrencyLimit=32`, `coldstepDomainLookupAttemptTimeout=25s`); the periodic check uses `maxAttempts=1` so transient resolver flakes recover on the next tick rather than producing retry storms against the runner's stub resolver.
- **Cross-platform stub stays intact** — `dns_drift.go` is portable and only depends on `context`, `time`, `log/slog`, and `internal/policy`; the test file is portable too so non-Linux contributors can iterate without docker.
- **No `enforce` references introduced** anywhere in the new surface (the rejection in `internal/config` for legacy `CI_GUARD_MODE=enforce` is unchanged).

## Validation

- `go vet ./internal/policy/... ./internal/report/... ./internal/telemetry/...` — pass.
- `go test ./internal/policy/... ./internal/agent/... -count=1` (Windows, non-BPF packages) — pass.
- `go test ./internal/report/... ./internal/telemetry/... -count=1` — pass.
- BPF compile + verifier load + Linux unit/integration are validated by CI's `coldstep-ci-runner.yml` (`unit`, `unit-arm64`, `integration`, `detect-mode`, `defend-mode`).

## Follow-ups (out of scope)

- **H14 (IPv6 allowlist drift)** — `Diff` currently compares IPv4 sets only; extending to `AllowedIPv6` is a one-line follow-up once the IPv6 enforcement path graduates from observe-only.
- **Drift-aware suggest-allow output** — the `coldstep-report` post-run pipeline could surface drift in `suggested-allow` so operators see "CDN flipped during run X, here's the union" without re-running. Tracking separately.
- **Operator-tunable interval** — `allowlistReCheckInterval` is a 5-minute const today. If real runs show heavy CDN churn making the digest noisy, expose it via env (e.g. `COLDSTEP_DNS_RECHECK_SECONDS`) in a later PR rather than wiring a new action input now.
