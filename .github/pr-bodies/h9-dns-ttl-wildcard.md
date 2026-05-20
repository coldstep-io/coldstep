## Summary

Implements **H9** (DNS TTL staleness warning + wildcard CDN risk scoring) and bundles **H12** (allowlist startup entry count telemetry) from the v0.3.0 hardening roadmap. The digest now tells operators when the in-memory DNS-resolved allowlist is older than the typical DNS TTL window, when a high-risk multi-tenant CDN wildcard is in the allowlist, and how many `/32 + CIDR` entries are actually programmed into the BPF `allowed_ipv4` LPM trie at startup (which is fixed until the agent restarts).

The wildcard-risk scoring and the underlying digest "Allowlist trust model" section already landed in earlier P1-1 work — this PR completes the H9 surface (TTL-staleness warning, spec-prescribed wording, per-domain `slog.Warn`) and adds the missing H12 telemetry field and digest note.

## What changed

- **`internal/policy/allowlist.go`** — add `CompileResult.CompileTimestamp time.Time`, stamped with `time.Now()` at the end of `CompileDomainAllowlist`. Emit `slog.Warn("allowlist: wildcard CDN domain may match unintended hosts", "domain", d)` for every entry the H9 CDN risk list matched (`*.githubusercontent.com`, `*.s3.amazonaws.com`, `*.blob.core.windows.net`, `*.azureedge.net`, `*.cloudfront.net` — plus the pre-existing `*.r2.dev` / `*.pages.dev`). The per-domain warn moved out of `internal/agent/agent_linux.go` and into the policy layer so non-Linux replay paths surface the same signal.

- **`internal/telemetry/event.go`** — new `MetaEvent.AllowlistEntryCount int` (json `allowlist_entry_count,omitempty`). Distinct from `AllowlistIPCount`, which counts domain-resolved IPv4s only — `AllowlistEntryCount` mirrors the post-merge total written into the BPF LPM trie at startup, so the JSONL meta records `len(domain-resolved IPv4) + len(literal --allowed-ips /32 + CIDR entries)`.

- **`internal/agent/agent_linux.go`** — pass `defendCompiled.CompileTimestamp` into `stats.setAllowlistCompileSnapshot` instead of a separate `time.Now()` capture; populate `meta.AllowlistEntryCount` from `defendState.snapshot().allowlistSize` (the actual programmed entry count, captured after `loadDefendMaps` returns).

- **`internal/agent/agent_linux_digest.go`** — wire `AllowlistCompileTime` (instead of the derived `AllowlistAgeMinutes`) and `AllowlistEntryCount` into `DigestInput`. The digest renderer is now the single source of truth for "is the compile stale?", so test/replay paths can compare to a fixed clock.

- **`internal/report/digest_types.go`** — replace `AllowlistAgeMinutes float64` with `AllowlistCompileTime time.Time` (per H9 spec) and add `AllowlistEntryCount int` (per H12 spec). The digest renderer computes `time.Since(...) > 5*time.Minute` itself.

- **`internal/report/digest.go`** — update `writeAllowlistTrust`:
  - New ⚠️ "DNS allowlist may be stale — compiled N minutes ago. DNS TTLs may have expired." box when `time.Since(AllowlistCompileTime) > 5m` (was a softer ℹ️ note tied to `AllowlistAgeMinutes`).
  - Wildcard warning rewritten to the spec-prescribed batched form: `> ⚠️ **High-risk wildcard domains in allowlist** — \`*.s3.amazonaws.com\`, \`*.cloudfront.net\` — may match unintended hosts.`
  - New ℹ️ "Allowlist: N IPv4 entries loaded at startup (fixed until restart)." note in defend mode when `AllowlistEntryCount > 0` (H12).

- **`internal/policy/allowlist_test.go`** — `TestCompileDomainAllowlist_FlagsAllH9CDNWildcards` walks the five CDN suffixes named in the H9 spec and asserts each is flagged; `TestCompileDomainAllowlist_RecordsCompileTimestamp` asserts the new field lands inside the call window.

- **`internal/report/digest_test.go`** — `TestBuildDetectMarkdown_AllowlistTrust_StaleWarning` covers the 6-minutes-ago / 2-minutes-ago / zero-time cases; `TestBuildDetectMarkdown_AllowlistTrust_EntryCountNote` covers the H12 defend-mode rendering and detect-mode suppression. The existing wildcard test was updated to the new "may match unintended hosts" wording.

## Constraints honored

- No new BPF programs or maps — pure Go + digest.
- No `enforce` references introduced; the staleness/wildcard surfaces follow the same `isBlockingDigestMode(...)` gate as the rest of the allowlist trust block.
- `AllowlistEntryCount` is a parallel field to the existing `AllowlistIPCount`, not a rename — the older field stays as-is so any downstream JSONL consumers keep working.
- The wildcard suffix list (`internal/policy/allowlist.go:highRiskWildcardSuffixes`) is unchanged; it already contained the H9-named CDNs.

## Validation

- `bash scripts/check-gofmt.sh` — pass.
- `bash scripts/check-encoding.sh` — pass.
- `go test ./internal/policy/... ./internal/report/... ./internal/telemetry/... ./internal/agent/... -count=1` (Windows, non-BPF packages) — pass.
- `GOOS=linux go test -c -o /tmp/policy.test ./internal/policy/` / `... ./internal/report/` cross-compile — pass.
- BPF compile + verifier load + Linux unit/integration are validated by CI's `coldstep-ci-runner.yml` (`unit`, `unit-arm64`, `integration`, `detect-mode`, `defend-mode`).

## Follow-ups (out of scope)

- **H16 (DNS allowlist trust hardening — live re-resolution)** — the H9 warning surfaces drift; a future PR can wire a background refresh goroutine if the warning fires often in real runs. The "warning-only" leg of H16 is now covered.
- **Documentation drift** — `website/` allowlist copy will be touched in the post-tag website-bump PR per `RELEASE_PROCESS.md`; this PR keeps the repo-side surface consistent.
