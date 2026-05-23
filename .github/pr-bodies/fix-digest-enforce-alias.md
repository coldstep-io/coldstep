## Summary

- Make `isBlockingDigestMode` (`internal/report/digest_aggregation.go`) accept `enforce` / `enforce+<backend>` as a case-insensitive alias for `defend` / `defend+<backend>`. Every mode-string comparison in `internal/report/` already routes through this predicate, so the alias propagates to the defend triage row, allowlist-trust section, and IPv6-defend logic without touching the writers.
- Add `TestBuildDetectMarkdown_LegacyEnforceModeTreatedAsDefend` (end-to-end: feeds `DigestInput{DefendMode:"enforce"}` etc. through `BuildDetectMarkdown` and asserts the defend triage row + deny suffix appear) and `TestIsBlockingDigestMode_LegacyEnforceAlias` (direct table-driven check on the predicate).
- Update the `CLAUDE.md` paragraph that previously claimed `internal/report/digest.go` parses legacy enforce strings to point at the actual location of the alias (`isBlockingDigestMode` in `digest_aggregation.go`) and describe what it covers.

## Why

Bug #6 from the post-v0.4.0 bug hunt. CLAUDE.md claimed `digest.go` still parsed `mode:"enforce"` for replay, but `grep enforce` under `internal/report` returned zero hits — the rename to `defend` had moved through the writer side without leaving a back-compat shim. Older JSONL artifacts replayed via `coldstep-report` therefore rendered as detect mode: the defend triage row, allowlist-trust section, and IPv6-defend logic all disappeared, even though the underlying run was a blocking one. Making `isBlockingDigestMode` accept the legacy spelling is the smallest fix that restores the documented behaviour.

## Test plan

- [ ] `go test ./internal/report/... ./cmd/coldstep-report/... ./internal/agent/... -count=1` — including the new `TestBuildDetectMarkdown_LegacyEnforceModeTreatedAsDefend` and `TestIsBlockingDigestMode_LegacyEnforceAlias` cases
- [ ] `bash scripts/check-gofmt.sh`
- [ ] CI sweep on Linux (gofmt, encoding, vet, staticcheck, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode)
