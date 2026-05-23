## Summary

- Fix `model.BuildDiff` so an empty (length-0) baseline is treated as "no comparison data," not "everything in current is brand-new traffic."
- The previous guard checked `baseline == nil`. `model.LoadEvents` returns a non-nil empty slice (`make([]Event, 0, 64)`) when the baseline JSONL file exists but is empty or contains no parseable events — that path slipped past the nil-check and flagged every current egress fingerprint as `traffic_new`.
- Pin the behaviour with `TestDiffWithEmptyNonNilBaselineReportsUnavailable`: a non-nil empty `[]Event{}` baseline must return `status="unavailable"`, `reason="no_baseline_provided"`, and zero `traffic_new` / `traffic_gone` / `traffic_changed` entries.

## Why

Bug #1 from the post-v0.4.0 bug hunt. Symptom in the wild: a workflow with a malformed or empty baseline JSONL produces a diff section that screams "100% of egress is new" even though the runs are identical, which is exactly the opposite of what an unavailable baseline should mean — and would noisily defeat any downstream diff-based gating.

## Test plan

- [ ] `go test ./internal/report/model/... -count=1` — includes the new regression test alongside the existing `TestDiffWithoutBaselineReportsUnavailable` and `TestDiffWithBaselineIncludesNewGoneChangedAndIndicators`
- [ ] `bash scripts/check-gofmt.sh`
- [ ] CI sweep on Linux (gofmt, encoding, vet, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode)
