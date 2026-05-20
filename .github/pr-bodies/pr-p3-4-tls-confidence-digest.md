## Summary

Additive follow-up to **P1-4** (#163), which introduced `telemetry.TLSConfidence`, `ScoreTLSConfidence`, and the `tls SNI confidence` KPI row. P1-4 surfaced confidence as an aggregate count; this PR makes the per-event reason code **visible per row** and **defined in-place** so operators can attribute KPI numbers to specific destinations and look up what each tier means without leaving the digest.

## What changed

- **Per-row Confidence column** in the recent TLS table (`internal/report/digest.go::writeTLSSection`) — every SNI row now shows its `full` / `partial` / `inferred` / `unknown` reason code next to the policy verdict.
- **Tier-meaning legend** under the existing `tls KPI` bullet in the Technical-details fold — defines all four codes (`full`, `partial`, `inferred`, `unknown`) with their capture semantics, including a reference to the `TLSSNIMaxLen=255` boundary that drives the `full → partial` transition.
- **`TLSDigestRow.Confidence`** field plumbed through the agent's TLS ring reader so each row carries the already-scored confidence into the digest. The row defaults to `unknown` when zero-valued, so the column is never blank.
- **Gating consistent with P1-4**: the legend is only emitted when `TLSTotal > 0` (matching the existing KPI-row gate), so a TLS-gated run with no events stays terse.

## Why this is small

P1-4 already implemented the scoring, the JSONL `Confidence` field, the per-tier counters, and the KPI row. Re-defining those would conflict and add no value. This PR is strictly additive: 4 files, no new types, no new fields on `TLSEvent`, no behavioral change to scoring.

## Test plan

- [x] `go test ./internal/telemetry/... ./internal/report/... -count=1` — passing locally.
- [x] New tests in `digest_test.go`:
  - `TestBuildDetectMarkdown_TLSConfidencePerRowAndLegend` — co-existing tiers render in the Confidence column **and** the legend is emitted.
  - `TestBuildDetectMarkdown_TLSConfidenceEmptyRowDefault` — zero-value `Confidence` falls back to `unknown`.
- [x] `gofmt -l internal/` clean.
- [ ] `coldstep-ci-runner.yml` matrix on PR (gofmt, encoding, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode).
- [ ] Confirm Job Summary on the `detect-mode` workflow shows the new Confidence column + legend.
