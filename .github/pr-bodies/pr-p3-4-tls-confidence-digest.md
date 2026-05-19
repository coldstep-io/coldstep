## Summary

- Surfaces TLS SNI **confidence reason codes** (`full`/`partial`/`inferred`/`unknown`) in the detect-mode Markdown digest so operators can tell at a glance how reliable each ClientHello SNI extraction is. (P3-4)
- Adds the codes to JSONL `TLSEvent`s via a new `confidence` field and a new `ParseClientHelloSNIWithConfidence` helper that distinguishes a fully-captured ClientHello from one whose record extended past the BPF buffer.
- KPI table gains a `tls SNI confidence` line (e.g. `5 names · 3 full · 1 partial · 1 inferred`), the recent-TLS table gains a `Confidence` column, and the **Technical details** fold gains a legend describing each tier.

## What changed

| Layer | File | Change |
| :-- | :-- | :-- |
| Telemetry | `internal/telemetry/event.go` | New `TLSSNIConfidence` constants; added `confidence` JSON field to `TLSEvent`. |
| Telemetry | `internal/telemetry/tls_clienthello.go` | New `ParseClientHelloSNIWithConfidence` that returns `full` when the record/CH/extensions all fit, `partial` when truncation was reached. Legacy `ParseClientHelloSNI` kept as a thin wrapper. |
| Agent | `internal/agent/agent_linux_state.go` | Per-tier counters on `runStats` (+ `tlsConfidenceCounts()` accessor) and updated `addTLS(cl, confidence)` signature. |
| Agent | `internal/agent/agent_linux_ring_read.go` | Wires confidence from parser into row buffer, stats, and JSONL event. |
| Agent | `internal/agent/agent_linux_digest.go` | Threads counts into `DigestInput`. |
| Report | `internal/report/digest_types.go` | `TLSDigestRow.Confidence` + `DigestInput.TLSConfidence*` fields. |
| Report | `internal/report/digest_aggregation.go` | `tlsConfidenceBreakdown` helper that emits the `"N names · X full · …"` line, omitting zero-count tiers. |
| Report | `internal/report/digest.go` | KPI row, recent-TLS Confidence column, and tech-details legend describing all four tiers. |

## Confidence semantics

- `full` — complete ClientHello parsed in a single syscall buffer (no truncation reached).
- `partial` — SNI found inside a buffer that the TLS record extended beyond; the name may be truncated.
- `inferred` — SNI inferred from prior DNS / connect correlation (reserved; not currently emitted by the agent).
- `unknown` — TLS framing detected but no SNI could be extracted (reserved; today such rows are suppressed).

## Test plan

- [x] `go test ./internal/telemetry/... ./internal/report/... -count=1` (Windows host) — passing locally
- [ ] `coldstep-ci-runner.yml` matrix (gofmt, encoding, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode) on PR
- [ ] Confirm Job Summary on `detect-mode` shows the new `tls SNI confidence` row + legend
- [ ] Nightly (`coldstep-ci-nightly.yml`) once merged
