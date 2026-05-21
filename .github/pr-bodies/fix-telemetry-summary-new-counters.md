## Summary

- Surface three counter groups in `.coldstep-telemetry.json` that already feed the shutdown digest but were missing from the on-disk summary file
- `tcp_state_total` / `_confirmed` / `_refused` / `_ringbuf_reserve_failures` (kernel-confirmed TCP handshake transitions — P3-2b)
- `quic_observed` (H19 — UDP/443 PossibleQUIC heuristic per-run total)
- `dns_drift_observations` (H16 — periodic allowlist re-resolution drift count)
- Pin the new fields with a `telemetry_test.go` round-trip, including the `omitempty` zero-default behaviour so existing detect runs do not gain noise fields

## Why

Discovered during a post-H14–H20 bug-hunt pass. Downstream consumers of `.coldstep-telemetry.json` (report tooling, dashboards) had no machine-readable twin of the digest's TCP-handshake / QUIC heuristic / DNS-drift cells; recovering the same totals required reparsing the JSONL stream. The runStats fields already existed and the digest pipeline already used them — this PR just plumbs them through `snapshotSummary` so the summary file stays consistent with the digest.

## Test plan

- [ ] `go test ./internal/telemetry/... -count=1` — including the new `TestWriteSummaryIncludesNewCounters`
- [ ] `go test ./internal/report/... -count=1` (no behaviour change, but exercises the same digest input fields)
- [ ] CI 22-check sweep on Linux (gofmt, encoding, vet, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode, …)
