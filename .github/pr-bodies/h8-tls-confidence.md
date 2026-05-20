## Summary

Implements **H8** from the v0.3.0 hardening roadmap (P1-4): consolidate the TLS SNI confidence scoring that already exists internally into the public telemetry surface, and wire it through to the headline verdict.

Most of the H8 plumbing already landed during P4 (PR #183) and the H1/H2 work: the `telemetry.TLSConfidence` enum, the `TLSEvent.Confidence` field, the `runStats.tlsConfidence*N` aggregators, the `DigestInput.TLSConfidence*` counters, the `formatTLSConfidenceCell` KPI row, and the per-row Confidence column in the recent-TLS table are all in place. The gaps this PR closes are the three remaining items the roadmap calls out explicitly:

- the public `Summary` JSON now carries the four per-tier counters,
- the headline ✅ verdict downgrades to ⚠️ when at least one TLS row landed in the `partial` or `unknown` bucket on this run,
- both behaviors are pinned by regression tests.

## What changed

- **`internal/telemetry/telemetry.go`** — add `Summary.TLSConfidenceFull / Partial / Inferred / Unknown` (`uint64`, all `omitempty`). They surface in `.coldstep-telemetry.json` so downstream consumers (`coldstep-report`, dashboards) can read the confidence breakdown without reparsing JSONL. Field doc spells out the tier semantics (`full` / `partial` / `inferred` / `unknown`) and points at `TLSConfidenceUnknownKTLS` in the digest input for the P4 KTLS-attributed subset.

- **`internal/agent/agent_linux_state.go`** — populate the new `Summary` counters from the existing `tlsConfidence*N` integers in `snapshotSummary`. No new locking or aggregation paths: the values were already incremented inside `addTLS` (held under `runStats.mu`) and read by the digest builder via `tlsConfidenceCounts()`.

- **`internal/report/digest.go`** — add a `tlsConfidenceGap` term to the `review` set in `verdictEmoji`. The badge downgrades to ⚠️ when `TLSConfidencePartial + TLSConfidenceUnknown > 0` **and** `tlsKPIVisible(in) && TLSTotal > 0` — gated so a TLS-free run cannot warn on a stale counter. Lines up with the existing H1 partial-coverage rules (ringbuf drops, multi-iovec, runner-has-IPv6) so the verdict consistently surfaces "the digest may be incomplete."

- **`internal/report/digest_test.go`** — `TestBuildDetectMarkdown_TLSConfidencePartialDowngradesVerdict` covers the three combinations: partial>0 triggers ⚠️ (with the KPI row visible), unknown>0 triggers ⚠️ alone, and full-only stays ✅. Sibling to the existing IPv6 and ringbuf badge regressions.

- **`internal/telemetry/telemetry_test.go`** — `TestWriteSummaryIncludesTLSConfidenceCounters` asserts the new fields round-trip through `WriteSummary` with the expected JSON keys (`tls_confidence_full`, `tls_confidence_partial`, `tls_confidence_unknown`), and that the zero-valued `tls_confidence_inferred` is dropped by `omitempty`.

## Why no BPF wire-struct change

The roadmap's H8 text mentions a `confidence` byte on the `tls_sniff_event` ringbuf struct. The current architecture ships the raw ClientHello payload up to userspace and parses the SNI in Go (`telemetry.ScoreTLSConfidence`), so there is no BPF-side parsing that would set such a byte — the userspace SNI parser already produces a strictly stronger result than a BPF prefix check would. Adding a byte that BPF would never write would be dead surface. The `ConfidenceReason="ktls"` override path from P4 stays as-is; H8 surfaces the resulting tier counters publicly without changing how individual rows are scored.

## Constraints honored

- No new BPF programs, maps, or wire-format changes — `tls_sniff_event` keeps its 312-byte layout. `_Static_assert` in `bpf/trace_connect_obs.h` was untouched.
- `omitempty` on all four `Summary` fields keeps the JSON footprint identical on TLS-free runs.
- No new event types and no schema bump — `telemetry.SchemaVersion` is unchanged.
- No `enforce` references introduced.

## Validation

- `bash scripts/check-gofmt.sh` — pass.
- `bash scripts/check-encoding.sh` — pass.
- `go test ./internal/telemetry/... ./internal/report/... ./internal/agent/... -count=1` — pass.
- BPF compile + verifier load and the cross-architecture matrix are validated by `coldstep-ci-runner.yml` (`unit`, `unit-arm64`, `integration`, `detect-mode`, `defend-mode`).

## Follow-ups (out of scope)

- **Inferred tier producer** — `TLSConfidenceInferred` ships zero today. A future enricher that correlates TCP egress on port 443 against the DNS cache could populate it (would land alongside H10 per-domain observation counts). The field is reserved so consumers can rely on the shape being stable.
- **Report tooling KPI propagation** — `coldstep-report render-summary` could grow a "TLS confidence" headline cell that reads the new `Summary` fields directly. Out of scope for H8; the digest path already surfaces the same numbers.
