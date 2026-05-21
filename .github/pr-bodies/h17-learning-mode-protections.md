## Summary

Implements **H17** (learning-mode poisoning protections) for the v0.4.0 hardening roadmap. The detect-mode JSONL → report-model → allowlist pipeline now carries explicit per-domain risk metadata so reviewers can spot the two shapes that most often slip a compromise into `allow:`:

- **DGA-shaped destinations** — leftmost DNS label ≥ 12 chars at Shannon entropy ≥ 3.5 bits/char, or 16+ chars of lowercase hex (UUID / hash style).
- **Single-observation destinations** — domains seen exactly once across the entire JSONL stream, which is the classic fingerprint of a briefly-poisoned learning run.

The existing hard gates (`--min-observation-hours`, `diff --fail-on-new-domain`) stay where they are. H17 adds the **reviewer-facing** surface around them: a `risk_hint` on every flagged entry, observation metadata for sorting / triage, and an `assert-integrity` warning block in the GitHub Actions UI.

## What changed

- **`internal/report/model/report.go`** — `SuspiciousDomain` grows three H17 fields:
  - `ObservationCount int` (`json:"observation_count"`) — connection-event count for the domain, mirroring the existing `Occurrences`. New canonical name for downstream consumers; the legacy `occurrences` field stays on the wire for backward compatibility.
  - `FirstSeenTS time.Time` (`json:"first_seen_ts"`) — earliest event timestamp for the domain. Set from the JSONL `ts` field; lets reviewers sort by recency.
  - `RiskHint string` (`json:"risk_hint,omitempty"`) — one of `suspicious-dga`, `single-observation`, or empty. DGA wins when both fire (e.g. a once-seen DGA host).

- **`internal/report/model/suspicious.go`** —
  - New exported `HasHighEntropyLabel(domain string) bool`. Returns true when the leftmost label is `[0-9a-f]{16,}` OR (length ≥ 12 AND Shannon entropy ≥ 3.5 bits/char). IP literals and empty input return false.
  - New `RiskHintSuspiciousDGA` / `RiskHintSingleObservation` consts mirror the wire values.
  - `BuildSuspiciousDomains` now tracks `firstSeen` per domain and populates `ObservationCount` / `FirstSeenTS` / `RiskHint` on each emitted row. The existing `high_entropy` reason keeps its looser 8-char floor so borderline entries still surface; the stricter 12-char `RiskHint` floor only fires the headline `suspicious-dga` tag.

- **`internal/report/model/suspicious_test.go`** — adds `TestHasHighEntropyLabel` (known-good `github.com`, `api.example.com`, `cdn3.example.com`, …; known-bad `a3b8c1d9e2f4a1b2.cdn.example.com`, `1a2b3c4d5e6f7890abcd.evil.io`, `deadbeefcafebabe.example.com`; borderline 11-char label must NOT fire) and `TestBuildSuspiciousDomainsSetsRiskHintAndObservationFields` (DGA host gets `risk_hint=suspicious-dga` with the right observation count; rare host gets `risk_hint=single-observation`).

- **`cmd/coldstep-report/build_model.go`** — `--min-observation-hours` now emits the H17-spec stderr line `coldstep-report: observation window is X minutes; --min-observation-hours requires Y hours (H17)` alongside the existing `::warning` annotation. Architecture is unchanged (build-model writes the model with `short_observation_window=true`; the hard fail still lives in `assert-integrity` so the model JSON remains inspectable on failure).

- **`cmd/coldstep-report/assert_integrity.go`** — new `reportLearningModeReviewerHints` helper emits a warn-only `::warning title=Coldstep learning-mode reviewer hints (H17)::N DGA-shaped / M single-observation destination(s)` annotation followed by one `::warning::DGA-shaped destination: …` / `::warning::Single-observation destination: …` line per flagged domain. Integrity verdict is **not** changed — these are reviewer hints, not a gate. Hard fails remain `short_observation_window`, BPF tamper, and the existing required-types / canary checks.

- **`cmd/coldstep-report/learning_poisoning_test.go`** — `TestAssertIntegrityEmitsLearningModeReviewerHints` captures stdout and asserts the H17 banner plus both per-domain rows render when the model carries a DGA + single-observation entry under a `verdict=pass` integrity result.

- **`QUICK_START.md`** — new "Building a safe allowlist (H17 learning-mode poisoning protections)" subsection under the existing promotion workflow. Documents the `risk_hint` taxonomy (`suspicious-dga`, `single-observation`), how `assert-integrity` surfaces them as warn-only annotations, and the recommended bar (≥ 24h window, baseline diff with `--fail-on-new-domain`, manual review of every `risk_hint` entry).

## Constraints honored

- No new BPF programs or maps — pure Go + report-model surface.
- No `enforce` references introduced.
- Legacy `occurrences` field preserved on the wire alongside the new `observation_count`; existing JSONL consumers keep working.
- `assert-integrity` exit-code semantics unchanged for clean / canary-missing / required-type-missing inputs; H17 hints add stdout lines only.
- Generated BPF artifacts (`bpf/vmlinux.h`, `internal/bpf/**/*_bpfel.go`, `*_bpfeb.go`) and local-only trees (`plans/`, `docs/`, `design/`, `knowledge/`, `AGENTS.md`) untouched.

## Validation

- `gofmt -l` — pass (touched files).
- `bash scripts/check-encoding.sh` — pass.
- `go vet ./internal/report/... ./cmd/coldstep-report/...` — pass.
- `go test ./internal/report/... ./cmd/coldstep-report/... -count=1` — pass (includes the three new H17 tests).
- Linux-only BPF compile + verifier + integration are validated by CI's `coldstep-ci-runner.yml` (`unit`, `unit-arm64`, `integration`, `detect-mode`, `defend-mode`).

## Follow-ups (out of scope)

- A `--fail-on-risk-hint` flag for `assert-integrity` would let teams that want allowlist-promotion CI to fail when any `risk_hint` entry is present. Today the workflow uses `--fail-on-new-domain` for that role; deferred until a real consumer asks.
- `website/` quick-start mirror copy will be touched in the post-tag website-bump PR per `RELEASE_PROCESS.md`; this PR keeps the repo-side `QUICK_START.md` consistent.
