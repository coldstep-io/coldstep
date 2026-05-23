## Summary

- Add `model.MarshalCanonicalValue(any)` in `internal/report/model/canon.go` — the shape-agnostic form of the existing `MarshalCanonical(*Report)`, applying the same encoder settings (2-space indent, `SetEscapeHTML(false)`, no trailing newline).
- Route `writeModelMap` in `cmd/coldstep-report/model_json.go` through `MarshalCanonicalValue`, replacing the plain `json.Marshal` path used by `rdns-enrich` and `otx-enrich`.
- Add `TestWriteModelMap_CanonicalRoundTrip` and `TestWriteModelMap_RoundTripReadsBack` in a new `cmd/coldstep-report/model_json_test.go`: verify enrichment writes byte-match the canonical encoder, that PTR/domain strings with `<` / `>` / `&` survive without HTML escaping, and that the file roundtrips through `readModelMap`.

## Why

Bug #5 from the post-v0.4.0 bug hunt. `build-model` writes the report through `MarshalCanonical` (2-space indent, no HTML escaping, no trailing newline). The enrichment subcommands then re-read and re-write the same file through `writeModelMap`, which used plain `json.Marshal` — HTML escaping on, compact, no newline. After `rdns-enrich` or `otx-enrich` ran, the on-disk model diverged from the canonical form: downstream attestation hashes no longer matched the post-build-model snapshot, and PTR records or suspicious domain names containing `<` / `>` / `&` were silently rewritten to their `<` / `>` / `&` escapes.

## Test plan

- [ ] `go test ./cmd/coldstep-report/... ./internal/report/... -count=1` — including the new `TestWriteModelMap_*` cases
- [ ] `bash scripts/check-gofmt.sh`
- [ ] CI sweep on Linux (gofmt, encoding, vet, staticcheck, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode)
