## Summary

- **Bug #10 (UTF-8 BOM drops first JSONL event)** — `internal/report/model/jsonl.go`. A leading `EF BB BF` on the first line of an event log (common when a Windows producer pre-pends the BOM) made `json.Unmarshal` fail silently, discarding the first event — typically `meta`. That skews `ObservationWindow` and can flip the integrity gate. Fix: strip the BOM with `strings.TrimPrefix(line, "\xef\xbb\xbf")` after `TrimSpace`. (BOM is U+FEFF, not classified as whitespace by Go's `unicode.IsSpace`, so the trim has to happen explicitly.)
- **Bug #11 (BuildDiff fingerprint conflates name vs IP)** — `internal/report/model/builders.go`. The fingerprint was per-event (`type»firstNonEmpty(fqdn, host, sni, dst)`). Two consecutive identical runs where one event hit a DNS cache miss would produce two fingerprints — `tcp»example.com` and `tcp»1.2.3.4` — and surface a spurious `traffic_gone` + `traffic_new` pair. Fix: build a single `dst → name` map across the union of `current ∪ baseline` events, then resolve dst-only events through that map so they share the fingerprint with their name-bearing siblings.
- **Bug #13 (Job Summary HTML rendered literal)** — `internal/report/detect.go`. The `detectReportPreamble` used `<p align="center">` and `<sub>` which fall outside GitHub's Job Summary HTML allowlist and rendered as literal HTML text. Replace with plain GFM (`**bold**` + em-dash subtitle).
- Add three regression tests: BOM strip (`TestLoadEventsStripsLeadingUTF8BOM`), fingerprint conflation (`TestDiffFingerprintCollapsesDNSCacheMiss`), preamble HTML-tag guard (`TestDetectReportPreamble_NoForbiddenHTML`). Adjust `BenchmarkBuildDiff_*` for the new `fingerprintCounts` signature.

## Why

All three are visible failure modes in the post-v0.4.0 hunt:

- **#10**: an external user reported the integrity gate failing intermittently on detect-mode artifacts they round-tripped through PowerShell pipelines. The PowerShell `Out-File` default encoding emits a BOM.
- **#11**: noisy `traffic_new` / `traffic_gone` diffs across identical workflow runs where the only difference was whether the DNS resolver had warm cache. Reviewers wasted time triaging "new traffic" that was the same destination IP with a momentarily missing fqdn.
- **#13**: the Job Summary card in detect-mode runs showed `<p align="center"><strong>eBPF runtime audit trail</strong></p>` as a literal HTML string, which looks broken. `internal/report/digest.go` already guards `BuildDetectMarkdown` against the same tags — the preamble in `detect.go` was the missing case.

## Test plan

- [ ] `go test ./internal/report/... ./internal/report/model/... -count=1` — including the three new regression cases
- [ ] `bash scripts/check-gofmt.sh`
- [ ] `staticcheck ./internal/report/... ./internal/report/model/...`
- [ ] CI sweep: gofmt, encoding, vet, staticcheck, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode
