## Summary

Redesigns `internal/report/digest.go` to surface the most-actionable signals first and collapse long-form prose into a single `<details>` fold. Pure presentation refactor on top of the BG-01 / BG-03 / EmptyReason work that landed via #142, #146, and #144 — no `DigestInput` / `telemetry.Summary` shape changes.

### What changed in the markdown

New section order under `## Coldstep · detect|defend`:

1. Header + caption
2. **Headline status badge** — one-line blockquote verdict (🚨 Alert / ⚠️ Review / ✅ Clean run · mode · BPF state · N exec · N tcp)
3. Hot egress destinations (moved before Triage so the "where did traffic go" answer comes first)
4. Triage ribbon — only the rows that have something to say (`Capture gaps` row hidden when empty); emoji status on BPF hooks / JSONL drops; tagline removed
5. KPI table — reordered to **network → process → fs → health**; ringbuf reserve / multi-iovec / partial-egress counters now sit immediately under the metric they relate to instead of scattering across the table
6. Policy + Dropped rollups
7. Defend section (unchanged)
8. Per-protocol collapsible sections (Exec, BPF audit, Process tree, TCP, UDP, HTTP, TLS, FS)
9. **Run info** — small 2-row table with the JSONL canonical-log path and userspace event-sequence range
10. **Technical details** — single `<details>` fold containing the long-form KPI semantics (now bullet points, not one run-on paragraph), the truncation / row-cap note, TCP / TLS / HTTPS / Process-tree caveats, and the BPF hook status table (previously a standalone table in the main body)

`⚠️` (U+26A0 U+FE0F) is now used consistently for warning rows, replacing the bare `⚠` (U+26A0).

### What changed in code

- `internal/report/digest.go`
  - New focused writers: `writeHeadlineBadge`, `writeKPITable`, `writeRollups`, `writeRunInfo`, `writeTechnicalDetails`, plus a small `partialEgressTotal` helper for the headline-badge threshold.
  - `BuildDetectMarkdown` now drives the section order through those writers; the giant inline KPI block, the bottom `<sub>…</sub>` blob of caveats, the standalone `| BPF hook | Status |` table, and the `### Footnotes` section are all gone.
  - The local `procTreeEmptyReason` closure inside `BuildDetectMarkdown` is replaced with a direct call to the shared `protocolEmptyReason(in.ProcForkDegraded, in.ProcForkReaderErrors)` helper (parity with the tcp/udp/http/tls/fs/bpf-audit call sites).
- `internal/report/digest_test.go` — two needle updates: `⚠` → `⚠️` (Fix 8), and `"IPv4 sendto and sendmsg egress"` → `"**UDP KPI**"` (the prose moved from a `<sub>` blob to a bulleted `<details>` block).

No public API change. No `DigestInput` or `telemetry.Summary` field added or removed. No agent / BPF code touched.

## Test plan

- [x] `go test ./internal/report/... -count=1` — all 30 tests pass.
- [x] `go vet ./internal/report/... ./internal/telemetry/... ./internal/agent/... ./cmd/...` — clean.
- [x] `gofmt -l .` — clean.
- [ ] CI: `coldstep-ci.yml` matrix (`unit`, `unit-arm64`, `integration`, `detect-mode`, `defend-mode`) — verified by CI on the PR.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
