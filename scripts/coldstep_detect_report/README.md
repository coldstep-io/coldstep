# Coldstep detect-mode report (v2.1)

Two-tier report driven by a single `report-model.json` (schema **v2.1** — string `schema_version`, OTX `confidence` tiers on malicious indicators, filter audit fields). Built for the `coldstep-demo-detect.yml` workflow.

## `coldstep-demo-detect.yml` pipeline order

1. `build_report_model.py` — current JSONL only (`diff` may be `unavailable` until baseline exists).
2. **Previous-run diff** — downloads baseline artifact, runs `ci_coldstep_jsonl_traffic_diff.py` with **`COLDSTEP_TRAFFIC_DIFF_SUMMARY=minimal`** (compact counts + markers only; no fingerprint tables in the job summary), then **rebuilds** `.coldstep-report-model.json` with `COLDSTEP_REPORT_BASELINE_JSONL` when the diff path succeeds.
3. `enrich_rdns.py` → `scripts.coldstep_otx.enrich` — in-place enrichment on `.coldstep-report-model.json` (PTR + AlienVault OTX).
4. `render_step_summary.py` — Tier-1 **BLUF only** (capabilities headline, baseline-diff headline, OTX headline, artifact pointer). Runs **after** enrich so OTX lines reflect the enriched model.
5. `render_html_report.py` — Tier-2 self-contained HTML (`coldstep-detect-report.html`).

`render_otx_summary.py` remains importable but **does not append** to `$GITHUB_STEP_SUMMARY`; full OTX tables and charts are Tier-2 only.

| Surface | What renders it | Where you see it | Owner |
|---|---|---|---|
| **Tier 1** — `$GITHUB_STEP_SUMMARY` (short BLUF Markdown, no Mermaid) | `render_step_summary.py` | Workflow run page, automatically | Engineering / agent |
| **Tier 2** — `report.html` (Observable Plot + d3) | `render_html_report.py` | Run page → Artifacts → download ZIP → unzip → open in a browser | **Frontend designer** |

> GitHub does **not** preview HTML artifacts inline. The Tier-2 file ships as a downloadable artifact, not as a clickable surface inside the run UI. The Tier-1 summary is the always-visible counterpart that needs no clicks. If we ever want a clickable rich URL, see `knowledge/wiki/gha-reports-formats.md` (local) for the GitHub-Pages route — that's a deferred follow-up, not a v1 concern.

## Data contract (`report-model.json`, schema v2.1)

`build_report_model.py` produces this shape; both renderers consume it. Insertion order is part of the contract — do not `sort_keys=True` on a re-encode.

| Key | Type | Notes |
|---|---|---|
| `schema_version` | `string` | Currently **`"2.1"`**. Bump when the shape changes incompatibly (semver-style string). |
| `generated_at` | ISO-8601 UTC string with `Z` suffix | Emitted by the builder, not by the renderer. Deterministic when `build()` is called with `now=...` (used in tests). |
| `run.run_id` | string | From the JSONL `meta` event if present, else `$GITHUB_RUN_ID`. |
| `run.workflow_file` | string | Parsed from `$GITHUB_WORKFLOW_REF` (the `{repo}/.github/workflows/{file}@{ref}` format). |
| `run.branch` | string | `$GITHUB_HEAD_REF` (PR builds) ?? `$GITHUB_REF_NAME` (push builds). |
| `run.runner_label` | string | `$NS_RUNNER_LABEL` if you set it. |
| `capability_matrix` | `[{id, label, status, evidence_count}]` | One row per `REQUIRED_CAPABILITIES` constant. `status` is `"pass"` / `"warn"` / `"fail"`. |
| `events_by_type` | `[{type, count}]` sorted descending by `count` | Excludes the `meta` envelope event so it doesn't pollute charts. |
| `timeline` | `[{bucket, type, count}]` | `bucket` is a 1-second UTC bin, ISO-8601 with `Z` suffix. |
| `egress_sankey` | `[{source, target, value, indicators}]` | `source` is host, `target` is policy decision. `indicators` is the OTX-eligible indicator list (IPv4/FQDN) for the edge — added in schema v2 for cross-joining with the `otx` block. |
| `diff` | `{status, reason?, traffic_new[], traffic_gone[], traffic_changed[]}` | `status` is `"ok"` (with the three buckets) or `"unavailable"` (with `reason`). Each entry in the three buckets carries `indicators: list[str]` (schema v2). |
| `otx` | `null` \| `{skipped, ...}` \| `{schema_version, generated_at, indicators[], summary, partial_results, api_calls, wall_time_ms}` | Populated by `scripts/coldstep_otx/enrich.py`. `null` until enrichment runs; `{"skipped": "no_api_key" \| "invalid_key" \| "no_indicators"}` when enrichment short-circuits; full block when enrichment completes (possibly partial). Each `indicators[]` entry is `{indicator, type, verdict, evidence[], rate_limited?}`. |
| `dns_lookups` | `{ip: hostname}` map, optional | Populated by `scripts/coldstep_dns/enrich_rdns.py`. Best-effort PTR resolution for every IPv4 indicator on the model (hostnames are skipped — they already are names). Missing entry = no PTR / timed out / not asked. Schema-additive: renderers that don't know about it ignore the key, renderers that do know join on the IP to display "8.8.8.8 (dns.google)". |

### Required capabilities (anchor the matrix)

The `REQUIRED_CAPABILITIES` constant in `build_report_model.py` is the source of truth for which detector probes show up in the matrix. Edit that tuple to add or remove rows; the renderers pick up the change with no further edits.

## Local rendering (no GitHub needed)

The same pipeline runs end-to-end against the bundled fixtures:

```powershell
# 1. Build the model from the fixtures.
$env:COLDSTEP_REPORT_CURRENT_JSONL  = "scripts/coldstep_detect_report/fixtures/coldstep-events.sample.jsonl"
$env:COLDSTEP_REPORT_BASELINE_JSONL = "scripts/coldstep_detect_report/fixtures/baseline-events.sample.jsonl"
$env:COLDSTEP_REPORT_MODEL_OUT      = "report-model.json"
python scripts/coldstep_detect_report/build_report_model.py

# 2a. Render the HTML artifact.
$env:COLDSTEP_REPORT_MODEL_IN  = "report-model.json"
$env:COLDSTEP_REPORT_HTML_OUT  = "report.html"
python scripts/coldstep_detect_report/render_html_report.py
# open report.html in a browser

# 2b. (Optional) render the GitHub step summary too. GitHub injects
#     GITHUB_STEP_SUMMARY in CI; locally you point it at any file.
$env:GITHUB_STEP_SUMMARY = "step-summary.md"
python scripts/coldstep_detect_report/render_step_summary.py
# step-summary.md previews in any markdown viewer that supports Mermaid
```

Drop `COLDSTEP_REPORT_BASELINE_JSONL` to simulate a first run (the diff section becomes `unavailable`).

## Designer seam — what you can and can't edit safely

`render_html_report.py` is a 60-line substitute-and-write script. The visual surface lives in two files:

```
scripts/coldstep_detect_report/templates/
  report.html     ← layout, mark up, chart code
  styles.css      ← inline-injected CSS
```

The Python renderer fills exactly three placeholders, in this order:

| Placeholder | Replaced with | Notes |
|---|---|---|
| `{{ STYLES }}` | the contents of `templates/styles.css` | Inlined inside `<style>…</style>`. Keep `styles.css` plain CSS — no `@import`, no relative URLs. |
| `{{ MODEL_JSON }}` | the full `report-model.json` payload | Goes inside `<script id="coldstep-report-model" type="application/json">`. The renderer defangs every literal `</` to `<\/` so the host script tag can't be terminated early. |
| `{{ GENERATED_AT }}` | `model["generated_at"]` | A convenience for the page header. |

The substitution order is intentional and security-sensitive — see the comment in `render_html_report.py`. If you add a new `{{ FOO }}`, do it in the same `.replace()` chain at the end, after the existing three.

**Designer-safe edits** (no Python change needed):
- Anything in `templates/styles.css`.
- HTML structure / classnames in `templates/report.html` outside the placeholders.
- Plot mark configurations in the inline `<script type="module">` (try a different `Plot.dot()` instead of `Plot.barX()`, swap colour scales, etc.).

**Edits that require coordinating with the Python side:**
- Adding a new top-level field to the model → edit `build_report_model.py` and bump `SCHEMA_VERSION`. Tests in `scripts/test_coldstep_detect_report_build.py` will need a new assertion.
- Removing a model field → same deal. Don't silently change the contract.
- Adding a new `{{ PLACEHOLDER }}` → add the corresponding `.replace()` call in `render_html_report.py` *after* `{{ MODEL_JSON }}` (so a malicious upstream value can't inject the literal).

**Don't touch unless you've read the rationale:**
- The `<script id="coldstep-report-model" type="application/json">` block — the type and id are what the inline reader code looks up.
- The vendor `<script src="…d3…">` and `<script src="…plot…">` tags — the `crossorigin="anonymous"` attribute is required for the `integrity=` SRI hash to be honoured. The current `@7` / `@0.6` URLs and `sha384-PLACEHOLDER_*` values are intentional placeholders pinned to be replaced by Task 7. Background in `knowledge/wiki/web-vendor-loading-sri-plot.md` (local).
- The `WARNING: these template literals write to innerHTML` comment in the inline script — it tells the next person what to do before adding a user-derived field. Honour it.

### XSS posture

Inputs to the report come from a controlled source (Coldstep's own JSONL events plus a fixed list of capability constants). The renderer is *defense-in-depth*, not the primary trust boundary:

- Server side: `_safe_json()` in `render_html_report.py` defangs `</` so an attacker who controls a JSON string value cannot terminate the data island.
- Client side: every field consumed by the `innerHTML` template-literal builders today comes from `REQUIRED_CAPABILITIES` (Python constants) or numeric counts. Before piping a *user-supplied string* (a CLI label from a contributor's PR, an arbitrary error message, etc.) through one of those builders, switch the relevant assignment to `textContent =` or pass it through an `escapeHtml()` helper.

## OTX threat-intel enrichment (schema v2)

`scripts/coldstep_otx/enrich.py` runs **between** the diff-step model rebuild and the HTML render. It reads the model in place, dedupes IPv4/FQDN indicators from `egress_sankey[].indicators` and `diff.traffic_*[].indicators`, looks up each one against AlienVault OTX's `general` endpoint, classifies the response into `malicious` / `clean` / `unidentified`, and writes the enriched model back to disk.

| Env var | Default | Notes |
|---|---|---|
| `OTX_API_KEY` | _(none)_ | Repo secret. Missing or empty → `model.otx = {"skipped": "no_api_key"}`, exit 0. |
| `COLDSTEP_REPORT_MODEL_IN` | _(required)_ | Path to the JSON model. The script reads and overwrites this file in place. |
| `COLDSTEP_OTX_WALL_BUDGET_MS` | `30000` | Hard wall-clock cap. When exhausted the script records `partial_results: true` and returns the indicators it had time for. |

**Failure modes are observational, not fatal.** Every error path (missing key, 403 invalid key, transport error, exhausted budget) returns exit 0. The CI step also pins `continue-on-error: true` for belt-and-braces. Malicious indicators surface as GitHub `::warning::` annotations on the run — they never fail the job.

**Allowlist (OTX bypass, not OTX skip).** RFC-reserved address space (loopback `127.0.0.0/8` in v1) is matched against `scripts/coldstep_otx/allowlist.py` *before* the OTX call. Allowlisted indicators are still recorded in `model.otx.indicators[]` with `verdict: "clean"`, `source: "allowlist"`, `reason: "loopback"` so the action is auditable, but they consume zero API calls and zero wall-clock budget. The Tier-1 GFM verdict cell shows `🟩 clean (allowlist: loopback)` so a reader can tell the two flavours of "clean" apart. Adding RFC1918 / link-local is a one-tuple edit in `allowlist.py` — no schema or renderer change needed.

The Tier-1 GFM summary picks up OTX in two places: a "Verdict" column appended to the `traffic_new` / `traffic_gone` / `traffic_changed` diff tables (rendered by `render_step_summary.py`), plus a standalone "Threat-intel verdicts" section (Mermaid pie + per-tier `<details>` tables for malicious confidence, plus an "Other verdicts" table for non-malicious rows) appended by `render_otx_summary.py`. Malicious indicators without `confidence` render as **high** tier for backwards compatibility. When `filter_drops` / `filtered_pulses` are set, the GFM section includes a short filter-audit block. The Tier-2 HTML report adds a collapsible OTX section with an Observable Plot `barY` chart, verdict-color-coded indicator pills (`.coldstep-verdict-{malicious,clean,unidentified,rate-limited}`), and confidence-tier grouping (`.coldstep-otx-tier`, `data-tier`, CSS vars `--coldstep-confidence-*` in `styles.css`).

**Egress-flow verdict pivot.** When OTX has produced verdicts the egress flow becomes 3-column instead of 2: `host → verdict → policy`. Tier-1 emits a Mermaid `sankey-beta` with two sub-edges per host (host → verdict, verdict → policy); Tier-2 splits the existing single stacked-bar into a pair (host → verdict on top, verdict → policy below). Edges whose indicators OTX never saw (partial budget, IPv6, allowlist-but-no-OTX-row) route through a synthetic `unverified` bucket so the visualization stays mass-balanced. Host labels also pick up the rDNS hostname from `model.dns_lookups` when present, so `8.8.8.8` displays as `8.8.8.8 (dns.google)`. Both renderers fall back to the classic 2-column flow when OTX is absent or skipped.

## Reverse-DNS enrichment (rDNS)

`scripts/coldstep_dns/enrich_rdns.py` runs **before** OTX enrichment so that the OTX renderers (and a future 3-column Sankey) can label IPv4 indicators with their PTR hostname (e.g. `8.8.8.8 (dns.google)`). Stdlib only — no API key, no third-party dep, no per-indicator HTTP request. Best-effort: missing PTR / OS-level timeout / unexpected exception silently omits the entry; never fails the job.

| Env var | Default | Notes |
|---|---|---|
| `COLDSTEP_REPORT_MODEL_IN` | _(required)_ | Same model file as OTX. Read + overwrite in place. |
| `COLDSTEP_RDNS_WALL_BUDGET_MS` | `5000` | Whole-batch wall budget. Per-call timeout is fixed at 1 s. Worker pool is 10. |

The enricher writes `model.dns_lookups` (an `{ip: hostname}` map, optional). Any renderer that wants to display friendly names joins on indicator IP. The Tier-1 OTX summary table widens to add a "Hostname" column when at least one indicator in the table has a lookup; the Tier-2 HTML OTX list appends `(hostname)` after the indicator code. Quality caveat: PTR is great for owned ranges (`dns.google`, `one.one.one.one`) but generic for cloud IPs (`*.1e100.net` for Google frontends, `*.amazonaws.com`). A passive-DNS fallback via OTX's `/passive_dns` endpoint is a tracked v2 follow-up.

## Tests

```powershell
python -m unittest discover -s scripts -p "test_*.py"
```

124 tests cover: schema invariants + diff/sankey indicators (`build`), capability pills + Mermaid charts + GFM-cell escaping + the OTX verdict column + the rDNS hostname column + the 3-column sankey pivot (`render_summary`), self-contained HTML5 + JSON island + SRI tag presence + `</script>` defanging + the OTX section anchor + pill classes + `dns_lookups` round-trip + the host→verdict / verdict→policy mounts (`render_html`), the standalone OTX summary renderer, the OTX HTTP client (retry / timeout / typed errors), the verdict classifier, the orchestrator's budget + skip + warning paths, the `traffic_indicators()` helper, the `coldstep_dns.rdns` batch resolver (wall budget + per-call timeout + dedupe + IPv4 filtering + trailing-dot normalisation), and the `coldstep_dns.enrich_rdns` orchestrator (always-exit-0 + idempotent overwrite).

## Why two tiers?

See `knowledge/wiki/gha-reports-formats.md` (local) for the full design-space write-up: GitHub gives exactly two surfaces (step summary + downloadable artifact); we use both, share one model, and let a designer own the rich one without ever touching Python.

The vendor-loading + SRI design decision (drop `type="module"`, why ESM is deferred to v2) lives in `knowledge/wiki/web-vendor-loading-sri-plot.md` (local).
