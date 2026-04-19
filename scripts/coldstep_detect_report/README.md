# Coldstep detect-mode report (v2)

Two-tier report driven by a single `report-model.json` (schema v2 — adds the `otx` block and per-entry `indicators`). Built for the `coldstep-demo-detect.yml` workflow.

| Surface | What renders it | Where you see it | Owner |
|---|---|---|---|
| **Tier 1** — `$GITHUB_STEP_SUMMARY` (Markdown + Mermaid) | `render_step_summary.py` | Workflow run page, automatically | Engineering / agent |
| **Tier 2** — `report.html` (Observable Plot + d3) | `render_html_report.py` | Run page → Artifacts → download ZIP → unzip → open in a browser | **Frontend designer** |

> GitHub does **not** preview HTML artifacts inline. The Tier-2 file ships as a downloadable artifact, not as a clickable surface inside the run UI. The Tier-1 summary is the always-visible counterpart that needs no clicks. If we ever want a clickable rich URL, see `knowledge/wiki/gha-reports-formats.md` (local) for the GitHub-Pages route — that's a deferred follow-up, not a v1 concern.

## Data contract (`report-model.json`, schema v1)

`build_report_model.py` produces this shape; both renderers consume it. Insertion order is part of the contract — do not `sort_keys=True` on a re-encode.

| Key | Type | Notes |
|---|---|---|
| `schema_version` | `int` | Currently `2`. Bump this any time the shape below changes incompatibly. |
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

The Tier-1 GFM summary picks up OTX in two places: a "Verdict" column appended to the `traffic_new` / `traffic_gone` / `traffic_changed` diff tables (rendered by `render_step_summary.py`), plus a standalone "Threat-intel verdicts" section (Mermaid pie + indicator table) appended by `render_otx_summary.py`. The Tier-2 HTML report adds a collapsible OTX section with an Observable Plot `barY` chart and verdict-color-coded indicator pills (`.coldstep-verdict-{malicious,clean,unidentified,rate-limited}` in `styles.css`).

## Tests

```powershell
python -m unittest discover -s scripts -p "test_*.py"
```

81 tests cover: schema invariants + diff/sankey indicators (`build`), capability pills + Mermaid charts + GFM-cell escaping + the new OTX verdict column (`render_summary`), self-contained HTML5 + JSON island + SRI tag presence + `</script>` defanging + the OTX section anchor and pill classes (`render_html`), the standalone OTX summary renderer, the OTX HTTP client (retry / timeout / typed errors), the verdict classifier, the orchestrator's budget + skip + warning paths, and the new `traffic_indicators()` helper.

## Why two tiers?

See `knowledge/wiki/gha-reports-formats.md` (local) for the full design-space write-up: GitHub gives exactly two surfaces (step summary + downloadable artifact); we use both, share one model, and let a designer own the rich one without ever touching Python.

The vendor-loading + SRI design decision (drop `type="module"`, why ESM is deferred to v2) lives in `knowledge/wiki/web-vendor-loading-sri-plot.md` (local).
