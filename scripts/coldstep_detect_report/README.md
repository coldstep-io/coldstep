# Coldstep detect-mode report (v1)

Two-tier report driven by a single `report-model.json` (schema v1). Built for the `coldstep-demo-detect.yml` workflow.

| Surface | What renders it | Where you see it | Owner |
|---|---|---|---|
| **Tier 1** — `$GITHUB_STEP_SUMMARY` (Markdown + Mermaid) | `render_step_summary.py` | Workflow run page, automatically | Engineering / agent |
| **Tier 2** — `report.html` (Observable Plot + d3) | `render_html_report.py` | Run page → Artifacts → download ZIP → unzip → open in a browser | **Frontend designer** |

> GitHub does **not** preview HTML artifacts inline. The Tier-2 file ships as a downloadable artifact, not as a clickable surface inside the run UI. The Tier-1 summary is the always-visible counterpart that needs no clicks. If we ever want a clickable rich URL, see `knowledge/wiki/gha-reports-formats.md` (local) for the GitHub-Pages route — that's a deferred follow-up, not a v1 concern.

## Data contract (`report-model.json`, schema v1)

`build_report_model.py` produces this shape; both renderers consume it. Insertion order is part of the contract — do not `sort_keys=True` on a re-encode.

| Key | Type | Notes |
|---|---|---|
| `schema_version` | `int` | Currently `1`. Bump this any time the shape below changes incompatibly. |
| `generated_at` | ISO-8601 UTC string with `Z` suffix | Emitted by the builder, not by the renderer. Deterministic when `build()` is called with `now=...` (used in tests). |
| `run.run_id` | string | From the JSONL `meta` event if present, else `$GITHUB_RUN_ID`. |
| `run.workflow_file` | string | Parsed from `$GITHUB_WORKFLOW_REF` (the `{repo}/.github/workflows/{file}@{ref}` format). |
| `run.branch` | string | `$GITHUB_HEAD_REF` (PR builds) ?? `$GITHUB_REF_NAME` (push builds). |
| `run.runner_label` | string | `$NS_RUNNER_LABEL` if you set it. |
| `capability_matrix` | `[{id, label, status, evidence_count}]` | One row per `REQUIRED_CAPABILITIES` constant. `status` is `"pass"` / `"warn"` / `"fail"`. |
| `events_by_type` | `[{type, count}]` sorted descending by `count` | Excludes the `meta` envelope event so it doesn't pollute charts. |
| `timeline` | `[{bucket, type, count}]` | `bucket` is a 1-second UTC bin, ISO-8601 with `Z` suffix. |
| `egress_sankey` | `[{source, target, value}]` | `source` is host, `target` is policy decision. Empty-string policy maps to `""` (matches the upstream traffic fingerprinter). |
| `diff` | `{status, reason?, traffic_new[], traffic_gone[], traffic_changed[]}` | `status` is `"ok"` (with the three buckets) or `"unavailable"` (with `reason`). |

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

## Tests

```powershell
cd scripts
python -m unittest test_coldstep_detect_report_build test_coldstep_detect_report_render_summary test_coldstep_detect_report_render_html -v
```

21 tests cover: schema invariants and fixture diffing (`build`), capability pills + `xychart-beta` + `sankey-beta` + GFM-cell escaping (`render_summary`), self-contained HTML5 + JSON island + SRI tag presence + `</script>` defanging (`render_html`).

## Why two tiers?

See `knowledge/wiki/gha-reports-formats.md` (local) for the full design-space write-up: GitHub gives exactly two surfaces (step summary + downloadable artifact); we use both, share one model, and let a designer own the rich one without ever touching Python.

The vendor-loading + SRI design decision (drop `type="module"`, why ESM is deferred to v2) lives in `knowledge/wiki/web-vendor-loading-sri-plot.md` (local).
