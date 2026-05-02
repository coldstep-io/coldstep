# Coldstep detect-mode report (v2.1)

Two-tier report driven by a single `report-model.json` (schema **v2.1**). Built by the Go CLI (`bin/coldstep-report`) and used by the `coldstep-demo-detect.yml` workflow.

**Reusable Tier-1 contract ("pattern D"):** see [`GHA_JOB_SUMMARY_REUSABLE_PATTERN.md`](GHA_JOB_SUMMARY_REUSABLE_PATTERN.md) for BLUF section order, triage alerts, run deeplink, and vocabulary parity with Tier-2 HTML headings.

## `coldstep-demo-detect.yml` pipeline order

1. `coldstep-report build-model` — current JSONL only (`diff` may be `unavailable` until baseline exists).
2. **Previous-run diff** — downloads baseline artifact, runs `coldstep-report diff`, then rebuilds `.coldstep-report-model.json` with `COLDSTEP_REPORT_BASELINE_JSONL` when the diff path succeeds.
3. `coldstep-report rdns-enrich` — in-place PTR enrichment on `.coldstep-report-model.json`.
4. `coldstep-report otx-enrich` — in-place AlienVault OTX enrichment (requires `OTX_API_KEY`).
5. `coldstep-report render-summary` — Tier-1 **BLUF only** (capabilities headline, baseline-diff headline, OTX headline, artifact pointer). Runs **after** enrich so OTX lines reflect the enriched model.
6. `coldstep-report render-html` — Tier-2 self-contained HTML (`coldstep-detect-report.html`).

| Surface | What renders it | Where you see it |
|---|---|---|
| **Tier 1** — `$GITHUB_STEP_SUMMARY` (short BLUF Markdown) | `coldstep-report render-summary` | Workflow run page, automatically |
| **Tier 2** — `report.html` (Observable Plot + d3) | `coldstep-report render-html` | Run page → Artifacts → download ZIP → unzip → open in a browser |

> GitHub does **not** preview HTML artifacts inline. The Tier-2 file ships as a downloadable artifact, not as a clickable surface inside the run UI. The Tier-1 summary is the always-visible counterpart that needs no clicks.

## Data contract (`report-model.json`, schema v2.1)

`coldstep-report build-model` produces this shape; both renderers consume it. Insertion order is part of the contract.

| Key | Type | Notes |
|---|---|---|
| `schema_version` | `string` | Currently **`"2.1"`**. Bump when the shape changes incompatibly. |
| `generated_at` | ISO-8601 UTC string with `Z` suffix | Emitted by the builder. |
| `run.run_id` | string | From the JSONL `meta` event if present, else `$GITHUB_RUN_ID`. |
| `run.workflow_file` | string | Parsed from `$GITHUB_WORKFLOW_REF`. |
| `run.branch` | string | `$GITHUB_HEAD_REF` (PR builds) ?? `$GITHUB_REF_NAME` (push builds). |
| `run.runner_label` | string | `$NS_RUNNER_LABEL` if set. |
| `capability_matrix` | `[{id, label, status, evidence_count}]` | `status` is `"pass"` / `"warn"` / `"fail"`. |
| `events_by_type` | `[{type, count}]` sorted descending by `count` | Excludes the `meta` envelope event. |
| `timeline` | `[{bucket, type, count}]` | `bucket` is a 1-second UTC bin, ISO-8601 with `Z` suffix. |
| `egress_sankey` | `[{source, target, value, indicators}]` | `source` is host, `target` is policy decision. `indicators` is the OTX-eligible indicator list for the edge. |
| `diff` | `{status, reason?, traffic_new[], traffic_gone[], traffic_changed[]}` | `status` is `"ok"` or `"unavailable"`. Each entry carries `indicators: list[str]` (schema v2). |
| `otx` | `null` \| `{skipped, ...}` \| full block | Populated by `coldstep-report otx-enrich`. `null` until enrichment runs; `{"skipped": "no_api_key" \| ...}` when enrichment short-circuits. |
| `dns_lookups` | `{ip: hostname}` map, optional | Populated by `coldstep-report rdns-enrich`. Best-effort PTR. |
| `ip_classification` | `[{...}]` | Embedded IP/FQDN/rDNS classification rows. |

## Local rendering (no GitHub needed)

The same pipeline runs end-to-end against the bundled fixtures using the Go CLI:

```bash
# 1. Build the model from the fixtures.
export COLDSTEP_REPORT_CURRENT_JSONL="scripts/coldstep_detect_report/fixtures/coldstep-events.sample.jsonl"
export COLDSTEP_REPORT_BASELINE_JSONL="scripts/coldstep_detect_report/fixtures/baseline-events.sample.jsonl"
export COLDSTEP_REPORT_MODEL_OUT="report-model.json"
./bin/coldstep-report build-model

# 2a. Render the HTML artifact.
export COLDSTEP_REPORT_MODEL_IN="report-model.json"
export COLDSTEP_REPORT_HTML_OUT="report.html"
./bin/coldstep-report render-html
# open report.html in a browser

# 2b. (Optional) render the step summary locally.
export GITHUB_STEP_SUMMARY="step-summary.md"
./bin/coldstep-report render-summary
# step-summary.md previews in any Markdown viewer
```

Drop `COLDSTEP_REPORT_BASELINE_JSONL` to simulate a first run (the diff section becomes `unavailable`).

## Designer seam — templates

The Tier-2 HTML report is rendered from two files:

```
scripts/coldstep_detect_report/templates/
  report.html     ← layout, markup, chart code
  styles.css      ← inline-injected CSS
```

The Go renderer fills exactly three placeholders:

| Placeholder | Replaced with | Notes |
|---|---|---|
| `{{ STYLES }}` | the contents of `templates/styles.css` | Inlined inside `<style>…</style>`. Keep `styles.css` plain CSS — no `@import`, no relative URLs. |
| `{{ MODEL_JSON }}` | the full `report-model.json` payload | Goes inside `<script id="coldstep-report-model" type="application/json">`. Every `</` is defanged to `<\/`. |
| `{{ GENERATED_AT }}` | `model["generated_at"]` | A convenience for the page header. |

**Designer-safe edits** (no Go change needed):
- Anything in `templates/styles.css`.
- HTML structure / classnames in `templates/report.html` outside the placeholders.
- Plot mark configurations in the inline `<script type="module">`.

**Don't touch unless you've read the rationale:**
- The `<script id="coldstep-report-model" type="application/json">` block — the type and id are what the inline reader looks up.
- The vendor `<script src="…d3…">` and `<script src="…plot…">` tags — `crossorigin="anonymous"` is required for SRI `integrity=` to be honoured.

## OTX threat-intel enrichment

`coldstep-report otx-enrich` runs **between** the diff-step model rebuild and the HTML render. It reads the model in place, dedupes IPv4/FQDN indicators, looks up each against AlienVault OTX's `general` endpoint, and writes the enriched model back to disk.

| Env var | Default | Notes |
|---|---|---|
| `OTX_API_KEY` | _(none)_ | Repo secret. Missing or empty → `model.otx = {"skipped": "no_api_key"}`, exit 0. |
| `COLDSTEP_REPORT_MODEL_IN` | _(required)_ | Path to the JSON model. Read and overwritten in place. |
| `COLDSTEP_OTX_WALL_BUDGET_MS` | `30000` | Hard wall-clock cap. When exhausted, records `partial_results: true`. |

**Failure modes are observational, not fatal.** Every error path returns exit 0. Malicious indicators surface as `::warning::` annotations — they never fail the job.

## Reverse-DNS enrichment (rDNS)

`coldstep-report rdns-enrich` runs **before** OTX enrichment so renderers can label IPv4 indicators with their PTR hostname (e.g. `8.8.8.8 (dns.google)`). Best-effort: missing PTR / timeout silently omits the entry; never fails the job.

| Env var | Default | Notes |
|---|---|---|
| `COLDSTEP_REPORT_MODEL_IN` | _(required)_ | Same model file as OTX. Read + overwritten in place. |
| `COLDSTEP_RDNS_WALL_BUDGET_MS` | `5000` | Whole-batch wall budget. Per-call timeout is fixed at 1 s. |

## Why two tiers?

GitHub gives exactly two surfaces (step summary + downloadable artifact); we use both, share one model, and let a designer own the rich one without touching Go internals. See `knowledge/wiki/gha-reports-formats.md` (local) for the full design-space write-up.
