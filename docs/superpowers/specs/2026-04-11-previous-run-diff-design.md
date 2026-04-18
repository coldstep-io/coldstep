# Previous-run drift diff for detect demo workflow

## Summary

Add an optional previous-run drift report to the detect demo workflow, gated by an environment flag that is enabled in `.github/workflows/nightstalker-demo.yml` and off by default elsewhere.

The report is hybrid:

- Primary: aggregated count deltas by JSONL event type.
- Secondary: capped raw `diff -u` excerpt of normalized JSONL rows.

This feature is observability-only and soft-fail by design. If baseline lookup/download/parsing fails, the workflow still succeeds and writes an explicit "diff unavailable" explanation to `GITHUB_STEP_SUMMARY`.

## Scope

- Add previous-run diff logic to `.github/workflows/nightstalker-demo.yml`.
- Use built-in `GITHUB_TOKEN` (no PAT requirement) with read-only permissions.
- Use baseline selection strategy:
  1) latest successful run for the same workflow,
  2) fallback to latest successful run on the current branch.
- Keep default behavior off unless `NIGHTSTALKER_DIFF_PREV_RUN=1`.
- Document usage and interpretation in quickstart docs.

## Non-goals

- No composite action input or runtime code changes for this feature in v1.
- No enforcement behavior changes.
- No hard-fail policy when diff data is unavailable.
- No cross-repo baseline retrieval.

## Workflow architecture

Feature flag:

- Add `NIGHTSTALKER_DIFF_PREV_RUN: '1'` in the detect demo workflow/job env.
- Treat unset/`0` as disabled.

Execution flow when enabled:

1. Resolve a baseline run ID:
   - Query successful runs for the same workflow.
   - Exclude current run ID.
   - If missing, query successful runs for current branch as fallback.
2. Download baseline artifact:
   - Retrieve artifact containing previous `.nightstalker-events.jsonl`.
   - Keep all failures non-fatal.
3. Compute hybrid diff:
   - Aggregated type-count deltas.
   - Optional capped raw diff excerpt.
4. Append a "Previous Run Diff" section to `GITHUB_STEP_SUMMARY`.

Authentication and permissions:

- Use `GH_TOKEN: ${{ github.token }}` for `gh` CLI commands.
- Ensure job permissions include:
  - `actions: read`
  - `contents: read`

## Data flow and semantics

Inputs:

- Baseline JSONL from previous successful run artifact.
- Current JSONL from `${GITHUB_WORKSPACE}/.nightstalker-events.jsonl`.

Normalization:

- Sort JSON keys for stable comparisons (`jq -S`) before raw diff.
- Preserve line-per-event semantics; no event reordering heuristic in v1.

Aggregated section (primary signal):

- Count rows by `type` for both baseline and current JSONL.
- Track representative known types: `exec`, `tcp`, `udp`, `http`, `tls`, `fs_event`, `proc_fork`, `deny`.
- Render table columns:
  - event type
  - baseline count
  - current count
  - signed delta
- Emit top-level status:
  - no drift when all deltas are zero
  - drift detected when any delta is non-zero

Raw section (secondary detail):

- Generate `diff -u` on normalized JSONL outputs.
- Include only first N lines (cap in v1 to keep summary readable).
- If no differences, print explicit "raw diff clean" message.

## Soft-fail behavior

Any of the following should mark diff as unavailable but not fail the job:

- no prior successful run found
- no matching artifact in the baseline run
- artifact download errors
- missing or malformed baseline/current JSONL
- `jq` or `diff` execution errors

Required summary markers:

- diff feature enabled/disabled
- resolved baseline run ID if available
- whether fallback path was used
- result category: `unavailable`, `no-change`, or `changed`

## Testing strategy

1. No-baseline path:
   - First run on branch reports unavailable baseline and succeeds.
2. Positive path:
   - Second run resolves baseline and prints aggregated + raw sections.
3. Fallback path:
   - Force same-workflow lookup miss and verify branch fallback activates.
4. Malformed input path:
   - Corrupt one side and verify soft-fail summary text appears without job failure.

Validation environment remains GitHub-hosted `ubuntu-latest` only.

## Documentation changes

Update quickstart documentation with:

- what the previous-run diff does
- how to enable in workflow via `NIGHTSTALKER_DIFF_PREV_RUN=1`
- default-off behavior
- required read permissions (`actions: read`, `contents: read`)
- how to read aggregated vs raw sections
- first-run expectation (no baseline yet)

## Risks and mitigations

- Artifact naming mismatch across runs:
  - Mitigation: explicit summary note with baseline run ID and missing artifact reason.
- Summary noise from large raw diffs:
  - Mitigation: cap raw diff lines and prioritize aggregated table.
- Workflow API variance (fork/branch permissions):
  - Mitigation: soft-fail and clear diagnostics in summary.

## Self-review

- Placeholder scan: no TODO/TBD placeholders.
- Consistency scan: feature flag, fallback strategy, and soft-fail behavior are aligned across sections.
- Scope scan: single workflow + docs change; no runtime agent changes.
- Ambiguity scan: baseline lookup order and failure handling are explicit.
