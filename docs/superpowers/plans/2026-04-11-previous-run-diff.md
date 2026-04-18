# Previous-run Drift Diff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in previous-run drift report to the detect demo workflow using a workflow env flag that is enabled in demo and off by default elsewhere.

**Architecture:** Keep the implementation in `.github/workflows/nightstalker-demo.yml` so no runtime/action interface changes are needed. When the env flag is enabled, resolve baseline run (same workflow then branch fallback), download prior JSONL artifact if available, generate aggregated+raw diff report, and write a soft-fail summary section.

**Tech Stack:** GitHub Actions YAML, bash, `gh` CLI, `jq`, `diff`, Markdown job summary.

---

## File map

| Path | Responsibility |
| --- | --- |
| `.github/workflows/nightstalker-demo.yml` | Flag wiring, artifact upload, baseline lookup/download, diff reporting |
| `QUICK_START.md` | User-facing docs for enabling and interpreting previous-run diff |

---

### Task 1: Wire feature flag and persist baseline artifact

**Files:**

- Modify: `.github/workflows/nightstalker-demo.yml`
- Test: N/A (workflow-level verification commands in Task 3)

- [ ] **Step 1: Add detect-job env flag**
  - Add `NIGHTSTALKER_DIFF_PREV_RUN: '1'` under the `detect-mode` job `env`.

- [ ] **Step 2: Add upload-artifact step for current JSONL**
  - Add a step after detect verification that uploads `${GITHUB_WORKSPACE}/.nightstalker-events.jsonl` as `nightstalker-events-baseline`.
  - Use `if: always()` and `retention-days: 14`.

- [ ] **Step 3: Verify YAML structure sanity**
  - Run: `python scripts/assert_utf8_text.py`
  - Expected: command exits 0.

---

### Task 2: Implement baseline lookup + hybrid diff summary (soft-fail)

**Files:**

- Modify: `.github/workflows/nightstalker-demo.yml`
- Test: N/A (workflow-level verification commands in Task 3)

- [ ] **Step 1: Add conditional diff step in detect job**
  - Gate with `if: env.NIGHTSTALKER_DIFF_PREV_RUN == '1'`.
  - Set `GH_TOKEN: ${{ github.token }}` in step env.

- [ ] **Step 2: Resolve baseline run ID**
  - Query same-workflow successful runs first (excluding current run id).
  - If empty, fallback to latest successful run on current branch.
  - Record `baseline_run_id` and `fallback_used` markers for summary.

- [ ] **Step 3: Download baseline artifact non-fatally**
  - Attempt `gh run download` for `nightstalker-events-baseline`.
  - If missing/failing, emit `result=unavailable` summary and exit 0.

- [ ] **Step 4: Build aggregated and raw diff output**
  - Use `jq -r '.type // "unknown"'` + `sort | uniq -c` to compute per-type counts for baseline/current.
  - Render a markdown table with baseline/current/delta.
  - Normalize rows with `jq -S .`, run `diff -u`, and append first 120 lines in a fenced block.
  - Emit result marker `changed` or `no-change`.

- [ ] **Step 5: Keep failures soft**
  - On parse/download/command failures, append a clear unavailable reason and exit 0.

---

### Task 3: Update quick start docs and verify changed files

**Files:**

- Modify: `QUICK_START.md`
- Test: N/A

- [ ] **Step 1: Add quickstart section**
  - Document that previous-run diff is workflow-env gated.
  - Show snippet enabling `NIGHTSTALKER_DIFF_PREV_RUN: '1'` in `nightstalker-demo`.
  - State default-off behavior, required permissions (`actions: read`, `contents: read`), first-run no-baseline expectation, and aggregated vs raw interpretation.

- [ ] **Step 2: Run repo text-encoding check**
  - Run: `python scripts/assert_utf8_text.py`
  - Expected: exits 0.

- [ ] **Step 3: Run focused sanity checks**
  - Run: `git diff -- .github/workflows/nightstalker-demo.yml QUICK_START.md`
  - Expected: only intended changes for flag, diff step, artifact upload, and quickstart docs.

---

### Task 4: Final verification and commit

**Files:**

- Modify: `.github/workflows/nightstalker-demo.yml`, `QUICK_START.md`
- Test: verification command outputs
- [ ] **Step 1: Run final verification commands**
  - Run: `python scripts/assert_utf8_text.py`
  - Run: `git status --short`
  - Expected: only intended files changed.

- [ ] **Step 2: Commit implementation changes**
  - Stage workflow and quickstart updates.
  - Commit message: `ci(demo): add opt-in previous-run drift diff reporting`
