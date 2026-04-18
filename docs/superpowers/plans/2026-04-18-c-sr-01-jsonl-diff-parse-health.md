# C-SR-01 JSONL Diff Parse-Health and Strict Semantics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close finding `C-SR-01` by making `scripts/ci_coldstep_jsonl_traffic_diff.py` always report line/parse health in the job summary, and by making `COLDSTEP_DIFF_STRICT=1` fail the process when either input file contains non-zero JSON-decode errors but a diff is still computable (so “degraded parse” cannot look like a clean pass).

**Architecture:** Extend `load_events` to return per-file **non-empty line counts** alongside **valid object count** and **JSON error line count**. In `main`, always append `NS_MARKER` lines for `parse.base_lines`, `parse.current_lines`, `parse.base_invalid`, `parse.current_invalid`, and a single `parse.health=ok|degraded` (degraded if either file has `invalid>0`). When `COLDSTEP_DIFF_STRICT=1` and `parse.health=degraded` but the diff path still runs (both sides have at least one valid event), return exit code `1` after writing the full diff tables. Retain existing behavior for the “unavailable” branch (empty after parse) and for `COLDSTEP_DIFF_STRICT=0` (relaxed; still write `policy=relaxed` in the unavailable case as today).

**Tech Stack:** Python 3.12+ (stdlib `json`, `os`, `tempfile` in tests), `unittest` in `scripts/test_ci_coldstep_jsonl_traffic_diff.py`, Docker for verification on Windows/Linux hosts per project policy.

---

## File Structure / Responsibility Map

- **Create:** (none)
- **Modify:** `scripts/ci_coldstep_jsonl_traffic_diff.py`
  - `load_events` — return line counts; keep UTF-8 and OSError behavior.
  - `main` — wire new return values; write new summary markers; apply strict parse-fail rule.
- **Modify:** `scripts/test_ci_coldstep_jsonl_traffic_diff.py`
  - Update any test that calls `load_events` to unpack the new return shape.
  - Add tests for strict fail on degraded parse with an otherwise successful diff.
- **Read-only (no code change required for C-SR-01):** `.github/workflows/coldstep-demo*.yml`, `coldstep-ci-runner.yml` already set `COLDSTEP_DIFF_STRICT` and run the script; they pick up stricter exit codes automatically.
- **Do not change in this plan:** `C-SR-02` (long HTTP path) is already mitigated in-tree by the `h=<sha256…>` tail in `traffic_fingerprint` (see `ci_coldstep_jsonl_traffic_diff.py`); do not conflate with this work.

---

### Task 1: Extend `load_events` and add a failing test

**Files:**
- Modify: `scripts/ci_coldstep_jsonl_traffic_diff.py` (function `load_events` only, at current top ~L19–L34)
- Test: `scripts/test_ci_coldstep_jsonl_traffic_diff.py`

- [ ] **Step 1: Add a test for the new return shape (fails until implementation)**

Append to `DiffScriptTests` in `scripts/test_ci_coldstep_jsonl_traffic_diff.py`:

```python
    def test_load_events_counts_non_empty_lines(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.jsonl"
            p.write_text('{"type":"tcp"}\n\nnot-json\n', encoding="utf-8")
            events, invalid, nlines = MOD.load_events(str(p))
            self.assertEqual(1, len(events))
            self.assertEqual(1, invalid)
            self.assertEqual(2, nlines)
```

- [ ] **Step 2: Run the new test to confirm it fails**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace python:3.12-slim python -m unittest scripts.test_ci_coldstep_jsonl_traffic_diff.DiffScriptTests.test_load_events_counts_non_empty_lines`  
Expected: `FAIL` (too many values to unpack or attribute error) or assertion failure until `load_events` is updated.

- [ ] **Step 3: Implement `load_events` with a third return value**

Replace the body of `load_events` in `scripts/ci_coldstep_jsonl_traffic_diff.py` with logic equivalent to:

```python
def load_events(path: str) -> tuple[list[dict], int, int]:
    """Load JSONL objects; skip empty lines after strip.

    Returns:
        events: successfully parsed JSON objects (order preserved).
        invalid: count of non-empty lines that raised json.JSONDecodeError.
        lines: count of non-empty lines after strip (attempted JSON lines).
    """
    out: list[dict] = []
    invalid = 0
    lines = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                lines += 1
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    invalid += 1
    except OSError:
        return [], 0, 0
    return out, invalid, lines
```

Update the function signature line and docstring at the top of `load_events` accordingly.

- [ ] **Step 4: Fix the existing test `test_load_events_counts_invalid_json_lines` unpacking**

Change the line:

```python
events, invalid = MOD.load_events(str(p))
```

to:

```python
events, invalid, _lines = MOD.load_events(str(p))
```

- [ ] **Step 5: Run unit tests for the script**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace python:3.12-slim python -m unittest scripts/test_ci_coldstep_jsonl_traffic_diff.py`  
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/ci_coldstep_jsonl_traffic_diff.py scripts/test_ci_coldstep_jsonl_traffic_diff.py
git commit -m "feat(diff): count JSONL lines for parse-health metrics"
```

---

### Task 2: Wire `main`, summary markers, and strict degraded-parse exit code

**Files:**
- Modify: `scripts/ci_coldstep_jsonl_traffic_diff.py` (`main` ~L162–304)

- [ ] **Step 1: Add failing tests for strict parse degradation**

Append to `scripts/test_ci_coldstep_jsonl_traffic_diff.py`:

```python
    def test_main_strict_fails_when_diff_ok_but_parse_degraded(self):
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            baseline = Path(td) / "base.jsonl"
            current = Path(td) / "cur.jsonl"
            baseline.write_text('{"type":"tcp","dst":"1.1.1.1","dport":443}\nbad\n', encoding="utf-8")
            current.write_text('{"type":"tcp","dst":"1.1.1.1","dport":443}\nbad\n', encoding="utf-8")

            old = dict(os.environ)
            try:
                os.environ["NS_SUMMARY"] = str(summary)
                os.environ["NS_BASELINE"] = str(baseline)
                os.environ["NS_CURRENT"] = str(current)
                os.environ["NS_MARKER"] = "unit"
                os.environ["COLDSTEP_DIFF_STRICT"] = "1"
                rc = MOD.main()
            finally:
                os.environ.clear()
                os.environ.update(old)

            self.assertEqual(1, rc)
            text = summary.read_text(encoding="utf-8")
            self.assertIn("unit.parse.health=degraded", text)

    def test_main_non_strict_ok_when_parse_degraded(self):
        with tempfile.TemporaryDirectory() as td:
            summary = Path(td) / "summary.md"
            baseline = Path(td) / "base.jsonl"
            current = Path(td) / "cur.jsonl"
            baseline.write_text('{"type":"tcp","dst":"1.1.1.1","dport":443}\nbad\n', encoding="utf-8")
            current.write_text('{"type":"tcp","dst":"1.1.1.1","dport":443}\nbad\n', encoding="utf-8")

            old = dict(os.environ)
            try:
                os.environ["NS_SUMMARY"] = str(summary)
                os.environ["NS_BASELINE"] = str(baseline)
                os.environ["NS_CURRENT"] = str(current)
                os.environ["NS_MARKER"] = "unit"
                os.environ["COLDSTEP_DIFF_STRICT"] = "0"
                rc = MOD.main()
            finally:
                os.environ.clear()
                os.environ.update(old)

            self.assertEqual(0, rc)
            text = summary.read_text(encoding="utf-8")
            self.assertIn("unit.parse.health=degraded", text)
```

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace python:3.12-slim python -m unittest scripts.test_ci_coldstep_jsonl_traffic_diff.DiffScriptTests.test_main_strict_fails_when_diff_ok_but_parse_degraded`  
Expected: FAIL until `main` is updated.

- [ ] **Step 2: Update `main` to unpack three values and emit markers**

At the start of event loading (after env validation), change:

```python
base_ev, base_invalid = load_events(base_path)
cur_ev, cur_invalid = load_events(cur_path)
```

to:

```python
base_ev, base_invalid, base_lines = load_events(base_path)
cur_ev, cur_invalid, cur_lines = load_events(cur_path)
```

In the **`if not base_ev or not cur_ev:`** branch (unavailable), extend the written lines to include line counts and health for observability:

```python
parse_health = "degraded" if (base_invalid or cur_invalid) else "ok"
with open(summary_path, "a", encoding="utf-8") as out:
    out.write(f"\n- {marker}.result=unavailable (empty JSONL after parse)\n")
    out.write(f"- {marker}.parse.base_invalid={base_invalid}\n")
    out.write(f"- {marker}.parse.current_invalid={cur_invalid}\n")
    out.write(f"- {marker}.parse.base_lines={base_lines}\n")
    out.write(f"- {marker}.parse.current_lines={cur_lines}\n")
    out.write(f"- {marker}.parse.health={parse_health}\n")
```

Keep the existing relaxed-policy line when `not strict_mode`.

In the **successful diff branch**, after opening `summary_path` for append (same `with open` block that ends near the file’s return 0), ensure these lines appear **once** before return (insert after invalid markers or with them):

```python
parse_health = "degraded" if (base_invalid or cur_invalid) else "ok"
out.write(f"- {marker}.parse.base_lines={base_lines}\n")
out.write(f"- {marker}.parse.current_lines={cur_lines}\n")
out.write(f"- {marker}.parse.health={parse_health}\n")
```

Place them adjacent to the existing `parse.base_invalid` / `parse.current_invalid` writes (currently ~L288–289) so humans can scan one block.

At the very end of `main`, after the `with open` block completes for the success path, add:

```python
    if strict_mode and (base_invalid or cur_invalid):
        return 1
    return 0
```

Remove the bare `return 0` inside the `with` block if present; the function should end with the two-return pattern above so the file is fully written before deciding the exit code.

Concrete end of `main` should look like:

```python
        else:
            out.write(f"- {marker}.result=no-change\n")
            ...
    if strict_mode and (base_invalid or cur_invalid):
        return 1
    return 0
```

(Adjust indentation to match the actual `with open` structure in the file.)

- [ ] **Step 3: Run full script unit tests**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace python:3.12-slim python -m unittest scripts/test_ci_coldstep_jsonl_traffic_diff.py`  
Expected: PASS.

- [ ] **Step 4: Run full Go suite (repo policy)**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./... -count=1`  
Expected: PASS (unchanged Go code; regression guard).

- [ ] **Step 5: Commit**

```bash
git add scripts/ci_coldstep_jsonl_traffic_diff.py scripts/test_ci_coldstep_jsonl_traffic_diff.py
git commit -m "fix(diff): strict CI fails on JSONL parse errors when diff runs"
```

---

### Task 3: Verification notes (documentation only)

**Files:**
- Modify (optional, local vault): `knowledge/reports/2026-04-17-reliability-code-review-findings.md` — update `C-SR-01` row status and evidence command output after merge (repo policy: **`knowledge/` is gitignored**; mirror a one-line note into **`SECURITY.md`** only if maintainers want a tracked artifact).

- [ ] **Step 1: Record verification**

After Docker unittest + `go test ./...`, paste commands and PASS into your local reliability report or PR description.

---

## Self-Review (plan author)

**1. Spec coverage**

| Requirement (from `#finding-c-sr-01`) | Task |
| --------------------------------------- | ---- |
| Counters for parsed vs invalid vs line coverage | Task 1–2 (`load_events` + markers) |
| Strict policy fails when malformed lines exist alongside valid diff | Task 2 (`strict_mode and invalid`) |
| Tests for mixed valid/invalid JSONL | Task 1–2 unit tests |

**2. Placeholder scan**

No `TBD`, `TODO`, or “handle edge cases” without code — each step names exact markers and return codes.

**3. Type consistency**

`load_events` consistently returns `tuple[list[dict], int, int]` everywhere; tests updated to unpack three values.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-18-c-sr-01-jsonl-diff-parse-health.md`. Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
