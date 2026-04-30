# Plan — Reject legacy `"mode":"enforce"` in JSONL (no reader tolerance)

**Goal:** On-disk and in-CI **JSONL** is **strict**: **`deny`** (and any other) rows must not use the removed consumer spelling **`enforce`** in the **`mode`** field. Parsers and product docs **do not** treat legacy **`enforce`** as an alias of **`defend`**.

**Non-goal (this plan):** Renaming the internal Go constant `config.ModeEnforce` or BPF object names containing `enforce` — that is implementation vocabulary, not the **JSONL wire format**. Optional follow-up: rename to `ModeDefend` in a separate refactor.

**Breaking:** Any archived **`.coldstep-events.jsonl`** (or copies) that still contain **`"mode":"enforce"`** must be **migrated** (search-replace or regeneration) before strict CI passes.

---

## Policy

| Surface | Allowed `mode` values (JSONL) |
| :------ | :---------------------------- |
| **`type":"deny"`** | **`defend`** only (blocking). |
| Other event types | Use product rules per schema (most rows omit **`mode`** or use **`defend`** / **`detect`** as documented). |

**Invalid:** `"mode":"enforce"` on any parsed row → **hard error** in validation paths, or **skip row + count as decode failure** where malformed lines are already skipped (decide per loader — prefer **fail** for `coldstep-report` integrity path).

---

## Phase 1 — Go: digest + telemetry

| Step | File / area | Change |
| :--- | :---------- | :----- |
| 1.1 | `internal/report/digest.go` | Remove **`enforce`** from **`isBlockingDigestMode`**. Delete **`digestModeCell`** normalization **`enforce`→`defend`**; blocking digest sections require **`defend`** (case-fold OK) or treat **`enforce`** as **non-blocking** / empty for display **only if** we still need to render old digests — **prefer**: treat unknown **`enforce`** as invalid and do not classify as defend (user chose **no tolerance**). |
| 1.2 | `internal/report/digest_test.go` | Replace fixtures using **`EnforcementMode: "enforce"`** with **`"defend"`**; update expected substrings if any. |
| 1.3 | `internal/telemetry/event.go` | Comment on **`DenyEvent.Mode`**: only **`defend`** is valid for new writes; **legacy `enforce` is invalid on read** when validation runs. |
| 1.4 | Optional helper | `telemetry.ValidateJSONLMode(deny bool, mode string) error` — single place for rules. |

---

## Phase 2 — Go: JSONL load / report model

| Step | File / area | Change |
| :--- | :---------- | :----- |
| 2.1 | `internal/report/model/jsonl.go` | Add **`LoadEventsStrict(path)`** (or **`ValidateNoLegacyEnforce`**) that, after **`LoadEvents`**, scans events with **`type":"deny"`** (and any row carrying **`mode`**) and returns **`error`** if **`strings.EqualFold(mode,"enforce")`**. Alternatively: **`LoadEvents`** gains **`opts StrictMode`** — default **false** for fuzz tolerance, **true** for report build / CI. |
| 2.2 | `cmd/coldstep-report` (and subpackages) | Wire **strict** mode for **`build-model`**, **`assert-integrity`**, and any command that ingests JSONL for **production** reporting. Fuzz/test-only loaders may stay loose **only** if isolated. |
| 2.3 | Unit tests | Golden JSONL **without** **`enforce`**; add a negative test file with one **`enforce`** line → expect error. |

---

## Phase 3 — Python (`public_scripts`)

| Step | File / area | Change |
| :--- | :---------- | :----- |
| 3.1 | `public_scripts/ci_coldstep_jsonl_traffic_diff.py` | After loading events, if **`strict_mode`** or new env **`COLDSTEP_JSONL_REJECT_LEGACY_ENFORCE=1`**, **fail** when any event has **`mode`** equal to **`enforce`** (case-insensitive). Or always reject when **`COLDSTEP_DIFF_STRICT`** — align with product decision. |
| 3.2 | `public_scripts/coldstep_detect_report/` | Any loader that builds **`report-model.json`** from JSONL: reject **`enforce`** in **`mode`**. |
| 3.3 | Tests | `python -m unittest` modules under **`public_scripts`** — update fixtures. |

---

## Phase 4 — Documentation

| Step | File | Change |
| :--- | :--- | :----- |
| 4.1 | `CHANGELOG.md` | Replace “readers remain tolerant” with **breaking**: legacy **`"mode":"enforce"`** in JSONL is **invalid**; migrate archived files. |
| 4.2 | `README.md` | Remove or rewrite the “Older JSONL files may still show …” paragraph — state **migration required** for old archives. |
| 4.3 | `VALIDATION.md` | Row for **`.coldstep-events.jsonl`**: deny rows **`"mode":"defend"`** only; **`enforce`** rejected. |
| 4.4 | `QUICK_START.md` / **FAQ** | If FAQ mentions legacy JSONL, align. |
| 4.5 | `plans/2026-04-29-drop-enforce-alias-approach-1.md` | Add one-line **erratum** or link to this plan (historical note). |
| 4.6 | Local **`knowledge/`** | Optional synthesis record (gitignored). |

---

## Phase 5 — CI artifacts & baselines

| Step | Action |
| :--- | :----- |
| 5.1 | Search repo **tracked** `*.jsonl`, **`testdata/**`, workflow **baseline artifacts** references — ensure no **`"mode":"enforce"`** remains. |
| 5.2 | Regenerate or patch **baseline JSONL** used by **`COLDSTEP_DIFF_PREV_RUN`** jobs if stored in-repo. |
| 5.3 | Run **`coldstep-ci`**, **`coldstep-demo-detect`**, **`defend-mode`** on a branch before merge. |

---

## Phase 6 — Consumer migration snippet

Document in **CHANGELOG** or **README**:

```bash
# Example: rewrite archived JSONL (review before commit)
rg -l '"mode":\s*"enforce"' . && perl -pi -e 's/"mode"\s*:\s*"enforce"/"mode":"defend"/gi' path/to/file.jsonl
```

(Use **`jq`** / **`python`** if you need JSON-safe rewriting for nested structures.)

---

## Verification checklist

- [ ] `go test ./...` (Linux / Docker per **`AGENTS.md`**) — **`internal/report`**, **`internal/telemetry`**, **`cmd/coldstep-report`**.  
- [ ] `python -m unittest discover -s public_scripts ...`  
- [ ] Grep: **`rg '"mode".*enforce|EqualFold.*enforce'`** in JSONL paths — only intentional **reject** code paths remain.  
- [ ] Docs grep: no “tolerant” / “legacy rows accepted” for JSONL **`mode`**.

---

## Ordering

1. Implement **Go strict validation + digest** (Phases 1–2) + tests.  
2. **Python** + scripts (Phase 3).  
3. **Docs** (Phase 4).  
4. **Baselines + CI** (Phase 5).

Estimated effort: **1–2 PRs** (code + tests first; docs/baselines second) or one PR if small.
