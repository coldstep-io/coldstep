# Plan — Drop `enforce` consumer alias (**Approach 1: single-release hard cut**)

**Design (vault):** `knowledge/reports/2026-04-29-drop-enforce-alias-design.md`  
**Implementation checklist (vault):** `knowledge/reports/2026-04-29-drop-enforce-alias-implementation-plan.md`  
**Date:** 2026-04-29  
**Status:** Implemented on **`dev`** (Approach 1 — single-release hard cut). Reader-facing docs iterated through **README / QUICK_START / VALIDATION / CHANGELOG** (see **Documentation delivered** below).

---

## What Approach 1 is

One coordinated change that **rejects** the string **`enforce`** anywhere **consumers** set mode:

- GitHub Action **`with: mode:`**
- Environment **`CI_GUARD_MODE`**
- **`coldstep-action`** mode normalization (flags / env passthrough)
- **TypeScript** composite: stop remapping **`defend` → `enforce`** before spawning the agent; pass **`defend`** through so **`CI_GUARD_MODE`** matches the product vocabulary.

**Internal** Go type **`ModeEnforce`**, BPF object names, and similar **implementation** identifiers **stay** for this release (optional rename = separate effort).

**Historical data:** JSONL / digest **read** paths may still interpret legacy **`"mode":"enforce"`** in old files; **new** runs must not require consumers to use **`enforce`**.

**Versioning:** Treat as a **breaking** change; document in **CHANGELOG** and bump consumer pin guidance (semver per project policy for pre-1.0 / post-1.0).

**Git:** Per current preference — **one commit when the full plan is done and verified**, not incremental WIP commits (unless the user asks for a checkpoint).

---

## Invariants (do not violate)

| Invariant | Detail |
| --------- | ------ |
| Two product modes | **`detect`** \| **`defend`** only at boundaries. |
| Blocking path | **`defend`** → **`ModeEnforce`** in **`LoadFromEnv`** remains the internal mapping. |
| No third mode | Do not reintroduce **`enforce`** as an accepted **input** spelling. |
| Read vs write | Tolerant **read** of old **`enforce`** in telemetry/digest; **inputs** strict. |

---

## Execution order (minimize broken intermediate states)

Land in this sequence so no layer expects **`CI_GUARD_MODE=enforce`** after Go strictness while TS still sends it:

1. **Go `internal/config`** — reject raw **`enforce`**; tests use **`defend`** for blocking.
2. **Go `cmd/coldstep-action`** — **`normalizeCompositeMode`** rejects **`enforce`**.
3. **`src/main.ts`** — validate **`mode`** input; remove **`defend`→`enforce`** remap; **`CI_GUARD_MODE`** is **`detect`** or **`defend`**.
4. **`npm run build`** — refresh **`dist/main`** / **`dist/post`** if applicable.
5. **`action.yml`** — **`mode`** description: no legacy alias; point to **`defend`**.
6. **`.github/workflows`** — replace **`mode: enforce`** with **`mode: defend`** everywhere in-repo.
7. **Docs + skills + CHANGELOG** — breaking note + migration table (`enforce` → **`defend`**).
8. **Telemetry audit** — grep **`internal/agent`**, **`internal/report`** for **emitted** JSONL **`mode`**; ensure **new** writes use **defend**-aligned labels; keep **`digest.go`** tolerant reads for **`enforce`** where needed.
9. **Verification** — Go tests (Linux/Docker per repo policy), Python **`public_scripts`** tests as in CI, **`npm`** checks if any.

---

## Task breakdown

### A — Go configuration

| ID | Task |
| -- | ---- |
| G1 | **`internal/config/config.go`**: Remove **`enforce`** from accepted **`CI_GUARD_MODE`** values; empty → detect; **`defend`** → **`ModeEnforce`**. |
| G2 | Error messages: only **`detect`** / **`defend`** (no legacy wording). |
| G3 | **`internal/config/config_test.go`**: Migrate **`enforce`** fixtures to **`defend`**; add **`enforce`** rejected test. |

### B — coldstep-action CLI wrapper

| ID | Task |
| -- | ---- |
| W1 | **`normalizeCompositeMode`**: **`detect`** \| **`defend`** only; **`enforce`** → error. |
| W2 | **`main_test.go`** (and related): align expectations + rejection case. |

### C — Composite TypeScript

| ID | Task |
| -- | ---- |
| T1 | **`src/main.ts`**: Explicit failure if input **`mode`** is **`enforce`** (clear message). |
| T2 | Remove **`defend` → `enforce`** assignment before **`CI_GUARD_MODE`**. |
| T3 | Comments / log lines: “enforce mode” → **defend** / blocking where user-facing. |
| T4 | **`npm run build`**; stage generated **`dist/`** with sources. |

### D — Action metadata & CI consumers

| ID | Task |
| -- | ---- |
| Y1 | **`action.yml`**: **`mode`** input docs updated. |
| Y2 | Workflow YAML grep: **`mode: defend`** for blocking demos; fix **`coldstep-ci`**, **`coldstep-demo`**, **`demo-enforce`**, etc. |
| Y3 | *Optional follow-up:* rename **`coldstep-demo-enforce.yml`** → **`coldstep-demo-defend.yml`** + references (can defer to reduce churn). |

### E — Documentation & harness

| ID | Task |
| -- | ---- |
| D1 | **README**, **QUICK_START**, **VALIDATION**, **SECURITY** — migration one-liner + remove alias narrative. |
| D2 | **CHANGELOG [Unreleased]** — **Breaking** subsection + table. |
| D3 | **`skills/coldstep-defend-track`** (and detect cross-refs) — inputs are **`defend`** only. |

### F — Digest / JSONL contract

| ID | Task |
| -- | ---- |
| J1 | **`digest.go`** **`isBlockingDigestMode`** / **`digestModeCell`**: keep legacy **`enforce`** recognition for **reading** old rows. |
| J2 | Confirm **emit** paths in agent/report output **`defend`** (or consistent policy) for new runs. |

---

## Done criteria

- [x] No accepted **`enforce`** string at composite / env / wrapper entrypoints.
- [x] **CHANGELOG** documents breaking change and migration (plus reader-facing tables).
- [x] Single signed commit(s) on **`dev`** implementing removal + follow-up **docs** commit (At a glance, QUICK_START two modes, VALIDATION how-to-read).
- [ ] Full **Go config tests** / Linux CI green (authoritative on **`ubuntu-latest`**; Windows skips `internal/config` tests by build tag).

## Documentation delivered (iteration complete)

| Doc | What readers get |
| --- | ---------------- |
| **README** | **At a glance** tables, migration **Before/After**, deduped OTX + deep-debug, **Modes and outputs** cross-link. |
| **QUICK_START** | **Two modes** section; **`coldstep-demo-enforce.yml`** explained as legacy filename. |
| **VALIDATION** | **How to read this page** numbered list. |
| **CHANGELOG** | **Breaking** + **Migration** table + links to README / QUICK_START anchors. |

---

## Out of scope (Approach 1)

- Renaming **`ModeEnforce`**, **`trace_enforce.bpf.c`**, packages — track separately.
- **Website** / Marketplace pin bump until after release tag (per release process).

---

## Post-merge housekeeping (vault)

Update **`knowledge/wiki/track-skills-research-loop`** or **`knowledge/records/`** with “shipped” note when the breaking release is tagged, so the brain matches the repo.
