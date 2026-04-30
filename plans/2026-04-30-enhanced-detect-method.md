# Plan — enhanced detect method

**Intent:** Add an **enhanced detect** path that improves **observability, integrity signals, and operator confidence** in **`mode: detect`** — **without** blocking egress and **without** per-application deny lists (explicit **non-goal**).

**Relationship to defend:** **Defend** remains the only **blocking** mode. Enhanced detect is **observe-only**, stricter or richer than “default detect” where configured.

---

## Non-goals

- **No application-level egress deny lists** (not pursuing process/`comm`-based block rules).
- **No new blocking semantics** inside detect — any “fail the job” behavior is **CI policy** (e.g. integrity gate), not kernel-level block.

---

## What “enhanced detect” can mean (pick / combine in implementation)

| Axis | Idea | Notes |
| ---- | ---- | ----- |
| **A. Profile input** | Composite input e.g. **`detect-profile: standard \| enhanced`** (or env **`COLDSTEP_DETECT_PROFILE`**) | Maps to agent + report behavior; default **`standard`** preserves today’s behavior. |
| **B. Feature gates bundle** | Enhanced turns on a documented set of **`feature-gates`** (e.g. proc tree, TLS SNI, fs events) so runs are **comparable** run-over-run | Avoid ad-hoc gates per workflow; document in **README** / **QUICK_START**. |
| **C. Integrity tier** | Stricter **anti-blindness** expectations for enhanced (required event types / canaries) surfaced in **`report-model`** and **`assert-integrity`** | May reuse existing evaluator with a **stricter ruleset** flag from profile. |
| **D. Signal density** | Optional extra summary sections or markers (job summary / digest) for enhanced only — **no** new external deps | Implement in **`coldstep-report`** + templates when needed. |
| **E. Baseline drift** | Treat **previous-run JSONL diff** as **first-class** when profile is enhanced (already partially wired on demos) | Ensure **`coldstep-report`** path covers diff without Python once migrated. |

---

## Implementation status (partial)

1. **`detect-profile`** composite input (`standard` \| `enhanced`), **`COLDSTEP_DETECT_PROFILE`** for agent + **`coldstep-report build-model`** — shipped in **`action.yml`**, **`cmd/coldstep-action`**, **`internal/config`** (`mergeEnhancedFeatureGates`), **`README`**.
2. **Enhanced** merges **`proc_tree`**, **`tls_sni`**, **`fs_events`** when each key is absent; explicit **`feature-gates`** override per key.
3. **`coldstep-report build-model`** reads **`COLDSTEP_DETECT_PROFILE`** and calls **`integrity.EvaluateForDetectProfile`** (stricter required JSONL types for **enhanced**).
4. **`coldstep-ci-runner`** **`detect-mode`** job uses **`detect-profile: enhanced`** and sets **`COLDSTEP_DETECT_PROFILE`** on **`build-model`**.

**Remaining (optional):** Tier-1 summary markers dedicated to enhanced; migrate traffic diff fully to Go (**minimal-dependencies** plan).

---

## Validation

- **`go test`** + existing integration tests; **detect** job remains **non-blocking** at the kernel.
- **`assert-integrity`** (or successor) behavior documented in **[VALIDATION.md](../VALIDATION.md)** when enhanced profile tightens gates.

---

## Related

- **[VALIDATION.md](../VALIDATION.md)** — mode matrix and what CI proves.
- **Minimal dependencies:** **[2026-04-30-minimal-dependencies.md](2026-04-30-minimal-dependencies.md)**.
