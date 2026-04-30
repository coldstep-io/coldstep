# Sprints — PR readiness (`dev` → `main`)

**Goal:** One coherent PR (**#78** or successor) with **green CI**, signed commits, and documentation aligned with **`RELEASE_PROCESS.md`** when cutting **`v0.2.0`** separately.

---

## Sprint 1 — Enhanced detect profile (ship code)

| Task | Status |
| ---- | ------ |
| Composite **`detect-profile`** + **`COLDSTEP_DETECT_PROFILE`** (`action.yml`, **`coldstep-action`**) | ✅ |
| **`mergeEnhancedFeatureGates`** + **`DetectProfile`** on **`internal/config.Config`** | ✅ |
| **`coldstep-report build-model`** reads profile → **`integrity.EvaluateForDetectProfile`** | ✅ |
| **`MetaEvent.DetectProfile`**, agent **`BuildMeta`**, digest KPI, **`render-summary` / `render-html`** | ✅ |
| **`README.md`** / **`VALIDATION.md`** consumer-vs-CI clarity + **`detect-profile`** row | ✅ |
| **`internal/report/digest_test`** KPI coverage | ✅ |

**Exit:** `go test` passes on packages touched (Linux CI authoritative).

---

## Sprint 2 — Repo hygiene

| Task | Status |
| ---- | ------ |
| **`/.gitignore`** — ignore root **`ARCHITECTURE.md`** (local-only notes) | ✅ |
| Add **`plans/2026-04-30-enhanced-detect-method.md`** so **`VALIDATION.md`** link resolves | ✅ |

---

## Sprint 3 — Merge gate (human)

| Task | Owner |
| ---- | ----- |
| Wait for **PR #78** checks green (CodeQL, **`coldstep-ci`**) | CI |
| Mark PR **ready for review**, merge **`dev` → `main`** when approved | Maintainer |
| **`RELEASE_PROCESS.md`** release PR + **`v0.2.0`** tag + attest | Maintainer |

---

## References

- **`plans/2026-04-30-master-roadmap-v020-and-engineering-phases-design.md`**
- **`RELEASE_PROCESS.md`**
