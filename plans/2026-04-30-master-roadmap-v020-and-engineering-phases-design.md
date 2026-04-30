# Design — master roadmap: `v0.2.0` release and later engineering phases

**Status:** Approved for execution planning (brainstorming closure).  
**Supersedes:** Nothing — this document **coordinates** existing plans; it does not replace **`RELEASE_PROCESS.md`**, **`VALIDATION.md`**, or detailed plans linked below.

---

## 1. Purpose

Provide a **single ordered program** that addresses the open threads discussed for Coldstep: ship **`v0.2.0`** with **CI truth**, then pursue **dependency consolidation**, **performance discipline**, **backlog hygiene**, and **local knowledge capture** without blocking the release.

---

## 2. Non-goals

- No **new** product requirements for **Phase 1** beyond what **`RELEASE_PROCESS.md`** and existing workflows already imply.
- No **mandatory** CPU or memory optimization targets in any phase — performance work is **visibility-first** (benchmarks / profiling), not arbitrary SLAs.
- No expansion of **`CONTRIBUTING.md`** or **`website/`** for this roadmap unless a phase explicitly lists those paths (owner decision).

---

## 3. Source-of-truth references

| Topic | Authoritative location |
| ----- | --------------------- |
| Pins, tag, release PR steps | **`RELEASE_PROCESS.md`** |
| Mode matrix / honesty limits | **`VALIDATION.md`** |
| Micro-task checklist (`v0.2.0`) | **`plans/2026-04-29-micro-tasks-v020-completion.md`** |
| Consumer Go-only path; optional Go diff | **`plans/2026-04-30-minimal-dependencies.md`** |
| Enhanced detect profile (already largely shipped) | **`plans/2026-04-30-enhanced-detect-method.md`** |
| Validation strategy (CI, Docker for heavy local) | **`AGENTS.md`** |

This design **links** these sources; detailed step lists stay there to avoid drift.

---

## 4. Phase 1 — Release and CI verification

**Intent:** Complete the **`v0.2.0`** track and re-validate critical workflows. **No** Phase 2 engineering (Go traffic diff, benchmarks, milestone-only cleanup) in this phase.

### 4.1 Entry criteria

- Changes intended for **`v0.2.0`** are merged or queued per normal **`dev`** workflow.
- **`coldstep-ci`** (and CodeQL as configured for the branch) are the merge gates.

### 4.2 Exit criteria (all required)

1. **Integration:** PR **`dev` → `main`** merged; **`coldstep-ci`** and CodeQL (if applicable) **green** on the resulting **`main`** state.
2. **Release PR on `main`:** Version pins, **`CHANGELOG.md`** section **`## [0.2.0]`**, and any **`RELEASE_PROCESS.md`** checklist items satisfied; **`website/`** changes **excluded** from this PR unless release policy explicitly includes them.
3. **Tag and attestations:** Signed **`v0.2.0`** tag pushed; **`supply-chain-attest`** workflow verified for that tag (subject to repo/org settings that enable attestations).
4. **`coldstep-detect-demo-dev`:** Outcomes reviewed — digest artifact lifecycle (including **Stop** phase) matches expectations for **`.coldstep-detect.md`**; discrepancies **fixed** or **documented** in **`VALIDATION.md`** with honest limits.
5. **`coldstep-redteam-ebpf`:** Anti-blindness **canaries** present **or** gates/docs adjusted so **`VALIDATION.md`** remains accurate (no silent “all green” when telemetry is blind).
6. **Website pins (if split):** If **`website/index.html`** pins are updated in a **follow-up PR** after the GitHub Release exists, that PR is **merged** **or** Phase 1 closes with an explicit **dated deferral** recorded in **`plans/2026-04-29-micro-tasks-v020-completion.md`** (checkbox and one-line reason).

### 4.3 Phase 1 — out of scope

- Migrating JSONL traffic diff from Python to Go.
- Adding Go **`Benchmark`** tests or perf gates.
- Closing GitHub milestones **#73–#77** except where required to unblock items 1–6.

---

## 5. Phase 2 — Dependency and pipeline engineering

**Intent:** Advance **`plans/2026-04-30-minimal-dependencies.md`** **Phase 2** when maintainers schedule it: move **JSONL fingerprint diff** toward **`coldstep-report` / Go** so detect-oriented workflows can drop Python **for that step**, while **`coldstep-ci-runner`** may retain **`python3`** until parity and sign-off.

### Exit criteria

- Demo/report workflows that today invoke **`public_scripts/ci_coldstep_jsonl_traffic_diff.py`** for diff either call a **Go** equivalent **or** the plan documents the remaining gap with a target date.
- **`go test`** / CI remain green; no consumer-facing requirement to install Python **for Coldstep itself**.

---

## 6. Phase 3 — Performance discipline

**Intent:** Establish **regression visibility** on at least one hot path (e.g. **`coldstep-report`** model build or JSONL ingest), not to maximize throughput.

### Exit criteria

- One **committed** **`Benchmark*`** in **`*_test.go`** **or** a short **documented** recipe (which package, `go test -bench`, optional `pprof`) checked into the repo under **`plans/`** or **`README`** / **`VALIDATION.md`** pointer — **pick one home** in the implementation plan so runners can find it.
- Heavy runs follow **`AGENTS.md`**: **Linux/Docker** for representative profiling, not bare Windows hosts.

---

## 7. Phase 4 — Backlog hygiene and track work

**Intent:** After Phase 1 ship pressure eases, reconcile **GitHub milestones #73–#77** and advance **detect/defend** track plans (**`plans/2026-04-29-coldstep-detect-track.md`**, **`plans/2026-04-29-coldstep-defend-track.md`**) per next **`D`/`F`** items.

### Exit criteria

- Milestones closed, moved, or explicitly wont-fix with a one-line rationale on the milestone or a linked issue.
- Next **`D`/`F`** items either scheduled or deferred with owner.

---

## 8. Phase 5 — Durable memory (local vault)

**Intent:** Capture **what shipped** vs **what stayed optional** in **`knowledge/reports/`** (and hub/index updates per **`knowledge/README.md`**). **Gitignored** — never **`git add knowledge/`**.

### Exit criteria

- At least one short synthesis note exists locally after **`v0.2.0`** tag, linking to **`RELEASE_PROCESS.md`** outcomes and this roadmap.

---

## 9. Risks and mitigations

| Risk | Mitigation |
| ---- | ---------- |
| Attestations or org settings block **`supply-chain-attest`** | Document failure mode in release notes; retry **`workflow_dispatch`** after settings fix — does **not** silently fake attest success. |
| Phase creep (Go diff into Phase 1) | Treat as **process violation**: Phase 1 PRs **only** touch release/CI verification paths. |
| CI flakes on **`main`** | Fix or quarantine per existing CI policy; do not tag until merge gates are trusted. |

---

## 10. Validation and testing

- **Phase 1:** Evidence is **green workflows** on **`main`**, successful tag Run, human sign-off on workflows in §4.2 items 4–5.
- **Later phases:** **`go test`**, **`python -m unittest`** over **`public_scripts`** as today; benchmarks optional in CI (**`coldstep-ci-nightly`** style) if adding bench time to every PR is undesirable.

---

## Self-review (editorial)

- **Placeholders:** None by policy — deferrals must name **`plans/`** or **`VALIDATION.md`** updates.
- **Consistency:** Phase 1 excludes backlog engineering; Phase 2+ references existing minimal-deps plan.
- **Scope:** One roadmap document; implementation splits by phase when **`writing-plans`** runs.
- **Ambiguity resolved:** Website follow-up is Phase 1 **unless** explicitly deferred with dated note in micro-tasks plan.

---

## 11. Execution progress (rolling log)

| Date | Phase | Note |
| ---- | ----- | ---- |
| 2026-04-30 | 2 | Workflows use **`coldstep-report diff`** (Go); see **`plans/2026-04-30-minimal-dependencies.md`** Phase 2 status. |
| 2026-04-30 | 3 | Regression visibility: **`go test -bench=. -benchmem ./internal/report/model`** (see **`builders_bench_test.go`**). |
| 2026-04-30 | 4 | GitHub **issues #73–#77** exist under milestone **`v0.2.0`** (not sequential milestone numbers); triage/close per board. |
| 2026-04-30 | 5 | Copy **`plans/knowledge-capture-template-post-v020.md`** into **`knowledge/reports/`** locally after tag (vault stays gitignored). |
| — | 1 | **PR #78** (`dev` → `main`): merge when checks green; then **`RELEASE_PROCESS.md`** train for **`v0.2.0`**. |
