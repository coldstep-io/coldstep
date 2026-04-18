# Multi-runner CI, slim composite, and README badges — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace single-runner PR/`main` CI with six GitHub-hosted Linux labels, a shared callable workflow for fat runners, a slim-only composite action for `ubuntu-slim`, and docs (`README.md`, `AGENTS.md`) that state official support for all six.

**Architecture (as implemented):** **[`.github/workflows/nightstalker-ci.yml`](../../../.github/workflows/nightstalker-ci.yml)** is the **single** entry workflow: **`hosted-linux`** matrix calls **`nightstalker-ci-runner.yml`** on **every** **`pull_request`**, **`push` to `main`**, and **`workflow_dispatch`**, with **`max-parallel`**, **`fail-fast: false`**, and **`use_slim_action`** (`'true'` / `'false'` strings) per row. Fat runners (`use_slim_action: 'false'`) run a job graph equivalent to the old `ci.yml` plus `nightstalker-demo.yml` detect and prevent jobs. Slim (`use_slim_action: 'true'`) runs a single job that executes **`.github/actions/nightstalker-ci-slim`**. **`ci.yml`** is removed; **`nightstalker-demo.yml`** is **`workflow_dispatch`** only. **Tradeoff:** one aggregate workflow badge instead of six per-runner badges.

**Tech stack:** GitHub Actions (`workflow_call`, composite actions), bash, `actions/checkout@v5`, `actions/setup-go@v6`, `actions/setup-node@v5`, existing repo scripts (`scripts/assert_utf8_text.py`, `scripts/build-agent-linux.sh`, `scripts/check-gofmt.sh`, `scripts/ci_nightstalker_jsonl_traffic_diff.py`), composite action `uses: ./`.

**Authoritative spec:** [`docs/superpowers/specs/2026-04-11-multi-runner-ci-and-badges-design.md`](../specs/2026-04-11-multi-runner-ci-and-badges-design.md)

**Developer verification (before push):** Run **`bash scripts/docker-ubuntu-test.sh`** so UTF-8, BPF **`go generate`** (including **`tracefs`**), Go gates, and the npm bundle match the fat **`nightstalker-ci-runner`** path on **`ubuntu:24.04`**. The **six `runs-on` SKUs**, **`ubuntu-slim`** composite, and **detect/prevent** composite steps still require GitHub Actions (or **`workflow_dispatch`** **`nightstalker-demo.yml`** for an extra **`ubuntu-latest`** composite run). Details: **`README.md`** (Local validation) and **`AGENTS.md`**.

---

## File map (create / modify / delete)

| Path | Action | Responsibility |
| :--- | :--- | :--- |
| `.github/workflows/nightstalker-ci-runner.yml` | **Create** | Callable workflow: inputs, fat job graph + slim job branch |
| `.github/workflows/nightstalker-ci.yml` | **Create** | Entry workflow: matrix of `workflow_call` + `concurrency` |
| `.github/workflows/nightstalker-ci-ubuntu-*.yml` | **N/A / removed** | Superseded by `nightstalker-ci.yml` |
| `.github/actions/nightstalker-ci-slim/action.yml` | **Create** | Composite: full CI + detect + enforce in one job |
| `.github/workflows/ci.yml` | **Delete** | Replaced by `nightstalker-ci.yml` + callable |
| `.github/workflows/nightstalker-demo.yml` | **Modify** | Keep jobs; change `on:` to **`workflow_dispatch` only** (remove `push` trigger and path filter) |
| `README.md` | **Modify** | Support matrix, six badges, slim limits, ARM note, example `runs-on` |
| `AGENTS.md` | **Modify** | Six-runner CI as authoritative for merge; Docker flow unchanged |

---

### Task 1: Callable workflow — inputs, env, and slim branch

**Files:**

- Create: `.github/workflows/nightstalker-ci-runner.yml`

- [ ] **Step 1: Add `workflow_call` header and top-level env**

Use this exact skeleton (extend with jobs in Task 2–4):

```yaml
name: nightstalker-ci runner

on:
  workflow_call:
    inputs:
      runner_label:
        description: 'GitHub-hosted runs-on label'
        required: true
        type: string
      use_slim_action:
        description: 'When true, only the slim job runs (composite action)'
        required: true
        type: boolean

env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true

jobs:
  slim:
    if: ${{ inputs.use_slim_action }}
    runs-on: ${{ inputs.runner_label }}
    steps:
      - uses: actions/checkout@v5
      - uses: ./.github/actions/nightstalker-ci-slim
```

- [ ] **Step 2: Confirm YAML**

Run: `python3 scripts/assert_utf8_text.py` (from repo root)  
Expected: exit `0`, no UTF-16 errors.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/nightstalker-ci-runner.yml
git commit -m "ci: add callable nightstalker-ci-runner workflow skeleton"
```

---

### Task 2: Callable workflow — fat jobs mirroring `ci.yml`

**Files:**

- Modify: `.github/workflows/nightstalker-ci-runner.yml`

- [ ] **Step 1: Append four jobs after the `slim` job**, each with:

`if: ${{ !inputs.use_slim_action }}`  
`runs-on: ${{ inputs.runner_label }}`

Copy **step bodies verbatim** from `.github/workflows/ci.yml` (implement Task 2 **before** Task 7 deletes this file):

| New job id | Mirror of `ci.yml` job | Lines to copy (approx.) |
| :--- | :--- | :--- |
| `action_manifest` | `action_manifest` | checkout + `python3 scripts/assert_utf8_text.py` |
| `unit` | `unit` | checkout, setup-go 1.24.x, gofmt, build-agent-linux, vet, staticcheck (`GOTOOLCHAIN: auto`), `go test ./...` |
| `integration` | `integration` | same as unit through staticcheck, then `sudo env "PATH=$PATH" go test -tags=integration ./internal/agent/...` |
| `action_bundle` | `action_bundle` | checkout, setup-node 24, npm cache, `npm ci`, typecheck, build |

Example pattern for `action_manifest`:

```yaml
  action_manifest:
    if: ${{ !inputs.use_slim_action }}
    runs-on: ${{ inputs.runner_label }}
    steps:
      - uses: actions/checkout@v5
      - name: Assert tracked text is UTF-8 (not UTF-16)
        run: python3 scripts/assert_utf8_text.py
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/nightstalker-ci-runner.yml
git commit -m "ci: mirror ci.yml jobs in callable runner workflow"
```

---

### Task 3: Callable workflow — detect job (parity with `nightstalker-demo`)

**Files:**

- Modify: `.github/workflows/nightstalker-ci-runner.yml`

- [ ] **Step 1: Add job `detect-mode`**

`if: ${{ !inputs.use_slim_action }}`  
`runs-on: ${{ inputs.runner_label }}`  
`permissions: actions: read, contents: read`  
`env: NIGHTSTALKER_DIFF_PREV_RUN: '1'`

Copy **all steps** from `nightstalker-demo.yml` job `detect-mode` (lines 28–252 in the current file), starting at `actions/checkout@v5` through `List workspace Nightstalker artifacts`, **unchanged** except:

- Replace the hard-coded summary title line that says `ubuntu-latest` with a dynamic runner label, e.g. use `${{ inputs.runner_label }}` in the heredoc that writes `### Detect Capability Matrix (...)` so the summary is truthful on ARM and 22.04.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/nightstalker-ci-runner.yml
git commit -m "ci: add detect-mode job to callable runner workflow"
```

---

### Task 4: Callable workflow — prevent job

**Files:**

- Modify: `.github/workflows/nightstalker-ci-runner.yml`

- [ ] **Step 1: Add job `prevent-mode`**

`if: ${{ !inputs.use_slim_action }}`  
`runs-on: ${{ inputs.runner_label }}`

Copy **all steps** from `nightstalker-demo.yml` job `prevent-mode` (lines 257–376), unchanged.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/nightstalker-ci-runner.yml
git commit -m "ci: add prevent-mode job to callable runner workflow"
```

---

### Task 5: Slim composite action

**Files:**

- Create: `.github/actions/nightstalker-ci-slim/action.yml`

- [ ] **Step 1: Write composite metadata**

```yaml
name: nightstalker-ci slim
description: Full CI + Nightstalker detect/enforce parity for ubuntu-slim (single job)
runs:
  composite:
    steps: []
```

- [ ] **Step 2: Fill `steps` in this order** (same commands as the fat path; no skipped gates)

1. `run: python3 scripts/assert_utf8_text.py` (shell: bash)
2. `uses: actions/setup-go@v6` with `go-version: '1.24.x'`
3. **Go static + unit block:** `bash scripts/check-gofmt.sh` → `bash scripts/build-agent-linux.sh "$GITHUB_WORKSPACE"` → `go vet ./...` → staticcheck install + run with `GOTOOLCHAIN: auto` (same as `ci.yml` unit job)
4. `run: sudo env "PATH=$PATH" go test -tags=integration ./internal/agent/... -count=1` (after `build-agent-linux.sh` already ran)
5. `uses: actions/setup-node@v5` with `node-version: '24'`, `cache: npm` → `npm ci` → `npm run typecheck` → `npm run build`
6. **Detect phase:** duplicate the detect-mode steps from `nightstalker-demo.yml` **after** Go/npm are green: `uses: ./` with detect inputs (mode, smoke-test-egress, allowed-hosts, feature-gates) → apt nmap → capability probes bash block → SIGTERM stop script → verify script → diff step (needs `permissions` on the **job** in caller; composite cannot set job permissions — set `permissions` on the `slim` job in `nightstalker-ci-runner.yml` to `actions: read, contents: read` alongside checkout) → upload-artifact → list artifacts
7. **Between detect and prevent:** Add a bash step that removes **detect-phase artifacts** so enforce matches a **fresh runner** semantics (fat path uses two jobs on two VMs). Example:

```bash
set -euo pipefail
rm -f "${GITHUB_WORKSPACE}"/.nightstalker-detect.md \
      "${GITHUB_WORKSPACE}"/.nightstalker-events.jsonl \
      "${GITHUB_WORKSPACE}"/.nightstalker-telemetry.json || true
# Ensure no stale agent PID file from the composite action path
ap="${GITHUB_ACTION_PATH:-}"
if [[ -z "${ap}" ]]; then ap="${GITHUB_WORKSPACE}"; fi
rm -f "${ap}/.ci-runtime-guard.pid" || true
```

8. **Prevent phase:** duplicate prevent-mode steps from `nightstalker-demo.yml` in order (UTF-8 assert optional second time; keep `setup-go` if `PATH`/`go` is still valid—usually yes in same job). Re-run `apt-get` for nmap if needed, hosts pins, `uses: ./` enforce, probes, SIGTERM, verify deny, summary, debug grep.

**Caching:** Add `actions/cache` steps before `npm ci` and optionally for Go build cache (`~/.cache/go-build`, `~/go/pkg/mod`) with keys including `runner.os` and hash of `go.sum` / `package-lock.json`.

**Parallelism:** After correctness is proven in serial form, add safe background parallelism (e.g. prefetch) only if wall time threatens the 15-minute cap; measure first.

- [ ] **Step 3: Add job permissions on slim job** (caller file in Task 6)

In `nightstalker-ci-runner.yml` job `slim`, add:

```yaml
    permissions:
      actions: read
      contents: read
    env:
      NIGHTSTALKER_DIFF_PREV_RUN: '1'
```

- [ ] **Step 4: Commit**

```bash
git add .github/actions/nightstalker-ci-slim/action.yml .github/workflows/nightstalker-ci-runner.yml
git commit -m "ci: add slim composite action and wire slim job permissions"
```

---

### Task 6: Entry workflow — matrix (`nightstalker-ci.yml`)

**Files:**

- Create: `.github/workflows/nightstalker-ci.yml` (or six parallel `nightstalker-ci-ubuntu-*.yml` files if you want six badges and six simultaneous pipelines).

- [ ] **Step 1: Add one workflow** with top-level `on:`, `permissions`, `concurrency`, and **one job** using **`strategy.matrix.include`** (six rows) that **`uses:`** the callable workflow with `secrets: inherit` and `with:` `runner_label` + `use_slim_action` as **quoted strings** (`'true'` / `'false'`). Set **`max-parallel`** (e.g. `2`) and **`fail-fast: false`** for queue-friendly DevSecOps defaults.

Skeleton (abbreviated; match repo file for full copy):

```yaml
jobs:
  hosted-linux:
    strategy:
      fail-fast: false
      max-parallel: 2
      matrix:
        include:
          - runner_label: ubuntu-latest
            use_slim_action: 'false'
          # … remaining labels …
    uses: ./.github/workflows/nightstalker-ci-runner.yml
    secrets: inherit
    with:
      runner_label: ${{ matrix.runner_label }}
      use_slim_action: ${{ matrix.use_slim_action }}
```

**Per-row `with` values:**

| `runner_label` | `use_slim_action` |
| :--- | :--- |
| `ubuntu-latest` | `'false'` |
| `ubuntu-24.04` | `'false'` |
| `ubuntu-22.04` | `'false'` |
| `ubuntu-slim` | `'true'` |
| `ubuntu-24.04-arm` | `'false'` |
| `ubuntu-22.04-arm` | `'false'` |

If any step uses `GITHUB_WORKFLOW` for cross-run diffs, confirm it still resolves as intended when all legs share one parent workflow name.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/nightstalker-ci.yml
git commit -m "ci: matrix nightstalker-ci with bounded parallelism"
```

---

### Task 7: Remove `ci.yml` and narrow `nightstalker-demo.yml`

**Files:**

- Delete: `.github/workflows/ci.yml`
- Modify: `.github/workflows/nightstalker-demo.yml`

- [ ] **Step 1: Delete `ci.yml`**

```bash
git rm .github/workflows/ci.yml
```

- [ ] **Step 2: Replace `on:` in `nightstalker-demo.yml`** with:

```yaml
on:
  workflow_dispatch:
```

Remove the `push` / `paths` block entirely.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/nightstalker-demo.yml
git commit -m "ci: remove ci.yml; demo workflow dispatch-only"
```

---

### Task 8: README support matrix and badges

**Files:**

- Modify: `README.md`

- [ ] **Step 1: README CI section** — **One** badge for **`nightstalker-ci.yml`** plus a support table (matrix layout), **or** six per-workflow badges if using six parallel entry workflows.

Use repository `shermanatoor/nightstalker` in URLs (matches current README). Sequential example:

```markdown
[![nightstalker-ci](https://github.com/shermanatoor/nightstalker/actions/workflows/nightstalker-ci.yml/badge.svg)](https://github.com/shermanatoor/nightstalker/actions/workflows/nightstalker-ci.yml)

| Order | `runs-on` | Notes |
| 1 | `ubuntu-latest` | … |
```

Document **`ubuntu-slim`**: 1 vCPU, 5 GiB RAM, **15-minute max job duration**.

- [ ] **Step 2: Rewrite opening paragraph** to state **supported GitHub-hosted labels** are the six in the table (not “latest only”). Keep honest caveats: shared runners, attribution, etc.

- [ ] **Step 3: Update Requirements / workflow example** so `runs-on` documents choosing one of the supported labels.

- [ ] **Step 4: Update references** that say PR gates live in `ci.yml` — point to **`nightstalker-ci.yml`** (and **`nightstalker-ci-runner.yml`**) or the six parallel entry files, depending on which layout you ship.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: README support matrix and per-runner CI badges"
```

---

### Task 9: `AGENTS.md` alignment

**Files:**

- Modify: `AGENTS.md`

- [ ] **Step 1: Replace “ubuntu-latest (amd64) only”** language with: merge gates are the six **required** legs on GitHub-hosted Linux (via **`nightstalker-ci.yml`** + callable, or six parallel entry workflows); state **`ubuntu-slim`** time/resource limits; state ARM labels are **native arm64**.

- [ ] **Step 2: Keep Docker guidance** as the recommended local parity path; clarify it is not a substitute for the multi-runner matrix on GitHub.

- [ ] **Step 3: Commit**

```bash
git add AGENTS.md
git commit -m "docs: AGENTS multi-runner CI authority"
```

---

### Task 10: Verification and branch protection handoff

**Files:**

- None (validate on PR)

- [ ] **Step 1: Push branch and open PR**

Expected: **`nightstalker-ci`** runs six legs in order (or six workflows appear if using parallel entry files); first run may fail on ARM or slim until fixed—iterate.

- [ ] **Step 2: Confirm no duplicate `ubuntu-latest` runs**

In Actions UI, a single PR should **not** show both deleted `ci` and the new **`nightstalker-ci`** graph doing the same `ubuntu-latest` work twice.

- [ ] **Step 3: PR description checklist for repo admin**

Paste:

```markdown
## Branch protection (manual)

After this PR is green, add these required checks for `main` / PRs:

- [ ] Each required check from **`nightstalker-ci.yml`** (top-level job names **and** reusable **`nightstalker-ci-runner.yml`** child job names as GitHub displays them) — or, if using six entry workflows, each file’s jobs plus children.
- [ ] Remove obsolete required checks pointing to deleted `ci.yml` jobs (`unit`, `integration`, etc. from old workflow) if they no longer exist.
```

- [ ] **Step 4: Merge when green**

---

## Plan self-review (spec coverage)

| Spec section | Task(s) |
| :--- | :--- |
| Six runner labels | Task 6 |
| All required on PR | Task 6 triggers + Task 10 branch protection |
| README badges | Task 6 + Task 8 (one aggregate vs six per-runner) |
| Slim one job + composite | Task 1, 5, 6 |
| Parity ci + demo | Tasks 2–5, 5 |
| No duplicate ubuntu-latest | Task 7 |
| nightstalker-demo non-overlapping | Task 7 |
| README + AGENTS | Tasks 8–9 |
| ARM called out | Task 8–9 |
| Risks (15m slim) | Task 5 caching/parallelism + Task 10 |

**Placeholder scan:** None intentional; implementation must paste real YAML from `ci.yml` / `nightstalker-demo.yml` rather than leaving `steps: []` in the composite.

**Gap addressed in plan:** Composite steps cannot set `permissions`; slim job gets `permissions` in Task 5/6.

---

**Plan complete and saved to `docs/superpowers/plans/2026-04-11-multi-runner-ci-and-badges.md`. Two execution options:**

1. **Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration  
2. **Inline execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints  

**Which approach?**
