# Multi-runner CI, slim composite action, and README badges

**Status:** Approved design (brainstorming session 2026-04-11).  
**Scope:** GitHub Actions workflows, one repo-local composite action for `ubuntu-slim`, README and `AGENTS.md` alignment. **No** product feature work beyond what existing CI and `nightstalker-demo` already validate.

## 1. Goals

- Run the **same substantive validation** the repo already defines (`ci.yml` gates plus `nightstalker-demo.yml`-equivalent detect and enforce evidence) on **six** GitHub-hosted Linux labels:
  - `ubuntu-latest`
  - `ubuntu-24.04`
  - `ubuntu-22.04`
  - `ubuntu-slim`
  - `ubuntu-24.04-arm`
  - `ubuntu-22.04-arm`
- Treat all six as **officially supported** when checks are green: README and agent-facing docs **must** match that stance (replacing “`ubuntu-latest` (amd64) only”).
- **Every** workflow check that gates merge is **required** on pull requests (repository settings; not expressible in YAML alone).
- **README:** a **support matrix** for all six labels. **Badges:** either **one** native GitHub workflow badge for **[`nightstalker-ci.yml`](../../../.github/workflows/nightstalker-ci.yml)** (matrix + bounded `max-parallel`—aggregate pass/fail) **or** six parallel entry workflows (six badges, six simultaneous pipelines). This repo ships a **single entry workflow** with a **matrix** and **`max-parallel`** to cap concurrent heavy legs while staying idiomatic GitHub Actions.
- **`ubuntu-slim`:** **one** top-level job per PR/push, **no** intentional reduction of validation compared to fat runners; **slim-specific orchestration** (caching, ordering, safe in-step parallelism) lives in a **dedicated repo-local composite action** (e.g. `.github/actions/nightstalker-ci-slim`).

## 2. Non-goals

- Supporting self-hosted runners, macOS, Windows, or non-GitHub images.
- Changing BPF feature semantics beyond what current scripts and workflows already test.
- Using third-party badge services for per-runner status (native badges only).

## 3. Architecture

### 3.1 Reusable workflow

Add a **callable** workflow (suggested path: `.github/workflows/nightstalker-ci-runner.yml`) with `on: workflow_call` and inputs, at minimum:

| Input | Type | Purpose |
| :--- | :--- | :--- |
| `runner_label` | string | Value for `runs-on` for every job in this callable that targets the caller’s runner SKU. |
| `use_slim_action` | string (`'true'` / `'false'`) | Callers pass quoted strings. `true` only for the slim leg: emit a **single** job that runs the full suite via the slim composite action. `false` for all other legs: emit the **multi-job** graph (mirror of current `ci.yml` job split, plus demo-equivalent jobs). |

Callers pass `secrets: inherit` where any step needs `github.token` or other inherited secrets (e.g. demo or future reporting).

### 3.2 Entry workflow (triggers + matrix legs)

**Shipped layout:** **[`.github/workflows/nightstalker-ci.yml`](../../../.github/workflows/nightstalker-ci.yml)** defines `on: pull_request` + `push` to `main` + `workflow_dispatch`, **`permissions`** (`contents: read`, `actions: read` for `gh` where needed), **`concurrency`** on `nightstalker-ci-${{ github.ref }}` with **`cancel-in-progress: true`**, and a **six-row matrix** on **all** triggers with **`max-parallel`** and **`fail-fast: false`**.

| Job (example id) | `runner_label` | `use_slim_action` |
| :--- | :--- | :--- |
| `runner-ubuntu-latest` | `ubuntu-latest` | `'false'` |
| `runner-ubuntu-24-04` | `ubuntu-24.04` | `'false'` |
| `runner-ubuntu-22-04` | `ubuntu-22.04` | `'false'` |
| `runner-ubuntu-slim` | `ubuntu-slim` | `'true'` |
| `runner-ubuntu-24-04-arm` | `ubuntu-24.04-arm` | `'false'` |
| `runner-ubuntu-22-04-arm` | `ubuntu-22.04-arm` | `'false'` |

**Alternative (not used here):** six thin workflow files (one per runner) for **six** native `badge.svg` URLs and **six** parallel pipelines per PR.

**Badge URL (single entry workflow):** One workflow badge for `nightstalker-ci.yml`, e.g.  
`https://github.com/<org>/<repo>/actions/workflows/nightstalker-ci.yml/badge.svg`.

### 3.3 Slim-only composite action

**Path (suggested):** `.github/actions/nightstalker-ci-slim/action.yml`  
**Type:** `composite` (`runs: composite`).

**Responsibilities:**

- Run the **union** of checks that the fat reusable graph runs for one PR revision: UTF-8 assert, Go setup, `build-agent-linux.sh`, `gofmt` check, `go vet`, `staticcheck` (with `GOTOOLCHAIN=auto` as today), `go test ./...`, sudo integration tests (`-tags=integration` on the same package set as `ci.yml`), `npm ci` / `npm run typecheck` / `npm run build`, then the **detect** and **enforce** phases that match **`nightstalker-demo.yml`** (including **SIGTERM** before reading digest, **IPv4-pinned** probes where the demo already pins, `/etc/hosts` pinning where the demo does, and grep-based assertions on JSONL and digest—same **evidence bar**, not a weaker smoke).
- Encapsulate **slim-only** tuning: cache keys and restore/save for Go and npm, and **safe** in-step parallelism (e.g. background steps with explicit `wait`) where it reduces wall time without skipping gates.

**Constraints:**

- Composite steps run in **one** job; GitHub’s **`ubuntu-slim` 15-minute maximum job duration** still applies to the **entire** job. The composite does **not** extend the limit.
- If, after caching and parallelism, the job still **exceeds 15 minutes** reliably, that is a **project risk** to resolve by optimization or by revisiting scope in a follow-up change—not by silently dropping checks.

### 3.4 Fat runners (non-slim)

The callable workflow with `use_slim_action: false` should mirror **job-level parallelism** similar to **`ci.yml`** today:

- `action_manifest` (UTF-8 script)
- `unit` (gofmt, build-agent-linux, vet, staticcheck, unit tests)
- `integration` (keep the same **split** as `ci.yml` today: separate job, same commands, including repeated `build-agent-linux.sh` if that is what current CI does)
- `action_bundle` (Node 24, npm ci, typecheck, build)
- Demo-equivalent jobs: at least **detect** and **enforce** flows equivalent to `nightstalker-demo.yml` (may be two jobs or one job with ordered steps, provided **SIGTERM** ordering and artifact/summary behavior remain correct)

Use `needs:` only where a strict ordering is required (e.g. build before integration if ever split across jobs; today many steps repeat `build-agent-linux.sh` per job—preserving that is acceptable for parity with current CI).

## 4. Parity definition

**Definition of “same substantive validation”:**

1. **Go / BPF / static:** Same scripts and commands as `.github/workflows/ci.yml` for manifest, format, `build-agent-linux.sh`, vet, staticcheck, unit tests, and root integration tests under `sudo` with `-tags=integration`.
2. **Action bundle:** Same npm commands as `ci.yml` `action_bundle` job (Node major aligned with GitHub-hosted defaults, currently 24).
3. **End-to-end action usage:** Same composite action (`uses: ./`) and behavioral assertions as `nightstalker-demo.yml` for **detect** and **enforce** (including post-step summary behavior where asserted today).

**ARM runners:** Builds and BPF objects target **native arm64** on the runner (`bpf2go` big-endian path is not exercised on these hosts). README should state **arm64** explicitly for the two ARM labels.

## 5. Migration and deduplication

- **Remove or collapse** `.github/workflows/ci.yml` once the new graph is live, so **`ubuntu-latest` is not executed twice** per PR (either delete `ci.yml` or replace its body with a single job that calls the same reusable workflow with `runner_label: ubuntu-latest` and `use_slim_action: false`).
- **`nightstalker-demo.yml`:** Avoid overlapping **`pull_request`** (and default-branch **`push`**) triggers with the new required set. Preferred: **fold** demo jobs into the callable workflow for **all** runners and restrict `nightstalker-demo.yml` to **`workflow_dispatch`** only if a separate manual demo is still desired; otherwise **delete** after parity is verified.

## 6. README and `AGENTS.md`

- **README:** Replace single-badge / single-runner support language with a **support matrix table** (runner, one-line description, badge, link to workflow file). Document **`ubuntu-slim`** resource limits and the **15-minute** job cap factually. Update the “Use in a workflow” example to show **`runs-on`** as a choice from the supported matrix (not only `ubuntu-latest`). Document **`bash scripts/docker-ubuntu-test.sh`** as the **pre-push** local loop (same BPF **`go generate`** set as **`build-agent-linux.sh`**, including **`tracefs`**) and list what still **requires GitHub-hosted runners** (six-way matrix, slim composite, detect/prevent **`uses: ./`** jobs).
- **`AGENTS.md`:** Update “validate on `ubuntu-latest` only” to describe the **six-runner** required CI and that **`docker-ubuntu-test.sh`** is the preferred local substitute before push; clarify which workflows are authoritative for merge and which checks are **GitHub-only** (matrix SKUs, slim path, live composite detect/prevent).

## 7. Branch protection (manual)

After the first successful runs, repository administrators must add **all** new required check names to branch protection for `main` (and PRs). Job display names come from the **caller + reusable** job graph; exact strings appear in the GitHub UI after one run.

## 8. Risks and acceptance

| Risk | Mitigation |
| :--- | :--- |
| `ubuntu-slim` exceeds 15 minutes | Aggressive caching; in-step parallelism in the slim composite; measure on real runners; if still failing, treat as a **blocking** engineering issue (not silent test removal). |
| ARM kernel / BTF / verifier variance | Runner-specific triage; do not disable checks without an explicit product decision. |
| Duplicate billing / queue time | **Matrix + `max-parallel`:** caps concurrent pipelines per PR ref while still exercising all SKUs in one workflow run. Six-file layout would run up to six pipelines in parallel with no cap unless each file sets concurrency. |
| `runs-on` label drift | Re-verify labels against GitHub documentation at implementation time. |

**Acceptance:** All six legs green on `main` and on pull requests (within **`nightstalker-ci`**); README and `AGENTS.md` describe the orchestrator + callable runner; no duplicate `ubuntu-latest` CI; aggregate badge reflects overall pass/fail.

## 9. Implementation follow-up

After this spec is reviewed and approved in the repo process, create an implementation plan using the **writing-plans** skill (concrete PR steps: add callable + composite + **orchestrator** `nightstalker-ci.yml`, migrate/remove old workflows, README + `AGENTS.md`, branch-protection checklist in PR description).
