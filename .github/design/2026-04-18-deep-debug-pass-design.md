# Deep debug pass — design (one-shot run + triage report)

**Status:** Draft for implementation planning  
**Date:** 2026-04-18  
**Scope:** coldstep repository — composite action (Node/TypeScript), Go agent, eBPF build graph, GitHub Actions CI

## 1. Purpose

Define a **repeatable “run everything” pass** that:

1. Executes **locally in Linux Docker** first (reproducible toolchain; avoids relying on bare Windows hosts for compile-heavy work).
2. **Confirms the same commands on GitHub Actions** on the **same commit** when the operator wants authoritative parity with CI runners.
3. Produces **one Markdown triage report**: failures grouped by severity, stage, and suggested follow-up.

This document is **design only**. Implementation (scripts, workflow YAML, optional container image) follows via the **writing-plans** workflow after approval.

## 2. Goals and non-goals

### Goals

- **Stage-aligned checks** mirroring today’s canonical pipelines, primarily **`coldstep-ci-runner.yml`** (including `action_manifest`, `unit`, `integration`, `action_bundle`, and — when enabled — detect/prevent jobs) and optional **`coldstep-ci-nightly.yml`** (govulncheck, shuffle, full-module race).
- **Hybrid failure policy:** within each stage, run **all** checks for that stage (exhaustive inside the stage); **stop before the next stage** when a **P0-class** failure occurs (see §5). Additionally, treat **core unit tests (stage 3a)** as a **hard gate** before expensive optional checks (3b) and full integration-style stages (4), so time is not spent on stress scans when the tree is already red.
- **Explicit parity rule:** CI confirmation should run the **same shell-level commands** as local Docker, preferably by invoking a **single checked-in driver script** (thin CI wrapper may skip Docker-only setup).

### Non-goals

- Replacing PR CI or nightly workflows; this is an **on-demand deep pass**, not a policy change to default CI.
- Guaranteeing **100% local parity** with GitHub-hosted **detect-mode / prevent-mode** jobs that depend on the composite action’s full runtime environment; those remain **CI-authoritative** unless the operator uses a privileged Linux host or accepted emulation.
- Automatically fixing findings (triage only).

## 3. Execution model

### 3.1 Local (Docker)

- **Host:** Linux preferred for BPF-related stages; on Windows, Docker Desktop with Linux containers is the supported path per project norms.
- **Workspace:** Bind-mount the repository root at a fixed path (e.g. `/workspace`) and run all commands from that root, analogous to `$GITHUB_WORKSPACE`.
- **Outputs:** Write logs and the final report under a host-visible directory (e.g. `.coldstep-deep-debug/` at repo root), gitignored or explicitly archived by the operator.

### 3.2 CI confirmation

- Add or use a **`workflow_dispatch`** workflow that runs the **same ordered stages** as the local driver (§6).
- Record the **workflow run URL** and **commit SHA** in the triage report appendix when confirmation is performed.

## 4. Severity and gating (P0 / P1 / P2 / P3)

| Class | Meaning | Gate: stop later stages? |
| ----- | ------- | -------------------------- |
| **P0** | Cannot trust **policy checks**, **TypeScript bundle**, or **BPF/Go codegen + mandatory static gates** (stages 0–2). | **Yes** — do not run stage 3+. |
| **P1** | **Tests**, **race**, **integration** failures (stages 3–4 core). | Stop **3b** and **4** if **3a** failed; overall run still **failed**. |
| **P2** | Static hygiene / linters already covered in P0 path where CI treats them as hard failures; optional reporting-only checks if introduced later. | Per stage policy. |
| **P3** | Informational / flaky environmental notes (e.g. kernel-dependent verifier variance without a clear bug). | No automatic gate. |

**Hybrid rule (user-selected):** exhaustive within a stage; between stages, **do not proceed past P0 failure**. **Stage 3a** (core unit tests) is a **practical gate** before **3b** (nightly-style) and **stage 4** (integration / composite-style), even though test failures are classified **P1** in the report.

## 5. Stage taxonomy (ordered)

Stages map to existing jobs so operators can mentally align with Actions tabs.

| Stage | Name | Aligns with (conceptually) | Typical contents |
| ----- | ---- | ---------------------------- | ---------------- |
| **0** | Repo hygiene / action manifest | `action_manifest` | `scripts/assert_utf8_text.py`, `scripts/check_workflow_action_pins.py`, `python3 -m unittest discover -s scripts`, `scripts/test_workflow_diff_markers.sh` |
| **1** | TypeScript action bundle | `action_bundle` | `npm ci`, `npm run typecheck`, `npm run build` (Node **24**) |
| **2** | Go/BPF codegen + static | `unit` / `integration` preamble | `scripts/check-gofmt.sh`, `scripts/build-agent-linux.sh "$PWD"`, `go vet ./...`, `staticcheck ./...` (pinned **v0.7.0** as in CI) |
| **3a** | Core tests | `unit` core | `go test ./... -count=1`, `go test -race -count=1 ./internal/agent/... -timeout 15m` |
| **3b** | Expensive / nightly-style (optional toggles) | `coldstep-ci-nightly.yml` | `go test ./... -count=1 -shuffle=on`, `govulncheck ./...`, optional **full-module** `go test -race ./...` (manual-only in nightly today) |
| **4** | Integration / sudo / composite realism | `integration`, `detect-mode`, `prevent-mode` | `sudo env "PATH=$PATH" go test -tags=integration ./internal/agent/...`; full composite jobs **primarily on CI** |

### Local vs CI for stage 4

- **Integration tests** (`sudo`, BPF attach): run locally only in a container with sufficient **capabilities** (often `--privileged` on Linux) and a compatible kernel; otherwise mark **skipped / CI-only** in the report with reason.
- **Detect/prevent workflow jobs:** treat as **CI confirmation** unless the project later adds a supported local harness.

## 6. Docker image and toolchain

Minimum alignment with **`coldstep-ci-runner.yml`**:

- **Go:** `1.24.x`, `GOTOOLCHAIN=auto` where used.
- **Node:** **24** (matches `action.yml` / workflows).
- **System packages:** everything required by **`scripts/build-agent-linux.sh`** (e.g. clang, llvm, libbpf, bpftool, linux headers, build essentials — exact list owned by implementation, derived from that script and CI images).

**Privileged mode:** document two **local profiles**:

1. **Standard:** stages 0–3a (and 3b if desired) without composite jobs.
2. **Privileged:** attempt stage 4 integration tests when the operator opts in and the host supports BPF in Docker.

## 7. CI confirmation wiring

- **Recommended:** one driver script in-repo, e.g. `scripts/deep-debug.sh`, run locally inside Docker; **`scripts/deep-debug-ci.sh`** or the workflow invokes the same stages with `bash` so YAML does not drift.
- **Workflow:** `workflow_dispatch` with boolean inputs mirroring nightly toggles (shuffle, govulncheck, full race) and optional “stop after stage X” for partial runs.

## 8. Triage report template

Single Markdown file, suggested sections:

1. **Metadata:** UTC timestamp, `git rev-parse HEAD`, Docker image id/tag, kernel uname (if relevant), optional CI run URL.
2. **Summary:** PASS/FAIL, first failing **stage**, counts by **P0–P3**.
3. **Per-stage table:** stage id, commands (summary), status, link/path to **log snippet**.
4. **Findings:** bullet list sorted **P0 → P3**, each with **file/command hint** and **next action**.
5. **CI confirmation:** SHA match note when workflow dispatch was used.

## 9. Repository constraints

- **`/docs/`**, **`/knowledge/`**, **`/specs/`** are **gitignored** in this repository; design artifacts intended for Git live under **`.github/design/`** (this file) or another **tracked** path chosen by maintainers.

## 10. Implementation transition

After this design is approved, use **writing-plans** to produce an implementation plan: scripts, optional Dockerfile or documented base image, `workflow_dispatch` YAML, gitignore entries for `.coldstep-deep-debug/`, and documentation pointers (without expanding `CONTRIBUTING.md` unless explicitly requested).
