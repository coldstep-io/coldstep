# Validation scope — what we prove in automation

This document is the **honest contract** between documentation and **automated checks**. It supports the phased roadmap (validation first, then UX, then hardening): consumers know what **GitHub Actions + Go tests** actually exercise versus what still depends on **your runner**, **your workflow**, or **manual** review.

**Primary CI graph:** [`.github/workflows/coldstep-ci.yml`](.github/workflows/coldstep-ci.yml) calls [`.github/workflows/coldstep-ci-runner.yml`](.github/workflows/coldstep-ci-runner.yml).

---

## Runner and version scope (v1)

| Topic | Position |
| ----- | -------- |
| **Supported label for egress agent jobs in CI** | **`ubuntu-latest`** (x64) for **`detect-mode`** and **`defend-mode`** jobs. **`defend-mode`** runs the composite with **`mode: defend`** (blocking egress); **`enforce`** remains an alias for the same mode in `with:` and **`CI_GUARD_MODE`**. |
| **Multi-distro matrix** | **`unit`**, **`unit-arm64`**, **`integration`** run on additional Ubuntu LTS / arm64 labels to stress **build + Go tests**, not a second full egress integration matrix for every OS. |
| **IPv6 egress enforcement** | **Out of scope for v1** — do not infer IPv6 guarantees from this repo’s BPF surfaces. |
| **Self-hosted / custom kernels** | **Not covered** by the same CI guarantees; treat as integration work in **your** environment. |

**Allowlist file inputs** (`allowed-domains-file`, etc.): composite merges workspace text files with inline `with:` strings in **`coldstep-action`**; paths are rejected if they resolve outside **`GITHUB_WORKSPACE`**. Merge behavior is covered by **`go test ./cmd/coldstep-action/...`**; end-to-end enforce with files is the same agent path as inline strings once merged.

**`bootstrap-allowlist`:** opt-in merge of vendored **`public_scripts/coldstep_bootstrap/*.txt`** (see **QUICK_START**). **Not** a live third-party API in v1.

---

## Mode capability matrix

| Capability | `mode: detect` | `mode: defend` (`enforce` alias) |
| ---------- | -------------- | ---------------- |
| **Egress observation (IPv4-focused telemetry)** | Yes — observe and record. | Yes — plus **block** non-allowlisted IPv4 egress per design. |
| **Allowlist required** | No. | Yes — non-empty effective policy (domains → IPv4 **A** records + literals / CIDR policy); invalid/empty effective allowlist **fails startup**. |
| **`.coldstep-events.jsonl`** | Yes. | Yes. |
| **Digest / shutdown markdown** | Yes (when enabled). | Yes. |
| **`fail-on-error` on start/stop** | Fails step if **operational readiness** (e.g. `.coldstep-ready.json` **ok:true**) is not achieved within the wait — **not** “fail because an attacker tried bad egress.” | Same readiness semantics; **blocking** is separate from step exit code (see [`action.yml`](action.yml) descriptions). |

---

## What automated validation proves

| Layer | What runs | What it demonstrates |
| ----- | --------- | -------------------- |
| **Policy / parsing** | Go tests under **`internal/policy/`** | Allowlist and policy parsing behave as coded for covered cases. |
| **Agent (Linux)** | **`go test ./...`**, **`go test -tags=integration ./internal/agent/...`** (with **`sudo`** in CI) | Large classes of agent behavior and BPF attach paths **on CI Linux**, subject to each test’s assertions. |
| **`action_manifest`** | UTF-8 gate, workflow pin checker, **`public_scripts`** unittest, shell markers | Repo hygiene and workflow guardrails — **not** the eBPF runtime itself. |
| **`action_bundle`** | Builds **`bin/coldstep`**, **`coldstep-action`**, **`coldstep-report`** | Shipping composite binaries exist after **`build-agent-linux.sh`**. |
| **`detect-mode`** job | Real **`uses: ./`** composite **detect**, probes (nmap/curl/UDP/fs, etc.), **`coldstep-report build-model`**, **`assert-integrity`** (when strict) | **End-to-end detect path** on **`ubuntu-latest`**: agent → JSONL → report model → integrity gate. |
| **`defend-mode`** job (defend mode) | Real composite **`mode: defend`**, allowed + denied curl/`nc` checks, JSONL **`deny`** assertions **when deny rows appear** | **Defend** (blocking) behavior for **scripted** allow/deny scenarios on **`ubuntu-latest`**. If no deny lines appear (runner variance), the workflow **warns** by default. **`workflow_dispatch`** on **`coldstep-ci`** can set **`defend_deny_jsonl_strict: true`** to **fail** the job when no deny JSONL rows are present (stricter operator guardrail). |

**Nightly / manual workflows** (e.g. **`coldstep-ci-nightly`**) add supply-chain and deeper Go checks; they extend confidence in **tooling and tests**, not a duplicate “full egress proof” matrix unless explicitly described there.

---

## What is *not* proven here

- **Security audit** or **red-team certification** of the agent — CI proves **regressions** on maintained scenarios, not universal non-bypassability.
- **Lossless telemetry** under all load — design assumes **best-effort** streams; extreme rates can drop or summarize events.
- **Every README sentence** as a formal guarantee — only behaviors with a **test or workflow assertion** (or explicit scope table above) are “proven” in the automation sense.

---

## How to reproduce proof yourself

1. Open a PR (or run **`workflow_dispatch`** on **`coldstep-ci`** with ref **`dev`** / your branch) and inspect the **`coldstep-ci`** run.
2. Run **`workflow_dispatch`** on **`coldstep-demo`**, **`coldstep-demo-detect`**, or **`coldstep-demo-enforce`** on a fork for full demo graphs.
3. For release binaries and SBOMs, see **`supply-chain-attest.yml`** and **`RELEASE_PROCESS.md`**.

---

## Roadmap alignment (high level)

| Phase | Focus |
| ----- | ----- |
| **1** | Honest CI matrix (this document). |
| **2** | **Allowlist file inputs** + optional **`bootstrap-allowlist`** (vendored packs) — no live third-party API in v1. |
| **3** | **Stricter optional CI** (`defend_deny_jsonl_strict` on **`coldstep-ci`** `workflow_dispatch`); **README** minimal deploy path; **`package.json`** description for legacy Node bundle; further hardening is incremental. |

Brainstorming artifacts: local HTML mocks (`*mockup*.html`) and optional **Visual Companion** — **`public_scripts/brainstorm_visual_companion/`** (see **`README.md`** there).
