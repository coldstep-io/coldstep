# Plan — minimal dependencies (get the job done)

**Goal:** Remove **Python as a dependency of Coldstep itself** — the **composite action path** uses **Go binaries + bash build script + eBPF** only. Downstream workflows may **`pip install`** anything they need; **we do not block or discourage pip** for GitHub Actions users.

**North star:** **Go + bpf/cc + libc/kernel** for runtime; **stdlib Python** only inside **this repository’s own CI** on **`dev`** (and integration branches) for hygiene tests and **`public_scripts`** helpers — **that CI keeps using `python3`** until/unless ported.

---

## Scope boundaries

| Surface | Python |
| ------- | ------ |
| **Consumers** (Marketplace, forks, composite users) | **Not required** to install Python for Coldstep. They may run **`pip install`** for **their** jobs freely — **no policy** to block or forbid pip in documentation or **`action.yml`**. |
| **This repo (`coldstep-io/coldstep`) CI** on **`dev`** | **Continues** to use **`python3`** for **`coldstep-ci-runner`** (`assert_utf8_text.py`, pin checker, **`unittest`** over **`public_scripts`**, etc.). **stdlib-only** for shipped scripts unless the repo explicitly adds a **`requirements.txt`** later. |

Removing Python means: **not** shipping or documenting Coldstep as depending on a Python runtime for **start/stop/report** — **not** deleting Python from **our** CI jobs.

---

## Current baseline (honest)

| Layer | Dependencies | Role |
| ----- | ------------- | ---- |
| **Go** (`go.mod`) | **cilium/ebpf**, **golang.org/x/sys**, **golang.org/x/sync** | Agent, action wrapper, coldstep-report — **keep**; this is already lean. |
| **Python** (`public_scripts/`) | **stdlib only** in tracked helpers (no **`requirements.txt`** today) | **This repo’s CI** only for UTF-8 gate, pin checker, JSONL diff script (until migrated), unittest corpus. |
| **Node** (`package.json`) | **@actions/core**, … | **Not** on the published composite path; **CodeQL** / optional **`dist/`** maintenance. |

---

## Principles

1. **Published Coldstep path:** **`action.yml`** invokes **`bin/coldstep-action`** / **`build-agent-linux.sh`** — **no Python runtime** required for consumers.
2. **Never** document “you cannot **`pip install`** in workflows that use Coldstep” — downstream tooling is their choice.
3. **Prefer porting to Go** for **hot-path** repo workflows (e.g. fingerprint diff → **`coldstep-report`**) to reduce **duplicate** stacks, **without** deleting **`python3`** from **`coldstep-ci-runner`** until parity + maintainer sign-off.
4. **This repo CI on `dev`:** keep **`python -m unittest discover -s public_scripts`** and existing **`python3 public_scripts/...py`** steps unless replaced by Go equivalents in the same PR.

---

## Phased work

### Phase 1 — Freeze unnecessary growth

- **Composite / release:** document **Go-only** runtime for the Action; **do not** add **`pip`**/**`npm`** as **requirements** for using Coldstep.
- **New features:** implement in **Go** under **`cmd/`** / **`internal/`** when they replace Python on the **demo/report** hot path.

**Done when:** **`go.mod`** grows only with justification; consumer-facing **Coldstep** docs never imply **`pip install`** is needed **for Coldstep itself**.

### Phase 2 — Collapse duplicate report/diff (optional; reduces Python on **demo** paths only)

- Migrate JSONL fingerprint diff from **`ci_coldstep_jsonl_traffic_diff.py`** into Go (**`internal/report/model`** + **`coldstep-report`**) so **detect demo workflows** can drop **`python3`** for that step.
- **This repo CI:** either keep Python tests until Go golden tests subsume them, or run both briefly — **`dev`** CI **continues** until green.

**Done when:** Demo jobs don’t need Python **for traffic diff**; **`coldstep-ci-runner`** still passes (unittest may remain Python).

**Status (2026-04):** CI and demo workflows (**`coldstep-ci-runner`**, **`coldstep-demo*.yml`**, **`coldstep-detect-demo-dev.yml`**) already invoke **`./bin/coldstep-report diff`** for previous-run traffic shape comparison. **`coldstep-report build-model`** embeds the same Go **`BuildDiff`** path. Remaining optional work: Python **`build_report_model.py`** still lazy-loads **`ci_coldstep_jsonl_traffic_diff.py`** for parity helpers when running the Python renderer pipeline locally; full fingerprint-string parity with the Python script (traffic/other/unclassified tables) is tracked in **`internal/report/model/builders.go`** comments.

### Phase 3 — Inventory

- Classify **`public_scripts/**/*.py`** as **CI-required** vs **reference-only**; remove dead entrypoints only with proof.

---

## Explicit non-goals

- **Banning `pip install`** on downstream GitHub Actions workflows — **out of scope** and **not** desired.
- **Removing Python from `coldstep-ci.yml` / `coldstep-ci-runner.yml`** on **`dev`** in one shot — only after Go replacements cover the same checks.

---

## Success metrics

| Metric | Target |
| ------ | ------ |
| **`go.mod` direct requires** | Stay minimal; document new deps in PRs. |
| **Coldstep composite** | No Python interpreter required on the runner **for Coldstep steps**. |
| **Consumer workflows** | **No restriction** on **`pip install`** (or other package managers) for **their** steps. |
| **Repo CI (`dev`)** | **`python3`** **continues** for **`public_scripts`** gates + unittest until explicitly migrated. |
| **Detect demo (this repo)** | **Zero** `python3` **only** for **traffic diff** after Phase 2 (optional goal). |

---

## Related

- **[VALIDATION.md](../VALIDATION.md)** — what CI proves.
- **Fingerprint parity:** **`internal/report/model/builders.go`** vs **`public_scripts/ci_coldstep_jsonl_traffic_diff.py`**.
