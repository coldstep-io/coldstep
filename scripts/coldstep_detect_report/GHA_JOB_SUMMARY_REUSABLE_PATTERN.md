# Reusable pattern — GitHub Actions Job Summary (`GITHUB_STEP_SUMMARY`)

This repository uses a **two-tier** reporting model (see `README.md` in this folder). **Pattern D** applies to **Tier-1 only**: a short, reusable contract for what belongs in the Job Summary so every workflow looks professional and consistent.

## What GitHub gives you

- **Surface:** `$GITHUB_STEP_SUMMARY` (append-only file per step; toolkit: `core.summary` → same file).
- **Rendering:** GitHub-flavored Markdown with tables, lists, task lists, collapsible `<details>`, **limited** sanitized HTML, and (when enabled for your org) diagram blocks — **Coldstep Tier-1 deliberately emits BLUF-only text + tables** and **does not rely on Mermaid** in the default path so CI stays predictable (see tests).
- **Budget:** Treat **size and attention** as budgets — stay far below platform limits (~1 MiB/step); prefer **under ~16 KiB** for Coldstep Tier-1 so mobile and PR reviewers load instantly.

## Contract — section order (BLUF)

1. **Title** — One H2, product-scoped (e.g. `## Coldstep detect — summary`).
2. **Run context (optional but recommended)** — One bullet with **repository run URL** built from `GITHUB_SERVER_URL`, `GITHUB_REPOSITORY`, `GITHUB_RUN_ID`; optional job id from `GITHUB_JOB`. Helps humans jump from chat → run.
3. **Triage callout (conditional)** — At most **one** GFM alert block (`> [!WARNING]`) when **any** of:
   - capability / health signals are **fail** (project-specific), or
   - threat-intel summary shows **malicious > 0**.

   **Coldstep omission:** baseline diff **`unavailable`** (e.g. first run with no baseline artifact) is **not** promoted to a triage alert — it is usually expected; the pulse line still carries the reason code.

   Do **not** spam alerts for informational noise.

4. **Pulse bullets (3–6 lines)** — Short quantitative lines with **stable labels** that mirror Tier-2 HTML `<h2>` nouns:
   - Capabilities (pass/warn/fail counts)
   - Baseline diff (ok + counts, or unavailable + reason code)
   - Threat intel / OTX (skipped vs summary counts + optional highest-severity pulse)
5. **Artifact pointer** — Italic line naming the **ZIP artifact** and **`coldstep-detect-report.html`** (or neutral wording for non-detect workflows).

## What never belongs in Tier-1

- Raw JSONL or multi-hundred-row tables (belongs in artifact + Tier-2 HTML).
- Mermaid charts **in Coldstep default Tier-1** (optional for other repos; our unittest forbids regressions).
- Secrets, tokens, full URLs with embedded credentials (redact per AGENTS.md egress policy).

## Pulses vs workflow annotations

| Mechanism | Use for |
| -------- | ------- |
| `$GITHUB_STEP_SUMMARY` markdown | Human-readable triage story, stable metrics, artifact pointer |
| `::notice` / `::warning` / `::error` workflow commands | File/line annotations and filter-bar signals — **not** a duplicate of every pulse row |

## Tier-2 HTML (this repo)

Tier-2 is **not** “pattern D reusable” — it is optimized for **deep forensics**, **Ctrl+F**, and interactive charts. Keep heading text **aligned** with Tier-1 nouns so operators context-switch cleanly.
