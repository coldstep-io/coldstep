# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **`.github/pr-bodies/`** — tracked UTF-8 templates for **`gh pr create` / `gh pr edit --body-file`** so PR descriptions are not corrupted by shell quoting (especially PowerShell); **`scripts/gh-pr-body.ps1`** wraps **`gh pr edit --body-file`** on Windows.
- **Optional `.pre-commit-config.yaml`** — runs **`scripts/check-encoding.sh`** on **`pre-commit install`** (same guard as CI **`gofmt`** job).

### Fixed

- **`scripts/check-encoding.sh`:** CI now also fails on UTF-8 **U+FFFD** replacement bytes (**`EF BF BD`**) in tracked sources (catches corrupt Unicode / paste damage).
- **`coldstep-demo`:** defend-mode verification matches **`coldstep-ci-runner`** deny-JSONL variance rules (warn when absent unless **`COLDSTEP_DEFEND_DENY_JSONL_STRICT=1`**). Detect-mode: **`smoke-test-egress`**, OpenSSL **`s_client`** probes, longer TLS settle/retry, and digest fallback when **`tls`** JSONL is delayed but the Markdown digest still shows TLS context.
- **BPF audit canary (CI):** defer **`raw_tp/sys_enter (bpf audit)`** attach until after fork/fs BPF loads so startup **`bpf(2)`** bursts do not fill the audit ringbuf before **`readBPFAuditRing`** runs (restores **`bpftool`** JSONL canaries on **`coldstep-redteam-ebpf`**).
- **`coldstep-redteam-ebpf`:** run **`apt-get`** before **`phase: start`** so package installs do not exhaust the fs-event JSONL cap before the intentional **`chmod`** probe; add OpenSSL TLS probe, longer post-probe settle, and explicit **`bpftool`** path.
- **Workflows:** `actions/upload-artifact@v4` → **`@v6`** everywhere it was pinned (native Node 24; clears deprecation warnings when **`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24`** is set).

---

## [0.2.1] - 2026-05-02

### Fixed

- **Release packaging:** Patch train so **`coldstep-linux-amd64`** is the supported downloadable artifact for demos (`gh release download`). Prefer tagging **`v0.2.1`** after **[supply-chain-attest](https://github.com/coldstep-io/coldstep/actions/workflows/supply-chain-attest.yml)** succeeds so the Release is created or updated with the binary (avoid empty immutable Releases that block uploads).

### Changed

- Consumer pins, **`COLDSTEP_AGENT_VERSION`**, **`website/`**, and **`scripts/check_workflow_action_pins.py`** target **`v0.2.1`**.
- **`supply-chain-attest`:** if GitHub rejects uploads (**immutable release**) and the Release still has **zero assets**, the workflow **fails** with a clear error instead of succeeding silently (demo jobs would otherwise hit **`no assets to download`**).

---

## [0.2.0] - 2026-05-02

### Added

- Encoding hygiene CI guard (`scripts/check-encoding.sh`) for tracked text sources.
- `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` on workflows that use JavaScript actions alongside the composite (align with hosted runner Node defaults).

### Fixed

- Composite post-step: UTF-8-safe truncation in Go and surrogate-aware line caps in TypeScript; PR summary HTTP uses `AbortController` so timeouts cancel in-flight requests (avoids duplicate PR comments).
- Workflows: invalid `actions/upload-artifact@v7` references corrected to `@v4`.
- Demo / red-team workflows: `COLDSTEP_AGENT_VERSION` matches published GitHub Releases that ship **`coldstep-linux-amd64`**.

### Changed

- Consumer documentation and **`website/`** examples pin **`coldstep-io/coldstep@v0.2.0`** (superseded by **v0.2.1** for download + pin alignment).

---

## [0.1.7] - 2026-04-19

Maintenance and packaging improvements on the v0.1 train; see [GitHub Releases](https://github.com/coldstep-io/coldstep/releases) for assets and notes.
