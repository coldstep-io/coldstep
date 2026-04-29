# Changelog

Notable changes to Coldstep follow this file. Releases are tagged as `v*.*.*` ([compare on GitHub](https://github.com/coldstep-io/coldstep/compare)).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

**Consumer / workflow pin target (next tag after `v0.1.7`):** `v0.2.0` — documentation, demo workflows, and the pin checker align on this version until the tag is published (then ship via **`RELEASE_PROCESS.md`**). Until **`v0.2.0`** exists on GitHub, **`gh release download v0.2.0`** and **`uses: coldstep-io/coldstep@v0.2.0`** in manually dispatched workflows will fail; use **`v0.1.7`** for soak runs until the release is cut.

### Breaking

- **`mode: enforce`** and **`CI_GUARD_MODE=enforce`** are **removed**. Use **`defend`** for blocking egress. Historical JSONL/digest rows may still contain legacy **`"mode":"enforce"`** strings; readers remain tolerant for old artifacts.

**Migration (copy/paste)**

| Location | Change |
| :------- | :----- |
| Composite `with:` | `mode: enforce` → **`mode: defend`** |
| Job `env:` | `CI_GUARD_MODE: enforce` → **`CI_GUARD_MODE: defend`** |

Docs: **[README — At a glance](README.md#at-a-glance)** · **[Quick Start — Two modes](QUICK_START.md#two-modes-read-this-first)**.

### `v0.2.0` track (implemented on `dev`; tag pending)

- **Composite + Go:** `action.yml` runs **`bin/coldstep-action`** (built by **`public_scripts/build-agent-linux.sh`** when needed); no Node **`main`/`post`** for the published path.
- **Two-phase lifecycle:** `phase: start` before workload steps; `phase: stop` at job tail (`if: always()`) to flush digest and optional notifications.
- **Detect reporting on demo workflows:** **`coldstep-demo-detect`** (and related paths) invoke **`bin/coldstep-report`** subcommands instead of Python entrypoints.
- **Supply-chain release bundle:** **`supply-chain-attest`** ships **`action.yml`**, Go binaries, and **`build-agent-linux.sh`** (not JS **`dist/`** as the primary artifact).
- **`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24`:** not required for Coldstep; optional only for other JavaScript actions in the same job.
- **CI maintenance scripts:** **`coldstep-ci`** still runs **`public_scripts`** Python (UTF-8 assert, workflow pin checker, unit tests for diff/pins). That is guardrail coverage for tracked helpers, not the composite runtime.

### Migration note

Existing single-step workflows that relied on JS `post` hooks must add an explicit second `uses:` invocation with `phase: stop`.

### Added

- **Track skills + plans (agent harness):** expert manager skills **`skills/coldstep-detect-track`** and **`skills/coldstep-defend-track`**, with living plans **`plans/2026-04-29-coldstep-detect-track.md`** and **`plans/2026-04-29-coldstep-defend-track.md`**; see **`skills/README.md`** to symlink into **`.cursor/skills/`** (default Cursor path; **`.cursor/`** is gitignored).
- **`VALIDATION.md`** — Honest matrix of detect vs defend capabilities, CI job coverage (**`detect-mode`**, **`defend-mode`**, unit/integration), and explicit non-goals; linked from **README**, **QUICK_START**, and **CONTRIBUTING**.
- **Allowlist file inputs** — **`action.yml`**: `allowed-domains-file`, `allowed-hosts-file`, `allowed-ips-file`, `ignored-ip-nets-file` (comma-separated paths under **`GITHUB_WORKSPACE`**). **`coldstep-action`** reads files and merges with inline allowlist strings; see **QUICK_START** and **VALIDATION.md**.
- **`bootstrap-allowlist`** — default **`false`**. When **`true`**, merges vendored **`public_scripts/coldstep_bootstrap/allowlist-{domains,ips}-v1.txt`** after other merges. Included in **`supply-chain-attest`** bundle tarball; **`LICENSE.md`** inventory updated.

### Changed

- **Telemetry / digest:** JSONL **`deny`** rows and the markdown digest now report **`mode":"defend`** / **Defend mode** for blocking runs (legacy **`enforce`** strings remain accepted when parsing digest inputs).
- **Composite blocking mode:** Product modes are **`detect`** and **`defend`** only. **`enforce`** is no longer accepted as an input spelling (use **`defend`**).
- **CI — defend mode naming + optional strict deny JSONL telemetry:** integration jobs are **`defend-mode`**. **`workflow_dispatch`** input **`defend_deny_jsonl_strict`** (default **false**) and env **`COLDSTEP_DEFEND_DENY_JSONL_STRICT`** pass through **`coldstep-ci-runner`** so **`defend-mode`** can **fail** when no **`deny`** JSONL rows appear (default remains variance-tolerant warn-only).
- **Documentation / hygiene (Phase 3):** **`package.json`** `description` for legacy Node bundle; **CONTRIBUTING** allowlist + **`package.json`** notes; **VALIDATION.md** roadmap and **`defend-mode`** strict option.

---

## [0.1.7] — 2026-04-20

**Pre-release** — pin alignment only (no Go agent, BPF, or composite TypeScript changes in this PR). Documentation, website, **`public_scripts/check_workflow_action_pins.py`**, Marketplace demo, and **`COLDSTEP_AGENT_VERSION`** on **`coldstep-demo*`** workflows now target **`v0.1.7`**.

### Publishing this pre-release

1. Merge the release PR to **`main`**.
2. **`git tag -s v0.1.7 -m "…"`** and **`git push origin v0.1.7`** — triggers **`supply-chain-attest`** (binary + SBOM + attestations).
3. **GitHub → Releases → v0.1.7 → Edit** — enable **Set as pre-release** until soak tests pass; attach notes from **`CHANGELOG`**. Clear pre-release when promoting to **Latest**.

---

## [0.1.6] — 2026-04-20

Re-dock the **recommended consumer tag** and in-repo demo **`COLDSTEP_AGENT_VERSION`** to **`v0.1.6`**. No application or eBPF changes in this bump—documentation, website, workflows, and the workflow pin checker only.

### Why publish **v0.1.6**

GitHub Releases can be **immutable**. If **`v0.1.5`** was finalized before **`supply-chain-attest`** uploaded **`coldstep-linux-amd64`**, later upload attempts could return **HTTP 422**. **`main`** now continues the workflow in that situation so attestations and downloadable artifacts still publish (change shipped after **PR #47**). Pin **`coldstep-io/coldstep@v0.1.6`** (or a newer tag) for new installs, then **create tag `v0.1.6`** and run **`supply-chain-attest`** (tag push or **`workflow_dispatch`**) so the Release and binary line up.

### Changed (0.1.5)

- README, QUICK_START, CONTRIBUTING, website, **`public_scripts/check_workflow_action_pins.py`**, **`coldstep-demo-marketplace.yml`**, and demo workflows (**`COLDSTEP_AGENT_VERSION`**) use **`v0.1.6`**.

---

## [0.1.5] — 2026-04-19

Detect-mode reporting matured with a two-tier pipeline (Tier-1 GitHub Actions step summary + Tier-2 offline HTML artifact), AlienVault OTX enrichment with incremental schema upgrades, tighter security hardening across helpers, and sustained eBPF/agent/CI reliability work. Documentation and consumer pins consistently reference **`coldstep-io/coldstep@v0.1.5`**.

### Added

- **Detect-mode report pipeline (PR #29):** `report-model.json` builder (`build_report_model.py`), Tier-1 GFM/Mermaid step summary (`render_step_summary.py`), Tier-2 self-contained **`report.html`** (`render_html_report.py`, templates, pinned Plot/d3 vendors with SRI); designer-handoff README under `public_scripts/coldstep_detect_report/README.md`.
- **OTX threat-intel enrichment (PR #30, extended in PR #43):** `public_scripts/coldstep_otx/` — client, verdicts (`malicious` / `clean` / `unidentified`), confidence tiers (schema **v2.1**), integration in `coldstep-demo-detect` with optional `secrets.OTX_API_KEY` and skip when unset.
- **Reverse DNS enrichment:** `public_scripts/coldstep_dns/` (`rdns.py`, `enrich_rdns.py`) wired into the detect report flow.
- **Job Summary / digest — triage-first output:** `internal/report/digest.go` and summary rendering emphasize IR-style triage (ribbon, collapsed technical detail, hot egress) for faster review; aligned Python/GFM tier (release train).
- **CI coverage:** Multi-distro matrix (ubuntu LTS x64 + arm), `coldstep-ci-nightly` (govulncheck, shuffle, optional race), **`coldstep-deep-debug`** + `Dockerfile.deep-debug` / helper scripts for staged deep triage.
- **Workflow guardrails:** `public_scripts/check_workflow_action_pins.py` + CI hook; shell markers test for JSONL diff summaries.
- **`supply-chain-attest`:** Continued publishing of **`coldstep-linux-amd64`** on matching tags (consumer demos align `COLDSTEP_AGENT_VERSION`).
- **`coldstep-demo-marketplace.yml`:** Minimal Marketplace-style consumer workflow.

### Changed

- **Consumer pins:** README, QUICK_START, CONTRIBUTING, website, and demo workflows pin **`@v0.1.5`** (replacing **`@v0.1.4`** guidance).
- **Composite action (`action.yml`, `src/main.ts`, `src/post.ts`):** Fail-fast readiness polling with extended bounded waits for BPF verifier latency; clearer stderr capture; ordering fixes so **`ok:true`** reflects syscall trace attachment in enforce mode; reduced noisy IPv6 probe step in fail-on-error path.
- **Agent (`internal/agent/*`):** Readiness/status file semantics (**0644**), syscall trace vs optional BPF ordering, ringbuf/exec lifecycle cleanup, policy allowlist merge behavior with DNS-derived literals, richer ring-buffer drop telemetry for digests.
- **Policy / enforce:** IPv4-centric allowlist compilation; **compile-time IPv6 cgroup hooks for enforce mode removed** — **breaking** for workflows that relied on IPv6 enforcement on GitHub-hosted runners (IPv4-only v1 scope documented).
- **eBPF (`bpf/`, generated loaders):** UDP `sendmsg` observability paths; multi-iovec counters; syscall coverage and visibility counters; LPM trie for CIDR allowlists (vs HASH-only literals); portability and **Ubuntu 22.04 verifier** fixes (bounded `probe_read_user` paths, single-read msghdr/sockaddr patterns); cgroup attach helpers; ABI `_Static_assert` / wire-size pairing with Go.
- **Telemetry:** Query-sensitive URI sanitization (`sanitize_request_uri`), Slack token shape redaction, Copilot autofix alignment in tests.
- **JSONL traffic diff (`ci_coldstep_jsonl_traffic_diff.py`):** Stricter decode health, configurable strictness via workflow inputs, baseline resolution improvements for PRs (**`GITHUB_HEAD_REF`**).
- **Dependencies:** `esbuild` / `typescript` bumps; `golang.org/x/sync`; `actions/cache@v5`, `actions/upload-pages-artifact@v5` where applicable; `LICENSE.md` inventory touch-up.
- **`dist/`:** Regenerated bundles for composite `main`/`post` (large diff; review source in `src/`).

### Fixed

- **Security (path & output):** Sanitized `COLDSTEP_REPORT_MODEL_IN` in rDNS enricher and related helpers (PR #37–#38); broad Snyk/CodeQL-driven fixes across detect/diff helpers, HTML/XSS-oriented hardening in report rendering, `.snyk` policy for vendored **dist** noise (PR #36, #40).
- **Code review remediation (PR #42):** Escaping/HTML generation fixes (including `{{ GENERATED_AT }}` handling), sanitizer parity, bounded job-related timeouts.
- **CI / workflows:** JSONL baseline lookup fallback (`coldstep-ci.yml` + `main`); Tier-1 detect summary ordering after baseline diff (#44); demo install probes aligned with runtime preflight; race fixes in defend-mode tests and BPF wait paths.
- **BPF verifier / probes:** Constant-size userspace reads for TLS/DNS/UDP paths across 5.15–6.x kernels used on GitHub runners.

### Security

- Documented **GitHub Actions threat model and consumer mitigations** in **`SECURITY.md`** (including outbound OTX when API keys are configured).
- Reduced sensitive material in telemetry URIs while preserving triage-relevant host/path signal.

---

## [0.1.4] — 2026-04-14

Baseline for comparison with **0.1.5**. Highlights included publishing **`coldstep-linux-amd64`** from release-tag workflows, pinning consumer docs to **`@v0.1.4`**, and demo workflows consuming the prebuilt GitHub Release binary where applicable.

See [comparison **v0.1.4…v0.1.5**](https://github.com/coldstep-io/coldstep/compare/v0.1.4...v0.1.5).

[Unreleased]: https://github.com/coldstep-io/coldstep/compare/v0.1.7...HEAD
[0.1.7]: https://github.com/coldstep-io/coldstep/releases/tag/v0.1.7
[0.1.6]: https://github.com/coldstep-io/coldstep/releases/tag/v0.1.6
[0.1.5]: https://github.com/coldstep-io/coldstep/releases/tag/v0.1.5
[0.1.4]: https://github.com/coldstep-io/coldstep/releases/tag/v0.1.4
