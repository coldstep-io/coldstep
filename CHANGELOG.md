# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.3] - 2026-05-17

### Fixed

- **Action bundle / release pin:** `0.2.2`'s `src/shared.ts` left `COLDSTEP_BINARY_VERSION` at `v0.2.1` and `COLDSTEP_BINARY_SHA256` at the v0.2.1 asset's hash, so consumers pinning `coldstep-io/coldstep@v0.2.2` either downloaded the wrong binary or hit `coldstep: downloaded binary sha256 mismatch` from the cgroup-root-attach build that was actually shipped on the v0.2.2 release. `0.2.3` re-aligns the constants with the published `v0.2.3` release asset and rebuilds `dist/{pre,main,post}/index.js`. **Action behavior is otherwise identical to v0.2.2.**

## [0.2.2] - 2026-05-17

### Removed (breaking)

- **`action.yml` inputs:** deprecated allowlist / report / feature-gate aliases removed. Consumers must migrate before the next tag:
  - `allowed-domains`, `allowed-domains-file`, `allowed-hosts`, `allowed-hosts-file`, `allowed-ips`, `allowed-ips-file` → unified **`allow`** / **`allow-file`** (entries auto-classify into domains, wildcard hosts, IPv4 literals/CIDRs).
  - `ignored-ip-nets`, `ignored-ip-nets-file` → **`ignored-nets`** / **`ignored-nets-file`**.
  - `report-job-summary`, `report-pr-summary` → unified **`report`** (`job-summary` | `pr-comment` | `both` | `none`).
  - `feature-gates` → **`detect-profile`** (`enhanced` enables `proc_tree=1,tls_sni=1,fs_events=1`).
- **`phase:`** input kept (internal). In-repo CI workflows still use it because **`uses: ./`** does not fire node24 pre/post hooks; consumer workflows pin a published tag and use a single `uses:` block.

### Changed

- **Internal config enum:** `config.ModeEnforce` renamed to `config.ModeDefend`; underlying string value also changed from `"enforce"` to `"defend"` so the in-memory enum matches the public surface. `internal/report/digest.go` keeps accepting legacy `"enforce"` JSONL/digest for replay.
- **BPF generators:** the five per-package `run_bpf2go.go` wrappers under `internal/bpf/{traceconnect,tracedns,tracefs,tracebpfaudit,tracelsmenforce}/` collapsed into one shared helper at `internal/bpf/bpfgen/main.go`. Each `gen.go` now reads `//go:generate go run ../bpfgen/main.go <Target> <source>.bpf.c`.

### Added

- **Integration:** **`TestRun_TLSClientHelloPwriteJSONL`** exercises **`tls_sni=1`** on **`os.pwrite`** (**`NR_PWRITE64`**) after **`connect`**, asserting **`type:tls`** and **SNI** (synthetic ClientHello, same shape as sendto coverage).
- **Integration:** **`TestRun_TLSClientHelloSendtoSockaddrJSONL`** exercises **`tls_sni=1`** on **TCP `sendto` with explicit `sockaddr`** after **`connect`**, asserting **`type:tls`** and **SNI** (parity with HTTP cleartext **sendto** coverage).
- **`.github/pr-bodies/`** — tracked UTF-8 templates for **`gh pr create` / `gh pr edit --body-file`** so PR descriptions are not corrupted by shell quoting (especially PowerShell); **`scripts/gh-pr-body.ps1`** wraps **`gh pr edit --body-file`** on Windows.
- **Optional `.pre-commit-config.yaml`** — runs **`scripts/check-encoding.sh`** on **`pre-commit install`** (same guard as CI **`gofmt`** job).

### Changed

- **BPF build:** **`scripts/ensure_vmlinux_int_typedefs.py`** runs from **`scripts/build-agent-linux.sh`** after **`bpf/vmlinux.h`** is present — repairs **`bpftool btf dump format c`** output when kernel BTF places integer typedefs after forward refs (fixes **`clang`** **`unknown type name '__u8'`** on GitHub-hosted kernels). Detection keys off the **`typedef signed char __s8`** / **`typedef unsigned char __u8`** pair immediately after the **`__VMLINUX_H__`** preamble (not a substring scan).
- **BPF (comments):** **`trace_connect.bpf.c`** file header no longer contains a **`pwrite*`** + **`/sendto`** sequence that closed the block comment early (**`*/`**) and broke **`clang`** (spurious **`sendto`** token) on CI.
- **BPF:** Removed unused **`note_unobserved_egress_syscall`** (**`-Werror,-Wunused-function`** on **`clang`** after **`pwrite*`** dispatch stopped calling it).
- **BPF (detect telemetry):** **`pwrite(2)`/`pwritev`/`pwritev2`** use the same TLS ClientHello sniff path as **`write`/`writev`** (first three syscall args match; **`NR_PWRITE64`/`PWRITEV`/`PWRITEV2`** in **`trace_tls_write.inc`**); no longer counted only as **`unobserved_egress_syscalls_observed`**.
- **BPF (detect telemetry):** **TLS ClientHello / SNI** sniffing mirrors the HTTP **`sendto`+sockaddr** path on **`NR_SENDTO`**: when **`addr_ul`** is populated and matches the **`connect`** destination, the first handshake-shaped buffer still runs **`try_emit_tls_clienthello`** (best-effort, same **`connect4_tuple`** layout).
- **BPF (defend enforcement):** **cgroup/LSM enforce** helpers shared via **`bpf/enforce_policy.inc`** (**`enforce_lpm_key.h`** for forward **LPM** key types); **`trace_enforce`** and **`trace_lsm_enforce`** stay behavior-equivalent while deduplicating deny/allowlist plumbing.

### Fixed

- **Defend mode cgroup attach:** BPF programs now attach to the cgroup v2 root (**`/sys/fs/cgroup`**) instead of the agent's own sub-cgroup. On GitHub-hosted runners the agent (launched via **`sudo`**) lands in a different cgroup than the job steps, so the previous sub-cgroup attach left all job traffic unprotected. Attaching to the root covers all descendant cgroups (PR **#122**).
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
