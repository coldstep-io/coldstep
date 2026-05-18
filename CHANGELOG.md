# Changelog

All notable changes to ColdStep are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

---

## [v0.2.5] — 2026-05-18

### Added
- **HTTP/1 sniff parity for write(2) family** — plaintext HTTP/1 requests on dport 80 are now captured when emitted via `write(2)`, `writev(2)`, `pwrite64(2)`, `pwritev(2)`, or `pwritev2(2)` on a connected TCP socket. Previously only the `sendto(2)` arm produced `http_events`; Go `net/http`, libcurl over plain HTTP, and most stdlib HTTP clients use `write(2)` and were silently missing from the HTTP JSONL stream. The new dispatch helper fetches the (tgid,fd) tuple once and runs both the TLS-ClientHello sniff and the HTTP/80 sniff from a single LRU lookup, keeping the verifier budget flat. (BG-04)

### Changed
- **Detect digest redesign** — the `.coldstep-detect.md` / Job Summary digest now leads with a one-line headline status badge (🚨 Alert / ⚠️ Review / ✅ Clean run), surfaces the hot-egress table before the triage ribbon, reorders the KPI table to network → process → fs → health with ringbuf-reserve and multi-iovec rows directly under their parent metric, and collapses the long-form KPI prose / standalone BPF hook table / Footnotes block into a single `<details>` "Technical details" fold plus a small Run info table. ⚠️ (with VS-16) is now used consistently for warning rows. Pure presentation change; no `DigestInput` / `telemetry.Summary` shape change, no agent or BPF code touched. (#149)
- refactor: consolidate four `*EmptyReason` digest helpers into `protocolEmptyReason`.
- **BPF telemetry — per-syscall partial-observe counters (BG-01).** Replaced the dead aggregate `unobserved_egress_syscalls_observed` ARRAY (no increment sites since the pwrite* sniff arms were added; always read 0) with a 4-slot `partial_egress_observed` PERCPU_ARRAY. Slots: `sendfile`/`sendfile64`, `splice`, and `sendmmsg` (first-message-only). The digest, triage ribbon, and telemetry JSON now surface each path independently (`sendfile_observed`, `splice_observed`, `sendmmsg_first_only`) so operators can see *which* syscall drove the visibility gap instead of a single total. Existing sniff paths are unchanged.
- **BG-02: bounded multi-iovec sniff** — When `writev`/`pwritev`/`pwritev2` is called with `vlen >= 2`, or `sendmsg`/`sendmmsg` is called with `msg_iovlen >= 2`, the BPF agent now performs a single additional bounded `bpf_probe_read_user` of `iov[1]` and feeds it through the existing TLS ClientHello and HTTP request fingerprint helpers. Previously only `iov[0]` was inspected, and any TLS/HTTP content fragmented into `iov[1]` (e.g. header-then-body framing) was silently dropped from `tls_events` / `http_events`. Strictly capped at index 1 — no unlimited iov walk. The `tls_writev_multi_iovec_observed` and `udp_sendmsg_multi_iovec_observed` counters continue to fire so the historical fragmentation-rate metric stays comparable.
- BG-03: `sendmmsg_multi_message_observed` counter tracks NR_SENDMMSG calls with vlen>1 (separate from multi-iovec counter)

---

## [v0.2.4] — 2025-05-16

### Fixed
- **cgroup root-attach** — BPF programs now attach to `/sys/fs/cgroup` (the cgroup v2 unified-hierarchy root) instead of a sub-cgroup derived from `/proc/self/cgroup`. On GitHub-hosted `ubuntu-latest` runners, job-step processes run in sibling or parent cgroups relative to the coldstep agent (which executes via `sudo`). Attaching to a sub-cgroup left those steps unprotected — the root cause of defend-mode blocking zero connections despite BPF programs loading successfully. Fixes #122.

### Changed
- **Runtime SHA256 verification** — removed the hardcoded `COLDSTEP_BINARY_SHA256` constant from `src/shared.ts`. Go binaries are not reproducible across CI runs, so a hardcoded SHA drifted after every `supply-chain-attest` build. The pre-step now fetches the expected digest at runtime from the GitHub Releases API (`asset.digest` on `GET /repos/coldstep-io/coldstep/releases/tags/{version}`), eliminating the mismatch cycle.

### Verified
- Defend-mode lab: 0 of 3 attack simulations reached the signal server (env exfil, DNS exfil, credential scan — all blocked).

---

## [v0.2.3] — 2025-05-15

### Notes
- Intermediate release tag. Binary predates the cgroup root-attach fix; dist bundles carried a stale SHA. Use v0.2.4.

---

## [v0.2.2] — 2025-05-14

### Notes
- Intermediate release tag. Dist bundles pointed at wrong SHA. Use v0.2.4.

---

## [v0.2.1] — 2025-04-30

### Added
- Initial public release.
- Linux eBPF agent with eight BPF probe packages: `traceexec`, `tracefork`, `traceconnect`, `tracedefend`, `tracelsmdefend`, `tracedns`, `tracefs`, `tracebpfaudit`.
- Two runtime modes: `detect` (observe-only telemetry) and `defend` (cgroup `connect4`/`sendmsg4` + BPF LSM `socket_connect`/`socket_sendmsg` for IPv4 egress blocking). The spelling `enforce` is explicitly rejected at startup.
- `coldstep-action` binary (`start`/`stop`) for composite Action lifecycle management.
- `coldstep-report` post-run pipeline: `build-model`, `assert-integrity`, `render-summary`, `render-html`, `diff`, `rdns-enrich`, `otx-enrich`, `render-ip-summary`.
- Workspace artifacts: `.coldstep-events.jsonl` (append-only event stream), `.coldstep-detect.md` (Markdown shutdown digest), `.coldstep-telemetry.json` (BPF health totals), `.coldstep-ready.json` (readiness probe).
- Optional AlienVault OTX enrichment for detect HTML reports when `OTX_API_KEY` is set; skipped silently when unset.
- Composite GitHub Action (`action.yml`) with inputs: `mode`, `allow`, `allow-file`, `detect-profile`, `report`, `fail-on-error`, `signing-key`, `log-level`, `ignored-nets[-file]`, `bootstrap-allowlist`, `ready-timeout-seconds`, `github-token`.
- CI gates: `gofmt`, encoding scan, unit tests (amd64 + arm64 matrix), integration tests (root + BPF), action bundle, detect-mode and defend-mode lab runs.
- BPF C unit tests (`bpf/host_test/`) via `scripts/run-bpf-c-unit-tests.sh`.
- `COLDSTEP_DETECT_PROFILE=enhanced` enables `proc_tree`, `tls_sni`, and `fs_events` streams by default.

---

[v0.2.5]: https://github.com/coldstep-io/coldstep/releases/tag/v0.2.5
[v0.2.4]: https://github.com/coldstep-io/coldstep/releases/tag/v0.2.4
[v0.2.3]: https://github.com/coldstep-io/coldstep/releases/tag/v0.2.3
[v0.2.2]: https://github.com/coldstep-io/coldstep/releases/tag/v0.2.2
[v0.2.1]: https://github.com/coldstep-io/coldstep/releases/tag/v0.2.1
