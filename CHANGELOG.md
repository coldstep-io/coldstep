# Changelog

All notable changes to ColdStep are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

[v0.2.4]: https://github.com/coldstep-io/coldstep/releases/tag/v0.2.4
[v0.2.3]: https://github.com/coldstep-io/coldstep/releases/tag/v0.2.3
[v0.2.2]: https://github.com/coldstep-io/coldstep/releases/tag/v0.2.2
[v0.2.1]: https://github.com/coldstep-io/coldstep/releases/tag/v0.2.1
