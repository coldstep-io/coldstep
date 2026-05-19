## Summary

Release train for **v0.2.6**. Promotes `CHANGELOG.md [Unreleased]` to `[v0.2.6]` (2026-05-19), bumps every consumer-pin surface to v0.2.6 (`coldstep-io/coldstep@v0.2.6`, `COLDSTEP_AGENT_VERSION: v0.2.6`, `MARKETPLACE_COLDSTEP_TAG`), bumps internal binary version constants (`src/shared.ts` `COLDSTEP_BINARY_VERSION`, `cmd/coldstep-report/build_model.go` `buildVersion`), and rebuilds the `dist/` bundles.

Per `RELEASE_PROCESS.md`, this is the **repo + CI** train. `website/index.html` stays at v0.2.5 in this PR and gets bumped in a separate follow-up PR after the tag is on Releases (consumer-pin standard: never advertise an unpublished tag on the site).

### v0.2.6 highlights

**Security (P0 / P1 / P2):**

- **P2-1 IPv6 Phase 2 — defend enforces** (#164). Non-loopback IPv6 egress is now blocked by an `allowed_ipv6` LPM trie populated from AAAA resolutions; `cgroup/connect6`/`sendmsg6` deny on miss. `::1` and `fe80::/10` bypass enforcement. AAAA-only services are now valid defend allowlist entries.
- **P1-1 DNS allowlist trust model** (#159). Compile-time `slog.Info`, `MetaEvent.AllowlistIPCount`, unresolved-domain warnings, allowlist-age info note, wildcard-risk scoring (`s3.amazonaws.com` / `githubusercontent.com` / `cloudfront.net` / `blob.core.windows.net` / `azureedge.net` / `r2.dev` / `pages.dev`), and per-domain contact counts surfaced in the digest.
- **P1-2 learning-mode poisoning** (#160). `build-model --min-observation-hours` + `assert-integrity` hard-fail on short windows; suspicious-domain heuristics (Shannon entropy DGA, rare flag, port anomaly); `diff --fail-on-new-domain` strict mode; `QUICK_START.md` "Promoting detect observations to an allowlist" workflow.
- **P1-3 eBPF safety audit** (#162). 71 audited sites across 8 categories; one zero-init hardening in `lsm_socket_connect`. Inline `AUDIT(5x)` comments make the review visible at every call site.
- **P1-4 SNI confidence scoring** (#163). `TLSConfidence` enum (`full`/`partial`/`inferred`/`unknown`) on `telemetry.TLSEvent`; new `tls SNI confidence` digest row.
- **P1-5 JSONL injection hardening** (#161). `telemetry.SanitizeField` strips C0/DEL/C1, replaces invalid UTF-8 with U+FFFD, truncates to per-field byte budgets — applied at the single ring-reader decode point per event type. Forged-record splicing via `argv[0]` / `comm` / SNI / DNS / HTTP prefix is now impossible.
- **P0-1 Phase 1 IPv6 detection** (#155). `cgroup/connect6`/`sendmsg6` observe-only programs surface previously-silent IPv6 egress; verdict flips ⚠️ in detect / 🚨 in defend (superseded by #164 for the enforcement half).
- **`lsm/socket_sendpage`** (#157) closes the sendfile/splice egress gap on kernel 5.15 (`sock_sendpage()` path that bypasses `sendmsg`); #158 pre-checks BTF for the hook so kernels without it degrade cleanly.
- **P0-2 / P0-3 coverage scope + ringbuf drops** (#154). Explicit "Coverage this run" line in every digest; ⚠️ subtitle when partial-coverage signals fire; aggregate ringbuf-drop KPI row.

**Capabilities:**

- **P2-2 QUIC/HTTP3 observation heuristic** (#167). UDP/443 egress to non-loopback IPv4 now emits a synthetic `quic_candidate` JSONL line alongside the underlying `udp` event; new `QUIC (port-443 UDP)` digest KPI row with explicit `N flows · payload not inspected` wording.
- **P2-3 Runner compatibility matrix CI** (#166). New weekly `coldstep-runner-compat.yml` exercises `vanilla` / `dind` / `buildkit` / `service-containers` variants; agent-side `CheckRunnerCompat()` surfaces non-fatal `compat_warnings` (`cgroup_v1_detected`, `cgroup_namespace_nondelegated`, `deep_cgroup_nesting`, `container_cgroup_detection_failed`) on `.coldstep-telemetry.json`.
- **P2-4 Kernel coupling regression harness** (#165). Named, fatal-at-startup BTF probe with actionable error text; `BTFAvailable` carried on a synthetic `bpf` row; new `coldstep-kernel-matrix.yml` scaffolding for 5.15 / 6.1 / 6.6 / 6.8; CI runner annotates a warning when the host kernel drifts >2 majors past the 5.15 floor.
- **P2-5 Reputation plug-in interface** (#168). `internal/reputation` ships `Enricher` / `Result` / `Register` / `EnrichAll`, an OTX backend, a CIRCL PassiveDNS stub, and an env-driven loader. Post-processing only, never on the agent's hot path. Coexists with the legacy `OTX_API_KEY` flow.

**Quality:**

- **PERCPU_ARRAY migration completion** (#139) for 7 hot-path counters; `securego/gosec` SHA-pinned.
- **Go Tier-1 simplifications** (#141) — ~219 LOC removed across agent / report / policy / config / action with no behavior change.
- **BG-03 sendmmsg multi-message observation up to `vlen=8`** (#153).
- **Compact GFM-compliant Step Summary** (#152) — visible portion ~19 lines (budget 30), per-protocol drilldowns inside nested `<details>`. Removes `<font>`, `<p align>`, `<sub>`, `<center>` that rendered as literal text on Job Summaries.

**Fixes:**

- **`io-uring-disable` now actually disables io_uring** (#151). Sysctl key was the bare `io_uring_disabled` instead of the fully-qualified `kernel.io_uring_disabled`; the bare form was silently rejected. Also surfaces sysctl failures as `::warning::` annotations instead of swallowing them.

### Files bumped

| File | Change |
|:--|:--|
| `scripts/check_workflow_action_pins.py` | `MARKETPLACE_COLDSTEP_TAG = "v0.2.6"` |
| `.github/workflows/coldstep-demo.yml` | `COLDSTEP_AGENT_VERSION: v0.2.6` |
| `.github/workflows/coldstep-redteam-ebpf.yml` | `COLDSTEP_AGENT_VERSION: v0.2.6` |
| `README.md`, `QUICK_START.md`, `CONTRIBUTING.md` | recommended pin → `coldstep-io/coldstep@v0.2.6` |
| `cmd/coldstep-report/build_model.go` | `buildVersion = "v0.2.6"` |
| `CHANGELOG.md` | new `[v0.2.6] — 2026-05-19` section + compare link |
| `.github/pr-bodies/pr-release-v0.2.6.md` | this PR body |

### Excluded by design

- **`src/shared.ts` `COLDSTEP_BINARY_VERSION`** stays at `v0.2.4` (current main value) — bumping it before the v0.2.6 GitHub Release exists makes the action's pre-step `pull_request` CI fail with `404 fetching .../releases/tags/v0.2.6` (chicken-and-egg). Same pattern v0.2.5 used. A follow-up PR after the tag publishes can bump this to `v0.2.6` alongside the website pin, or independently.
- `website/index.html` — stays at v0.2.5. Bumped in a follow-up PR after the tag is on Releases.
- `bpf/vmlinux.h`, `internal/bpf/**/*_bpfel.go`, `internal/bpf/**/*_bpfeb.go` — gitignored generated artifacts; CI regenerates per-runner.

## Test plan

- [x] `gofmt -l .` clean
- [x] `bash scripts/check-encoding.sh` clean
- [x] `npm run typecheck` clean
- [x] `npm run build` regenerated `dist/{pre,main,post}/index.js{,.map}` cleanly; binary version intentionally stays at `v0.2.4`
- [ ] `coldstep-ci` matrix green on this PR (gofmt, encoding, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode, CodeQL)
- [ ] After merge: `git tag -s v0.2.6 -m "Release v0.2.6"`, push, watch `supply-chain-attest.yml` upload `coldstep-linux-amd64`
- [ ] Follow-up PR: bump `website/index.html` pin to v0.2.6

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
