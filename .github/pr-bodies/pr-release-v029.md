## Summary

Release train for **v0.2.9**. Promotes `CHANGELOG.md [Unreleased]` to `[v0.2.9]` (2026-05-20), bumps every consumer-pin surface to v0.2.9 (`coldstep-io/coldstep@v0.2.9`, `COLDSTEP_AGENT_VERSION: v0.2.9`, `MARKETPLACE_COLDSTEP_TAG`), and bumps the internal `cmd/coldstep-report/build_model.go` `buildVersion` constant. No `src/*.ts` changes this train; `dist/` was rebuilt locally (esbuild) for verification.

### v0.2.9 highlights

- **H1 — Honest detect-digest verdict + Coverage scope table (#193).** Headline badge text spells out what each emoji means (✅ "No anomalies detected (IPv4 TCP/UDP in scope)", ⚠️ "Partial observation or coverage gaps — review required", 🚨 "BPF failure or canary pipeline issue"); new 7-row Coverage scope table names each traffic class with its observation status; new `RunnerHasIPv6` wiring downgrades ✅ → ⚠️ when the runner has IPv6 but no v6 hooks are loaded.
- **H2 — Ringbuffer drop counter propagation (#194).** New `MetaEvent.DroppedEvents map[string]uint64` on the shutdown record (per-channel counters, `omitempty` + zero-keys-dropped). Detect-digest KPI row renamed to `**⚠️ Dropped events (ringbuf overflow)**`; a non-zero reserve-failure on any detect-path channel flips the headline badge to ⚠️.
- **H4 — DNS allowlist startup logging + JSONL surface (#196).** New `slog.Info("allowlist compiled", ...)` at policy load + `MetaEvent.AllowlistIPCount` / `MetaEvent.UnresolvedDomains` (both omitempty) + a `> ⚠️ **Allowlist: N domain(s) unresolved at startup**` blockquote at the top of the defend digest section. Closes the "partial DNS resolve at startup is silent" gap.
- **H5 — Structured coverage telemetry stub (#195).** New `telemetry.CoverageReport` embedded as `*CoverageReport` under JSON key `coverage` on `MetaEvent` (six locked-shape fields: `ipv4_tcp`, `ipv4_udp_sendmsg`, `ipv6`, `quic_http3`, `tls_sni_full`, `io_uring`). Machine-readable twin of H1's Coverage scope table.
- **H6 — IPv4-only coverage boundaries documented (#192).** `action.yml` `mode:` description, `README.md` At-a-glance + Requirements rows, and `QUICK_START.md` blockquote all now accurately state that defend cgroup hooks are IPv4-only by kernel ABI. New `SECURITY.md ## Coverage Boundaries` section with a per-traffic-class matrix and "Why IPv4-only" rationale.
- **P6 Phase 2 — io_uring SQE TLS ClientHello peek (#191).** Extends the v0.2.8 Phase 1 io_uring submission probe with a bounded `bpf_probe_read_user` peek at the SQE user-space buffer (gated behind `COLDSTEP_DETECT_PROFILE=enhanced` via a new `io_uring_peek_cfg` array map). Surfaces TLS-over-io_uring egress that escapes syscall-based hooks. Wire size preserved at 40 B by repurposing the trailing `_pad` byte as `has_tls_hello`.

### Files changed in this PR

| Path | Change |
| :--- | :----- |
| `scripts/check_workflow_action_pins.py` | `MARKETPLACE_COLDSTEP_TAG = "v0.2.9"` |
| `.github/workflows/coldstep-demo.yml` | `COLDSTEP_AGENT_VERSION: v0.2.9` |
| `.github/workflows/coldstep-redteam-ebpf.yml` | `COLDSTEP_AGENT_VERSION: v0.2.9` |
| `README.md`, `QUICK_START.md`, `CONTRIBUTING.md` | recommended pin → `coldstep-io/coldstep@v0.2.9` |
| `cmd/coldstep-report/build_model.go` | `buildVersion = "v0.2.9"` |
| `CHANGELOG.md` | new `[v0.2.9] — 2026-05-20` section + compare link |
| `.github/pr-bodies/pr-release-v029.md` | this PR body |

### Intentionally **not** bumped here (Train 2 / follow-up)

- **`website/index.html`** stays at `v0.2.7` (current main value) — per `RELEASE_PROCESS.md` the marketing site must never advertise a tag that does not exist on GitHub Releases yet. Train 2 bumps the site after the v0.2.9 tag publishes (and can roll forward from v0.2.7 to v0.2.9 in one hop).
- **`src/shared.ts` `COLDSTEP_BINARY_VERSION`** stays at `v0.2.4` (current main value) — same chicken-and-egg pattern v0.2.5 / v0.2.6 / v0.2.7 / v0.2.8 used. Bumping it before the v0.2.9 GitHub Release asset exists makes the action's pre-step `pull_request` CI fail with `404 fetching .../releases/tags/v0.2.9`. A follow-up PR after the tag publishes can bump this alongside the website pin, or independently.

### Test plan

- [x] `wsl -e bash -c "cd ... && npm ci && npm run build"` — esbuild bundles built clean for `pre/main/post`.
- [x] U+FFFD scan on every changed file — clean (`scripts/check-encoding.sh`).
- [ ] `coldstep-ci` green (unit + integration + action-bundle + detect + defend).
- [ ] After merge: `git tag -s v0.2.9 -m "v0.2.9"`, push, watch `supply-chain-attest.yml` upload `coldstep-linux-amd64`.
- [ ] Train 2 follow-up PR: bump `website/index.html` pin to v0.2.9 after the tag exists on Releases.
