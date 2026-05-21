## Summary

Release train for **v0.3.0**. Promotes `CHANGELOG.md` with a new `[v0.3.0] — 2026-05-20` section, bumps every consumer-pin surface to v0.3.0 (`coldstep-io/coldstep@v0.3.0`, `COLDSTEP_AGENT_VERSION: v0.3.0`, `MARKETPLACE_COLDSTEP_TAG`), and bumps the internal `cmd/coldstep-report/build_model.go` `buildVersion` constant. No `src/*.ts` changes this train.

Per `RELEASE_PROCESS.md`, this is **Train 1 (repo + CI pins)**. Train 2 (website + `src/shared.ts` `COLDSTEP_BINARY_VERSION`) lands in a separate follow-up PR **after** the v0.3.0 tag is published on Releases — bumping those before the tag exists causes the action pre-step `pull_request` CI to 404 against the Releases API.

### v0.3.0 highlights

- **H7 — IPv6 egress observe-only hooks (#199).** `cgroup/connect6` + `cgroup/sendmsg6` now emit `tcp6` / `udp6` JSONL events with `note: "ipv6-not-enforced"`; digest renders a ⚠️ box when any IPv6 egress is observed and `CoverageReport.ipv6` transitions from `false` to `"observe-only"`.
- **H8 — TLS SNI confidence scoring (#200).** New `TLSConfidence` enum (`full` / `partial` / `inferred` / `unknown`) on `TLSEvent`; digest KPI row added and headline badge downgrades to ⚠️ when `partial + unknown > 0`.
- **H9 — DNS TTL staleness warning + wildcard CDN risk scoring (#201).** Digest emits ⚠️ when the allowlist was compiled more than 5 minutes ago; wildcard CDN domains (`*.githubusercontent.com`, `*.s3.amazonaws.com`, `*.blob.core.windows.net`, `*.azureedge.net`, `*.cloudfront.net`) are flagged with `slog.Warn` per domain and surfaced in the JSONL `MetaEvent`.
- **H10 — Per-domain observation counts (#203).** Agent tracks `dst_domain → connection_count`; digest lists zero-contact allowlist entries as trimming candidates.
- **H11 — Summary file integrity (#203).** SHA-256 of `.coldstep-events.jsonl` recorded in `MetaEvent.EventsFileSHA256`; `<!-- coldstep-digest-sha256: <hex> -->` trailer appended to the digest Markdown.
- **H12 — Allowlist startup entry count (#201).** `MetaEvent.AllowlistEntryCount` records LPM trie size at startup.
- **H13 — Docker-in-Docker detection (#202).** Reads `/proc/1/cgroup` and emits `MetaEvent.RunnerEnv` (`"dind"` / `"standard"` / `"unknown"`); digest renders a ⚠️ box when DinD is detected.
- **H18 — eBPF safety audit (#204).** Annotation-only sweep of every BPF C source under `bpf/` against the Section 5 checklist (5a–5h: map null checks, ringbuf reserve/discard pairing, pointer bounds, loop bounds, BTF CO-RE field stability, helper return checks, cgroup attach cleanup, allowlist entry count log). **No safety gaps found**; no behavioural BPF changes. Two superseded standalone defend translation units (`trace_defend.bpf.c`, `trace_lsm_defend.bpf.c`) documented as dead code.

### Files bumped

| File | Change |
|:--|:--|
| `scripts/check_workflow_action_pins.py` | `MARKETPLACE_COLDSTEP_TAG = "v0.3.0"` |
| `.github/workflows/coldstep-demo.yml` | `COLDSTEP_AGENT_VERSION: v0.3.0` |
| `.github/workflows/coldstep-redteam-ebpf.yml` | `COLDSTEP_AGENT_VERSION: v0.3.0` |
| `README.md`, `QUICK_START.md`, `CONTRIBUTING.md` | recommended pin → `coldstep-io/coldstep@v0.3.0` |
| `cmd/coldstep-report/build_model.go` | `buildVersion = "v0.3.0"` |
| `CHANGELOG.md` | new `[v0.3.0] — 2026-05-20` section + compare link |

### Excluded by design (Train 2 follow-up)

- **`website/index.html`** stays at `v0.2.9` — per `RELEASE_PROCESS.md` the marketing site must never advertise a tag that does not exist on GitHub Releases yet. Train 2 bumps the site after the v0.3.0 tag publishes.
- **`src/shared.ts` `COLDSTEP_BINARY_VERSION`** stays at `v0.2.4` (current main value) — same chicken-and-egg pattern v0.2.5 through v0.2.9 used. Bumping it before the v0.3.0 GitHub Release asset exists makes the action's pre-step `pull_request` CI fail with `404 fetching .../releases/tags/v0.3.0`. Follow-up PR after the tag publishes.

### Comments not bumped (correctly historical)

- `internal/telemetry/event.go` / `event_test.go` and `internal/agent/agent_linux_digest.go` / `coverage_report_linux_test.go` retain `H5 v0.2.9 telemetry stub` comments — these document the historical commit when H5 landed, not a pin to bump.

## Test plan

- [x] `git diff origin/main -- src/ dist/` — empty (no TS bundle drift introduced by this PR).
- [x] `grep -rn "v0.2.9"` against tracked files (excluding `.github/pr-bodies/`, historical CHANGELOG entries, and the H5-stub comments listed above) — clean.
- [ ] `coldstep-ci` matrix green on this PR (`action_bundle`, `detect-mode`, `defend-mode` are the load-bearing gates).
- [ ] After merge: `git tag -s v0.3.0 -m "v0.3.0 — IPv6 observe-only hooks + DNS trust + SNI confidence + summary integrity"`, push, watch `supply-chain-attest.yml` upload `coldstep-linux-amd64`.
- [ ] Train 2 follow-up PR: bump `website/index.html` pin and `src/shared.ts` `COLDSTEP_BINARY_VERSION` to v0.3.0 once the tag exists on Releases.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
