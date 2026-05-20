## Summary

Release train for **v0.2.7**. Promotes `CHANGELOG.md [Unreleased]` to `[v0.2.7]` (2026-05-19), bumps every consumer-pin surface to v0.2.7 (`coldstep-io/coldstep@v0.2.7`, `COLDSTEP_AGENT_VERSION: v0.2.7`, `MARKETPLACE_COLDSTEP_TAG`), and bumps the internal `cmd/coldstep-report/build_model.go` `buildVersion` constant. No `src/*.ts` changes this train; `dist/` was rebuilt locally for verification and is byte-identical to the current main bundle.

### v0.2.7 highlights

- **P3-1 — KTLS offload detection (#174).** New `raw_tp/sys_enter` BPF probe surfaces `setsockopt(SOL_TLS, TLS_TX|TLS_RX, …)` calls as `ktls_offload` JSONL events with a dedicated KPI row, exposing the structural SNI-extraction gap on KTLS sockets.
- **P3-2 — TCP connect result events (#175).** Paired kprobe/kretprobe on `tcp_v4_connect` adds a `tcp_result` JSONL event and a TCP-connections KPI row that splits attempts into `established / refused / timeout / unreachable` instead of conflating outcomes.
- **P3-3 — Inter-syscall TLS ClientHello reassembly (#173).** Userspace per-`(pid,dst,dport)` accumulator (512 B per key, 30 s TTL, 1024-key LRU) stitches split ClientHellos that the single-buffer SNI parser was dropping; rescued events surface with `tls_confidence=partial` and a new `ReassembledSNI=true` field.
- **P3-4 — Per-row TLS SNI confidence column (#178).** Digest TLS section now shows the per-event tier (`full / partial / inferred / unknown`) and includes a 4-tier legend in the Notes block, gated on `TLSTotal > 0`.

### Files changed in this PR

| Path | Change |
| :--- | :----- |
| `scripts/check_workflow_action_pins.py` | `MARKETPLACE_COLDSTEP_TAG = "v0.2.7"` |
| `.github/workflows/coldstep-demo.yml` | `COLDSTEP_AGENT_VERSION: v0.2.7` |
| `.github/workflows/coldstep-redteam-ebpf.yml` | `COLDSTEP_AGENT_VERSION: v0.2.7` |
| `README.md`, `QUICK_START.md`, `CONTRIBUTING.md` | recommended pin → `coldstep-io/coldstep@v0.2.7` |
| `cmd/coldstep-report/build_model.go` | `buildVersion = "v0.2.7"` |
| `CHANGELOG.md` | new `[v0.2.7] — 2026-05-19` section + compare link |
| `.github/pr-bodies/pr-release-v0.2.7.md` | this PR body |

### Intentionally **not** bumped here (Train 2 / follow-up)

- **`website/index.html`** stays at `v0.2.6` — per `RELEASE_PROCESS.md` Consumer Pin Standard the marketing site must never advertise a tag that does not exist on GitHub Releases yet. Train 2 bumps the site after the tag is published.
- **`src/shared.ts` `COLDSTEP_BINARY_VERSION`** stays at `v0.2.4` (current main value) — same chicken-and-egg pattern v0.2.5 and v0.2.6 used. Bumping it before the v0.2.7 GitHub Release asset exists makes the action's pre-step `pull_request` CI fail with `404 fetching .../releases/tags/v0.2.7`. A follow-up PR after the tag publishes can bump this alongside the website pin, or independently.

### Test plan

- [x] `wsl -e bash -c "cd ... && npm ci && npm run build"` — esbuild bundles built clean for `pre/main/post`.
- [x] `wsl -e bash -c "cd ... && npm run typecheck"` — `tsc --noEmit` passes.
- [x] `gofmt -l cmd/coldstep-report/build_model.go` — clean.
- [x] U+FFFD scan on every changed file — clean.
- [ ] `coldstep-ci` green (unit + integration + action-bundle + detect + defend).
- [ ] After merge: `git tag -s v0.2.7 -m "v0.2.7"`, push, watch `supply-chain-attest.yml` upload `coldstep-linux-amd64`.
- [ ] Train 2 follow-up PR: bump `website/index.html` pin to v0.2.7 after the tag exists on Releases.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
