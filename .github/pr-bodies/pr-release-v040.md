## Summary

Release train for **v0.4.0**. Promotes `CHANGELOG.md` with a new `[v0.4.0] — 2026-05-21` section, bumps every consumer-pin surface to v0.4.0 (`coldstep-io/coldstep@v0.4.0`, `COLDSTEP_AGENT_VERSION: v0.4.0`, `MARKETPLACE_COLDSTEP_TAG`), and bumps the internal `cmd/coldstep-report/build_model.go` `buildVersion` constant. No `src/*.ts` changes this train (`git diff v0.3.0..HEAD -- src/ dist/` empty).

Per `RELEASE_PROCESS.md`, this is **Train 1 (repo + CI pins)**. Train 2 (website + `src/shared.ts` `COLDSTEP_BINARY_VERSION`) lands in a separate follow-up PR **after** the v0.4.0 tag is published on Releases — bumping those before the tag exists causes the action pre-step `pull_request` CI to 404 against the Releases API.

### v0.4.0 highlights

- **H14 — IPv6 block phase 2: coverage telemetry + docs + bypass test (#206).** The BPF + userspace machinery already shipped in P2-1 (v0.2.6, #164); H14 closes the three remaining public-surface gaps. `CoverageReport.IPv6` changes from `bool` to a three-value string enum (`telemetry.CoverageIPv6Off` / `…ObserveOnly` / `…Enforce`). New `internal/policy/ipv6_bypass.go` mirrors the BPF loopback / link-local classifier as a regression anchor — production code is unchanged (the BPF program is authoritative). README + `SECURITY.md` drop "IPv6 unsupported in defend" wording.
- **H15 — `lsm/io_uring_cmd` defend hook (#212).** New `SEC("lsm/io_uring_cmd")` program blocks non-allowlisted IPv4 egress on `IORING_OP_URING_CMD` submissions — closes the socket-backed `URING_CMD` gap that bypasses `security_socket_sendmsg()`. Defense-in-depth only — the cgroup `connect4`/`sendmsg4` hooks remain the primary IPv4 defense path. `defend.HaveIOUringLSM()` probes kernel BTF for `bpf_lsm_io_uring_cmd` (not `security_uring_cmd` — that symbol is present on every 5.19+ kernel regardless of whether the LSM dispatch is wired); the loader strips the program on kernels without `CONFIG_BPF_LSM` so prog_load doesn't fail.
- **H16 — DNS allowlist drift watchdog (#205).** Background goroutine periodically re-resolves the startup allowlist and emits a `dns_drift` JSONL event when IPv4 addresses diverge from the snapshot programmed into the BPF map. **Warning-only by design** — the live enforce policy is never updated mid-run (TOCTOU risk). New `policy.DriftReport` + `policy.Diff` + `policy.ReResolve`; new `telemetry.DNSDriftEvent`; new `runDNSDriftWatch` ticking every 5 min; digest renders a fourth `writeAllowlistTrust` advisory box when drift is non-zero.
- **H17 — Learning-mode poisoning protections (#207).** Per-domain risk metadata + reviewer-facing surface around the existing `--min-observation-hours` / `diff --fail-on-new-domain` gates. `model.SuspiciousDomain` grows `ObservationCount` / `FirstSeenTS` / `RiskHint` (`suspicious-dga`, `single-observation`, or empty); new exported `model.HasHighEntropyLabel` (12-char floor + Shannon ≥ 3.5 bits/char OR 16+ hex). `assert-integrity` now emits warn-only `::warning title=Coldstep learning-mode reviewer hints (H17)::…` annotations — verdict is **not** changed.
- **H19 — QUIC/HTTP3 observation heuristic (#208).** UDP egress on dport 443 carries a per-event `possible_quic bool` and feeds a per-run `CoverageReport.QuicObserved uint64`. Both fields are `omitempty` so runs without UDP/443 see no JSON drift. Full QUIC ClientHello parsing is structurally out of scope (requires QUIC crypto decryption — same architectural limit as ECH).
- **H20 — Red-team validation CI (#209).** New `internal/agent/redteam_test.go` (`//go:build integration && linux && !windows`) with 12 `TestRedTeam_*` integration tests covering the v0.4.0 security review's attack paths. New `redteam-integration` job in `coldstep-redteam-ebpf.yml` runs them on `ubuntu-latest`.

### Bug fixes (post-feature pass)

- **DNS drift watchdog races with agent shutdown (#215).** `runDNSDriftWatch` now checks `ctx.Err()` after `ReResolve` returns; otherwise a 25s in-flight resolve that the per-lookup context cancels on shutdown would return a partial `CompileResult` and diff as `RemovedIPs=[all]`, producing a spurious `dns_drift` event in `.coldstep-events.jsonl` on the way out.
- **`.coldstep-telemetry.json` missing TCP-state / QUIC-observed / DNS-drift counters (#216).** `snapshotSummary` now plumbs through `tcp_state_total` / `tcp_state_confirmed` / `tcp_state_refused` / `tcp_state_ringbuf_reserve_failures` (P3-2b), `quic_observed` (H19), and `dns_drift_observations` (H16). The shutdown digest already had them via `DigestInput`; this PR makes the on-disk summary file consistent. All new fields are `omitempty` so existing detect runs see no noise.

### Files bumped

| File | Change |
|:--|:--|
| `scripts/check_workflow_action_pins.py` | `MARKETPLACE_COLDSTEP_TAG = "v0.4.0"` |
| `.github/workflows/coldstep-demo.yml` | `COLDSTEP_AGENT_VERSION: v0.4.0` |
| `.github/workflows/coldstep-redteam-ebpf.yml` | `COLDSTEP_AGENT_VERSION: v0.4.0` |
| `README.md`, `QUICK_START.md`, `CONTRIBUTING.md` | recommended pin → `coldstep-io/coldstep@v0.4.0` |
| `cmd/coldstep-report/build_model.go` | `buildVersion = "v0.4.0"` |
| `CHANGELOG.md` | new `[v0.4.0] — 2026-05-21` section + compare link |

### Excluded by design (Train 2 follow-up)

- **`website/index.html`** stays at `v0.3.0` — per `RELEASE_PROCESS.md` the marketing site must never advertise a tag that does not exist on GitHub Releases yet. Train 2 bumps the site after the v0.4.0 tag publishes.
- **`src/shared.ts` `COLDSTEP_BINARY_VERSION`** stays at `v0.2.4` (current main value) — same chicken-and-egg pattern v0.2.5 through v0.3.0 used. Bumping it before the v0.4.0 GitHub Release asset exists makes the action's pre-step `pull_request` CI fail with `404 fetching .../releases/tags/v0.4.0`. Follow-up PR after the tag publishes.

## Test plan

- [x] `git diff origin/main -- src/ dist/` — empty (no TS bundle drift introduced by this PR; no rebuild needed).
- [x] `grep -rn "v0.3.0"` against tracked files (excluding `.github/pr-bodies/`, historical CHANGELOG entries, `website/index.html` Train 2 surface) — clean.
- [ ] `coldstep-ci` matrix green on this PR (all 22 checks; `action_bundle`, `detect-mode`, `defend-mode` are the load-bearing gates).
- [ ] After merge: `git tag -s v0.4.0 -m "v0.4.0"` (key 26339171048CB12C), push, watch `supply-chain-attest.yml` upload `coldstep-linux-amd64`.
- [ ] Train 2 follow-up PR: bump `website/index.html` pin and `src/shared.ts` `COLDSTEP_BINARY_VERSION` to v0.4.0 once the tag exists on Releases.
