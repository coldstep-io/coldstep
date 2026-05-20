## Summary

Release train for **v0.2.8**. Promotes `CHANGELOG.md [Unreleased]` to `[v0.2.8]` (2026-05-20), bumps every consumer-pin surface to v0.2.8 (`coldstep-io/coldstep@v0.2.8`, `COLDSTEP_AGENT_VERSION: v0.2.8`, `MARKETPLACE_COLDSTEP_TAG`), and bumps the internal `cmd/coldstep-report/build_model.go` `buildVersion` constant. No `src/*.ts` changes this train; `dist/` was rebuilt locally for verification.

### v0.2.8 highlights

- **P3-2b — Kernel-confirmed TCP handshake outcomes (#182).** New `tp/sock/inet_sock_set_state` tracepoint emits `tcp_state_event` (48-byte ABI) on every outbound `SYN_SENT → *` transition. Detect digest's `tcp` KPI row picks up a `(confirmed)` suffix plus `↳ established / refused` sub-row when state-machine events arrive.
- **P4 — KTLS offload wired into TLS SNI confidence (#183).** New `ktlsTracker` flags pids that emitted a P3-1 KTLS `setsockopt(SOL_TLS,…)` event so subsequent TLS SNI rows are pinned to `TLSConfidenceUnknown` with `ConfidenceReason="ktls"`. Digest splits the `unknown` bucket as `unknown=K (N ktls-offloaded)`.
- **P5 — IPv6 TLS SNI sniff (#187).** New `handle_tcp_obs_connect6` BPF hook wires `AF_INET6` connects through the TLS sniff path; `connect4_tuple` 8 → 24 bytes (adds `daddr6[16]` + `is_ipv6`) and `tls_sniff_event` 292 → 312 bytes via appended trailer. Legacy IPv4 wire offsets 0..289 stay byte-identical. JSONL `Dst` carries unbracketed v6 string; digest renders bracketed `[v6]:port`.
- **P6 Phase 1 — io_uring write-class submission detection (#188).** New `SEC("raw_tp/io_uring_submit_sqe")` handler (kernel 5.14+) filters on `IORING_OP_SENDMSG` / `IORING_OP_SEND` and emits a 40-byte `io_uring_send_event` on a 64 KiB ringbuf. Runtime fallback for the `io-uring-disable` sysctl gate; new `io_uring writes` KPI row hidden at zero.
- **P3 bug audit — 5 fixes + 2 test gaps (#184).** KTLS pre-offload SNI no longer poisoned; `comm` sanitized in TCPResult / KTLS readers; `tcp_v4_connect_inflight` HASH → LRU_HASH; `ktls_events` ringbuf 4 KiB → 64 KiB; new `TestKTLSTracker_PreOffloadTLSPreserved`.
- **P3-2b / P4 second bug audit — 5 more fixes (#186).** `comm` sanitized in `readTCPStateRing`; KTLS tracker earliest-mark semantics on multi-fd pids; TCPState reader errors now counted; `refused` classification scoped to `CLOSE | CLOSE_WAIT | TIME_WAIT` (table-driven); doc fix for `tcp_state_event` host-byte-order fields.
- **P7 — TLS ECH / SNI extraction limits documented (#181).** Detect digest tech-details fold gains an ECH callout (gated on `TLSTotal > 0`) explaining only the outer SNI is visible under TLS 1.3 ECH; README / QUICK_START gain a "SNI extraction limits" subsection covering fragmented ClientHello, KTLS offload, ECH, and io_uring bypass.

### Files changed in this PR

| Path | Change |
| :--- | :----- |
| `scripts/check_workflow_action_pins.py` | `MARKETPLACE_COLDSTEP_TAG = "v0.2.8"` |
| `.github/workflows/coldstep-demo.yml` | `COLDSTEP_AGENT_VERSION: v0.2.8` |
| `.github/workflows/coldstep-redteam-ebpf.yml` | `COLDSTEP_AGENT_VERSION: v0.2.8` |
| `README.md`, `QUICK_START.md`, `CONTRIBUTING.md` | recommended pin → `coldstep-io/coldstep@v0.2.8` |
| `cmd/coldstep-report/build_model.go` | `buildVersion = "v0.2.8"` |
| `CHANGELOG.md` | new `[v0.2.8] — 2026-05-20` section + compare link |
| `.github/pr-bodies/pr-release-v0.2.8.md` | this PR body |

### Intentionally **not** bumped here (Train 2 / follow-up)

- **`website/index.html`** stays at `v0.2.7` — per `RELEASE_PROCESS.md` Consumer Pin Standard the marketing site must never advertise a tag that does not exist on GitHub Releases yet. Train 2 bumps the site after the tag is published.
- **`src/shared.ts` `COLDSTEP_BINARY_VERSION`** stays at `v0.2.4` (current main value) — same chicken-and-egg pattern v0.2.5 / v0.2.6 / v0.2.7 used. Bumping it before the v0.2.8 GitHub Release asset exists makes the action's pre-step `pull_request` CI fail with `404 fetching .../releases/tags/v0.2.8`. A follow-up PR after the tag publishes can bump this alongside the website pin, or independently.

### Test plan

- [x] `wsl -e bash -c "cd ... && npm ci && npm run build"` — esbuild bundles built clean for `pre/main/post`.
- [x] U+FFFD scan on every changed file — clean.
- [ ] `coldstep-ci` green (unit + integration + action-bundle + detect + defend).
- [ ] After merge: `git tag -s v0.2.8 -m "v0.2.8"`, push, watch `supply-chain-attest.yml` upload `coldstep-linux-amd64`.
- [ ] Train 2 follow-up PR: bump `website/index.html` pin to v0.2.8 after the tag exists on Releases.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
