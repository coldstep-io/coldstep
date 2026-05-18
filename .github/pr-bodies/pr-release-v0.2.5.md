## Summary

Release train for **v0.2.5**. Bumps consumer pins everywhere they advertise the recommended tag, promotes `CHANGELOG.md [Unreleased]` to `[v0.2.5]` (today, 2026-05-18), and adds a section for the detect digest redesign that landed in #149.

Per `RELEASE_PROCESS.md`, this is the **repo + CI** train. `website/index.html` stays at v0.2.4 in this PR and gets bumped in a separate follow-up PR after the tag is published on Releases (consumer-pin standard: never advertise an unpublished tag on the site).

### v0.2.5 highlights

- **Detect digest redesign** (#149) — headline status badge (🚨 / ⚠️ / ✅), hot-egress table now appears before triage, KPI table reordered network → process → fs → health, long-form prose collapsed into a single `<details>` "Technical details" fold plus a small Run info table.
- **HTTP/1 sniff parity for `write(2)` family** (BG-04) — `write` / `writev` / `pwrite64` / `pwritev` / `pwritev2` paths now produce `http_events` for dport-80 traffic.
- **Per-syscall partial-observe counters** (BG-01) — `sendfile_observed`, `splice_observed`, `sendmmsg_first_only` supersede the dead `unobserved_egress_syscalls_observed` aggregate.
- **Bounded multi-iovec sniff** (BG-02) — single additional bounded read of `iov[1]` for TLS / HTTP fingerprinting when `vlen >= 2`.
- **`sendmmsg_multi_message_observed`** (BG-03) — counter for `NR_SENDMMSG` with `vlen > 1`, separate from the per-message multi-iovec counter.
- **`*EmptyReason` consolidation** — four near-identical helpers folded into `protocolEmptyReason`.

### Files bumped

| File | Change |
|:--|:--|
| `scripts/check_workflow_action_pins.py` | `MARKETPLACE_COLDSTEP_TAG = "v0.2.5"` |
| `.github/workflows/coldstep-demo.yml` | `COLDSTEP_AGENT_VERSION: v0.2.5` |
| `.github/workflows/coldstep-redteam-ebpf.yml` | `COLDSTEP_AGENT_VERSION: v0.2.5` |
| `README.md`, `QUICK_START.md`, `CONTRIBUTING.md` | recommended pin → `coldstep-io/coldstep@v0.2.5` |
| `CHANGELOG.md` | `[Unreleased]` → `[v0.2.5] — 2026-05-18` + new compare link |

### Excluded by design

- `website/index.html` — stays at v0.2.4. Bumped in a follow-up PR after the tag is on Releases.

## Test plan

- [x] `go test ./internal/report/... -count=1` — clean.
- [x] `gofmt -l .` — clean.
- [ ] `coldstep-ci` matrix green on this PR.
- [ ] After merge: `git tag -s v0.2.5 -m "Release v0.2.5"`, push, watch `supply-chain-attest.yml` upload `coldstep-linux-amd64`.
- [ ] Bump `coldstep-io/coldstep-demo` workflow pins to v0.2.5; dispatch all 7 demo workflows; verify success.
- [ ] Follow-up PR: bump `website/index.html` pin to v0.2.5.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
