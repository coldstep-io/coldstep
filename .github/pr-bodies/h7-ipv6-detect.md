## Summary

Implements **H7** from the v0.2.9+ hardening roadmap: surface non-loopback IPv6 egress in **detect mode**. Until now the cgroup/connect6 + cgroup/sendmsg6 hooks lived inside the defend BPF object (P0-1 Phase 1 counters, P2-1 Phase 2 LPM enforcement), so detect-mode runs had **zero visibility** into IPv6 destinations — the digest could only report `"runner has IPv6 — coverage gap"` heuristically from MetaEvent.RunnerHasIPv6.

H7 ships a standalone observe-only BPF object (`internal/bpf/traceipv6`) that attaches `cgroup/connect6` + `cgroup/sendmsg6` programs which **always allow** but emit a ringbuf record per non-loopback / non-link-local IPv6 destination (`{daddr[16], dport, pid, comm, hook}`). The agent decodes each record into a `telemetry.IPv6Event` JSONL line (`"type":"tcp6"` / `"udp6"`) and bumps `runStats.IPv6EventCount`. The digest renders a headline-area blockquote

> ⚠️ **IPv6 egress detected (not enforced)** — N connection(s) observed

whenever the counter is non-zero in detect mode, plus a triage row and a Full-KPI row inside Technical details. Defend mode is unchanged — `traceipv6` is skipped there because the defend object already attaches enforcing IPv6 hooks to the same cgroup (single-program attach).

## What changed

- **`bpf/trace_ipv6_obs.bpf.c`** (new) — standalone BPF object. Two `SEC()` programs:
  - `cgroup/connect6`: emit ringbuf record (hook=0), return 1.
  - `cgroup/sendmsg6`: emit ringbuf record (hook=1), return 1.

  Loopback (`::1`) and link-local (`fe80::/10`) are filtered in BPF so the ringbuf is not drowned by mDNS/SLAAC. Wire-format `struct ipv6_obs_event` is pinned at 44 bytes via `_Static_assert`; copy of `ctx->user_ip6[i]` uses four explicit `__u32` loads to satisfy the cgroup-sockaddr verifier (mirrors `cg_copy_user_ip6_u32` in `trace_defend_cgroup.inc`).

- **`internal/bpf/traceipv6/`** (new package) — `gen.go` with direct `bpf2go` (no per-arch syscall NR flags needed) and `abi_test.go` validating ringbuf shape, per-CPU reserve-failures map shape, and presence of both programs.

- **`internal/telemetry/event.go`** — new `IPv6Event` JSONL type with `EventTypeIPv6TCP`/`EventTypeIPv6UDP` discriminators (`"tcp6"`, `"udp6"`) and canonical `IPv6NotEnforcedNote = "ipv6-not-enforced"` so downstream filters can locate H7 events without parsing the type field.

- **`internal/telemetry/telemetry.go`** — `Summary.IPv6Events` + `Summary.IPv6RingbufReserveFailures` for `.coldstep-telemetry.json`. Separate from the existing `IPv6Connect/SendmsgObserved` counters which only fire in defend mode.

- **`internal/agent/agent_linux_ring_read.go`** — `readIPv6ObsRing` decodes the 44-byte wire record, sanitizes `comm` (P1-5 JSONL-injection hardening), converts the network-order port via `binary.BigEndian.Uint16`, formats `net.IP.String()` for the dst, and writes `telemetry.IPv6Event` to the JSONL stream.

- **`internal/agent/agent_linux_state.go`** — `runStats.ipv6EventCountN` + `ipv6RingbufReserveFailuresN` with the usual lock-protected accessors. Wired into `snapshotSummary`.

- **`internal/agent/agent_linux_bpf_start.go`** — `startIPv6ObsTrace(cgPath)` loads the object and attaches both cgroup programs against `cfg.CgroupAttachPath` (default `/sys/fs/cgroup`).

- **`internal/agent/agent_linux.go`** — load + attach guarded by `cfg.Mode != config.ModeDefend`. Tolerates attach failures (very old kernels lacking cgroup/connect6 support) with a `BPFStatus{Name: "cgroup/connect6+sendmsg6 (ipv6_obs)", OK: false}` row so the Coverage scope cell can downgrade. Spawn a `readIPv6ObsRing` goroutine when the ringbuf reader opened.

- **`internal/report/digest_types.go`** — `DigestInput.IPv6EventCount` + `IPv6RingbufReserveFailures`. Wired from agent state in `agent_linux_digest.go`.

- **`internal/report/digest.go`** —
  - `ipv6EgressObserved` now sums the defend-side per-CPU counters AND the H7 event count.
  - `ipv6HooksLoaded` returns true in defend mode OR when the `cgroup/connect6+sendmsg6 (ipv6_obs)` BPF row is OK.
  - `ipv6CoverageCell` gains a new path: detect mode with H7 attached + no events → `"✓ observed (detect — H7 observe-only hook, no events)"` instead of the previous `"✗ not observed (runner has IPv6 — coverage gap)"` heuristic.
  - `writeHeader` emits the spec'd `> ⚠️ **IPv6 egress detected (not enforced)** — N connection(s) observed` blockquote when `IPv6EventCount > 0 && !defend`.
  - Triage row breakdown switches between `connect=X sendmsg=Y` (defend) and `N ringbuf event(s)` (detect) so the figures match the source counters.
  - Full KPI gains an H7 events row and the matching ringbuf reserve-failures row.

- **`internal/agent/ipv6_obs_decode_linux_test.go`** (new) — `TestIPv6ObsHookName` (0→tcp6, 1→udp6, unknown→tcp6 fallback) and `TestIPv6ObsEventWireDecode` pinning the 44-byte layout (daddr@0, dport@16, pid@20, comm@24, hook@40).

- **`internal/report/digest_test.go`** — `TestBuildDetectMarkdown_IPv6EventCount_DetectMode` walks the headline blockquote, triage row, KPI row, and confirms no 🚨 escalation. `TestBuildDetectMarkdown_IPv6EventCount_RunnerHasIPv6_NoGapDowngrade` verifies the H7 hook row closes the H1 RunnerHasIPv6 coverage-gap downgrade.

## Constraints honored

- **Detect-mode-only attach** — defend mode already owns cgroup/connect6+sendmsg6 via its own object (P0-1 + P2-1); double-attach would fail with EBUSY.
- **No promise of IPv6 *enforcement* in detect** — the blockquote, triage row, and Coverage row all say "not enforced" / "no enforcement". Operators flip to defend (with P2-1 AAAA-resolved allowed_ipv6 entries) to actually gate IPv6.
- **No defend regression** — every existing IPv6Connect/SendmsgObserved test still passes; defend-mode triage / KPI / Coverage logic is unchanged.
- **Best-effort attach** — `BPFStatus{OK: false}` on attach failure; agent continues without IPv6 visibility, the digest's Coverage scope reflects the gap.
- **JSONL injection hardening** — `comm` is sanitized at the ring-reader decode point (P1-5), same as every other event type.
- **No new required JSONL types in integrity** — `tcp6`/`udp6` are conditional on IPv6 traffic; `RequiredTypesForDetectProfile("enhanced")` is unchanged.
- **No enforce/defend rename churn** — agent only emits `mode: detect|defend`.

## Validation

- `gofmt -l` (on the changed files) — clean.
- `go vet ./...` — clean.
- `go test ./... -count=1` (WSL Ubuntu, BPF stubs generated via `go generate ./internal/bpf/...`) — all packages pass, including the new `internal/bpf/traceipv6` abi tests and the two new digest tests.
- `go test -race -count=1 ./internal/agent/... -timeout 5m` — pass.
- Encoding scan on touched files — no mojibake / U+FFFD bytes.
- BPF verifier load + cgroup attach are validated by CI's `coldstep-ci-runner.yml` (`unit`, `unit-arm64`, `integration`, `detect-mode`, `defend-mode`).

## Follow-ups (out of scope)

- **website/** copy update — bump after the next release tag per `RELEASE_PROCESS.md`. The existing IPv6 marketing copy is still accurate (defend gates, detect now observes); the section just needs a sentence about detect-mode visibility.
- **CHANGELOG.md** entry — lands with the release PR; H7 itself ships unreleased on `main`.
- **SECURITY.md** — the IPv6 row in the "What coldstep observes" matrix could note that detect mode now records IPv6 destinations (currently marked observe-only via the defend hook, which was technically false in detect mode).
