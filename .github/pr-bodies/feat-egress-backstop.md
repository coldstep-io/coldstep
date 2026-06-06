## cgroup/skb egress backstop (observe-only)

Adds an observe-only `cgroup_skb/egress` BPF program that surfaces egress which
**bypassed** the existing connect4/sendmsg4 address hooks — raw sockets
(`SOCK_RAW`), `AF_PACKET`, or post-connect destination redirects. These paths
leave no telemetry today (the long-open "raw socket egress" coverage gap).

### Insight
In defend mode, connect4/sendmsg4 already block every non-allowlisted IPv4 dest
that traverses them. So any packet that *reaches* `cgroup_skb/egress` bound for a
non-allowlisted, non-ignored, non-loopback IP **must have bypassed** the address
hooks. That packet is the signal — no separate "seen via connect4" map needed;
the existing allowlist maps are the reference set.

### What ships
- **BPF** (`bpf/trace_defend_skb.inc`, wired into `trace_defend_all.bpf.c` after
  the cgroup section): reads L3/L4 dst via `bpf_skb_load_bytes`, short-circuits
  loopback/link-local, reuses the address-based `cg_dst_in_ignored` /
  `cg_dst_is_allowlisted` helpers (IPv4) and the `allowed_ipv6` LPM (IPv6),
  dedups by dst-IP in a 1s-cooldown LRU, emits on a dedicated `skb_backstop_events`
  ringbuf. **Always returns 1 — never drops.** IPv4 + IPv6.
- **Telemetry**: `telemetry.EgressBackstopEvent` (`type:"egress_backstop"`,
  signed) + 56-byte wire struct (`bpf/egress_backstop_event.h`) + Go decoder.
  `cgroup_skb` egress may run in softirq context, so `pid`/`comm` are
  best-effort; `dst`/`proto`/`af` are reliable (documented).
- **Agent**: `readEgressBackstopRing` (seq allocated under `jsonlMu` only on
  emit), runStats counters (total + distinct-dst set + reserve-failure), attach
  via `AttachCGroupInetEgress` in **defend mode only**, tolerate-on-failure with
  a `cgroup_skb/egress` BPFStatus row.
- **Digest**: `🚨 egress backstop (bypassed address hooks)` KPI row, hidden when
  zero.
- **Tests**: telemetry JSON/sig, wire decode round-trip + too-short, runStats,
  reader builder, digest row visible/hidden, defend ABI (maps + program),
  `internal/policy` classification regression anchor, BPF source-assertion
  (observe-only invariant + OOB-fix pin), and two `TestRedTeam_EgressBackstop_*`
  integration tests (raw-socket bypass emits; allowlisted connect does not).

### Posture
Observe-only, defend-only, hidden-when-zero → zero blast radius on existing runs.
Active drop is a deferred follow-up once field data confirms a low false-positive
rate.

### Notes
- A review caught and fixed an out-of-bounds stack read (v4 dedup key built from
  a 4-byte var memcpy'd as 16 bytes) before merge — now builds a 16-byte array.
- Generated `internal/bpf/defend/*_bpfel.go` are gitignored; CI regenerates.

Part of the eBPF hardening roadmap (sub-project A of A/B/C).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
