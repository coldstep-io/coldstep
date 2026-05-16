# BPF observability gaps — wiki memo (theme-first outline)

**Purpose:** Mirror into vault **`wiki/Memo - BPF observability gaps backlog 2026-05-08`** for Obsidian linking. **Canonical engineering order** lives in [`2026-05-08-bpf-gaps-backlog.md`](./2026-05-08-bpf-gaps-backlog.md).

---

## Theme: Egress syscall coverage

Coldstep's large `raw_tp/sys_enter` program (`bpf/trace_connect.bpf.c`) observes IPv4-centric `connect`, `sendto`, `sendmsg`, `write`, `writev`, `sendmmsg` (first message only), `sendfile`, `splice`, and bumps a **single** "unobserved egress" counter for **`pwrite*`** syscalls that have no sniff arm yet.

**Backlog refs:** BG-04, BG-01, BG-03.

## Theme: Payload capture limits

HTTP and TLS sniff use bounded `bpf_probe_read_user` patterns. Multi-buffer scatter/gather (`msg_iovlen > 1`, `writev` `vlen > 1`) increments explicit counters but **does not** stitch payloads; operators see counters rise when workloads fragment ClientHello or HTTP across iovecs.

**Backlog refs:** BG-02.

## Theme: Defend vs detect

Cgroup programs (`trace_defend.bpf.c`) and LSM (`trace_lsm_defend.bpf.c`) enforce IPv4 allowlist semantics separately from syscall telemetry; shared helpers live in `bpf/defend_policy.inc`. Parity gaps (for example hook coverage vs detect paths) should be tracked as explicit decisions, not assumed.

**Backlog refs:** (future items; tie to defend-mode CI).

## Theme: Async / syscall bypass

`io_uring_setup` is counted because ring completions bypass syscall tracepoints used for sniffing. Detection posture today relies on composite sysctl/disable paths plus this counter.

**Backlog refs:** BG-05.

## Theme: Address family / protocol

IPv6 is rejected at policy and tracing design scope. QUIC and UDP-shaped TLS require a different observation story than TCP `write`/`sendto` ClientHello sniff.

**Backlog refs:** BG-06, BG-07.

## Theme: Correlation / maps

`(tgid,fd)` LRU correlates TLS/HTTP to prior `connect`; LRU eviction limits staleness but does not replicate full socket lifecycle cleanup.

**Backlog refs:** BG-08.

---

## Sources (stub — expand in vault memo)

1. Internal: `bpf/trace_connect.bpf.c` (file header + PR-D / PR-E / M-01 comments).
2. Internal: `documentation/2026-05-08-bpf-gaps-backlog.md`.
3. Kernel: BPF ringbuf / verifier docs (when expanding iov or new syscalls).
