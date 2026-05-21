## Summary

Systematic audit of all BPF C sources under `bpf/` against the H18 Section 5
safety checklist (items 5a-5h). Every audited site is annotated inline with a
short `// audit(5X): <reason>` comment so future reviewers can see at a glance
that it was checked. No behavioural BPF changes — comments only.

## Checklist coverage

- **5a (map lookup null checks)** — every `bpf_map_lookup_elem` is null-checked
  before deref. Added inline `AUDIT(5a)` annotations on the
  `kprobe/kretprobe tcp_v4_connect` pair, the ktls reserve-failure counter,
  the two `connect4_by_tgid_fd` updates, the canary trigger clear, and the
  DNS `recvfrom_buf` update.
- **5b (ringbuf reserve/discard pairing)** — every `bpf_ringbuf_reserve` has
  either a `submit` or `discard` on every exit path. Added inline
  `AUDIT(5b)` annotations on the `tcp_state_events` reserve, the
  `io_uring_events` reserve, the `kretprobe_tcp_v4_connect` reserve, and
  the `ktls_events` reserve. **No leaks found.**
- **5c (pointer arithmetic bounds)** — already audited inline in
  `trace_udp_sendmsg.inc` (iov[1] peek), `trace_tls_write.inc` (writev
  iov[1] peek), and the `sendmmsg` unrolled-loop in `trace_connect.bpf.c`.
  Verifier-side `bpf_probe_read_user` enforces kernel-side bounds.
- **5d (loop bounds)** — the only loop is the `#pragma unroll` sendmmsg
  extra-message walk in `trace_connect.bpf.c`, capped at
  `SENDMMSG_EXTRA_MAX = 7`. Already annotated `AUDIT(5d)` inline.
- **5e (BTF CO-RE field stability)** — annotated the
  `trace_event_raw_inet_sock_set_state` field reads (stable since 4.16
  tracepoint addition) and the `io_kiocb.opcode` CO-RE read (u8 at stable
  logical offset since io_uring landed in 5.1). `task_struct` /
  `pid_namespace` fields already annotated 5e in `trace_fork.bpf.c`.
- **5f (helper return checks)** — every `bpf_probe_read_user` /
  `bpf_probe_read_kernel` return is either checked or its destination is
  zero-initialized before the call so a probe miss fails closed. Added
  `AUDIT(5f)` annotations on the `tcp_state_events` saddr/daddr/sport/dport
  reads and the `io_kiocb.opcode` read.
- **5g (cgroup attach cleanup)** — the partial-attach cleanup paths in
  `internal/agent/agent_linux.go` (LSM section ~lines 263 and cgroup
  section ~342) close prior links explicitly on failure and defer per-link
  `Close` on success. Already annotated `AUDIT(5g)` inline. The
  `internal/bpf/defend/loader.go` side uses `success` + `defer coll.Close()`
  to release the entire collection on partial detach failure.
- **5h (allowlist startup entry count log)** — wired by H12 — confirmed
  `internal/agent/agent_linux_policy_maps.go:300` logs `ipv4_entries` and
  `ignored_cidrs` via `slog.Info` on startup map load.

## Dead-code paths

`trace_defend.bpf.c` and `trace_lsm_defend.bpf.c` remain in the tree as
superseded standalone translation units (no Go package generates from
them; the active path is `trace_defend_all.bpf.c`). Documented in their
leading comments that the active safety annotations live in the included
`.inc` files and that a future revert MUST first port the zero-init
defense-in-depth pattern from `trace_lsm_defend_lsm.inc`.

## Files touched

```
bpf/trace_connect.bpf.c          (+25/-2)
bpf/trace_defend.bpf.c           (+7)
bpf/trace_defend_all.bpf.c       (+12)
bpf/trace_dns.bpf.c              (+2)
bpf/trace_ktls.bpf.c             (+3)
bpf/trace_lsm_defend.bpf.c       (+9)
bpf/trace_tcp_connect_kprobe.inc (+9/-1)
bpf/trace_tcp_obs.inc            (+4)
```

## Test plan

- [x] `bash scripts/check-gofmt.sh` — no Go files touched but ran for safety
- [x] `bash scripts/check-encoding.sh` — passed
- [ ] CI matrix (`coldstep-ci.yml`) — verifier still loads each program
      cleanly with the new comments (comment-only change, no semantics)
- [ ] Reviewers scan the inline `AUDIT(5x)` annotations for accuracy
