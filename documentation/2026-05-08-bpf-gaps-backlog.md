# BPF gaps — engineering backlog (ranked)

**Implementation plan:** [`2026-05-09-bpf-features-implementation-plan.md`](./2026-05-09-bpf-features-implementation-plan.md) (phased PRs BG-04 -> BG-01 -> …).

**Companion:** theme-first narrative + sources in [`2026-05-08-bpf-gaps-wiki-memo.md`](./2026-05-08-bpf-gaps-wiki-memo.md) (vault memo: `knowledge/wiki/Memo - BPF observability gaps backlog 2026-05-08.md`).

**Ranking:** Lower **rank #** = ship first. Tags: **theme** (Wiki cluster), **surface** (syscall / cgroup / LSM / research).

---

## #1 — BG-04 — `pwrite*` TCP egress sniff parity

- **Theme:** Egress syscall coverage  
- **Surface:** `raw_tp/sys_enter` (`NR_pwrite64`, `NR_pwritev`, `NR_pwritev2`)  
- **Gap:** Today these paths only bump `unobserved_egress_syscalls_observed` (PR-E); no HTTP/TLS sniff correlation to `(tgid,fd)` tuple like `write`/`writev`.  
- **Acceptance (draft):** When `tls_sni` / HTTP sniff gates are on and tuple exists for the fd, attempt same bounded peek path as `NR_WRITE` / `NR_WRITEV` for IPv4 TCP (verifier-safe caps unchanged). Emit digest/agent metrics if new reserve-failure paths appear.  
- **Dependencies:** `coldstep_connect_tuple_fetch`, existing sniff helpers in `trace_tls_write.inc` / `trace_http_obs.inc`.  
- **Risk:** Verifier complexity on arm64/x86 matrix; must stay within existing probe-read patterns.

---

## #2 — BG-01 — Per-syscall "unobserved egress" triage

- **Theme:** Egress syscall coverage  
- **Surface:** same trace program  
- **Gap:** Single aggregate counter mixes multiple NR values (`trace_connect.bpf.c` PR-E comment); operators cannot tell whether blind traffic is `pwrite*` vs future gaps.  
- **Acceptance (draft):** Replace or supplement global counter with a **small fixed map** (one slot per tracked NR, or PC array keyed by syscall id within a bounded set) exported to Go JSONL/digest as optional KPIs. Document cardinality and CI impact.  
- **Dependencies:** `internal/agent` map readers + tests.

---

## #3 — BG-02 — Multi-iovec payload visibility (TLS / HTTP)

- **Theme:** Payload capture limits  
- **Surface:** `sendmsg`, `writev`, TLS/HTTP helpers  
- **Gap:** Only `iov[0]` is read; `msg_iovlen > 1` / `vlen > 1` increments dedicated counters (`udp_sendmsg_multi_iovec_observed`, `tls_writev_multi_iovec_observed`) but drops payload from JSONL (`trace_connect.bpf.c` PR-D block).  
- **Acceptance (draft):** Bounded strategy only (unrolled loop cap N, or second-iov peek when first peek fails TLS/HTTP prefix tests). No unlimited iov walk. Tests when counters fire in CI fixtures.  
- **Dependencies:** Verifier budget; possibly agent-side merge of fragments if multi-ringbuf emission is avoided.

---

## #4 — BG-03 — `sendmmsg` multi-message visibility

- **Theme:** Egress syscall coverage  
- **Surface:** `NR_sendmmsg`  
- **Gap:** Only first `mmsghdr` is passed to `handle_udp_obs_sendmsg`; messages 2..N not introspected (`trace_connect.bpf.c` M-01 comment). Distinct from multi-iovec counter semantics.  
- **Acceptance (draft):** At minimum, separate **counter for `vlen_ul > 1`** (multi-message) per M-01 audit; optional bounded inspection of second message if verifier allows. Agent JSONL field if new counter is user-visible.  
- **Dependencies:** Agent wiring (`UdpSendmsgMultiIovecObserved` naming collision avoidance).

---

## #5 — BG-08 — Tuple cache hygiene

- **Theme:** Correlation / maps  
- **Surface:** `connect4_by_tgid_fd` LRU  
- **Gap:** `close(2)` cleanup removed by design; LRU bounds staleness but misses exact eviction semantics for long-lived processes.  
- **Acceptance (draft):** Optional `sys_enter_close` or tracepoint arm that deletes `(tgid,fd)` when cheaply derivable; measure map pressure / false correlation rates in CI smoke.  
- **Dependencies:** New syscall NR handling or tracepoint program; loader attach order.

---

## #6 — BG-05 — `io_uring` beyond setup counter

- **Theme:** Async / bypass  
- **Surface:** research (not raw_tp alone)  
- **Gap:** `io_uring_setup` increments counter; completions bypass `sys_enter` hooks (`trace_connect.bpf.c` comment).  
- **Acceptance (draft):** Research memo with candidate hooks (BPF tracepoints, perf, policy sysctl alignment); **no** production promise until threat model agreed.  
- **Dependencies:** Kernel-version matrix; possibly separate lightweight BPF collection.

---

## #7 — BG-06 — IPv6

- **Theme:** Address family  
- **Surface:** entire detect/enforce stack  
- **Gap:** Explicitly unsupported across policy + BPF (`README` / enforce programs).  
- **Acceptance (draft):** Epic decomposition (tuple shapes, CI runners, policy trie types); out of scope for single PR.  
- **Dependencies:** Product decision.

---

## #8 — BG-07 — QUIC / UDP-encapsulated TLS

- **Theme:** Protocol  
- **Surface:** UDP paths vs TCP write sniff  
- **Gap:** TLS SNI sniff targets TCP-shaped cleartext ClientHello on tracked syscalls; QUIC embeds crypto in UDP datagrams (different observation model).  
- **Acceptance (draft):** Research-only backlog item; link to digest honesty already discouraging QUIC for curl TLS tests.  
- **Dependencies:** Protocol scope decision.

---

## Self-check

- Each item has ID, theme, rough acceptance, deps.  
- Memo ordering differs (theme-first); backlog order is canonical for sequencing.
