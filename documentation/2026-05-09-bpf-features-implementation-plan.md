# BPF new features — implementation plan

**Source backlog:** [`2026-05-08-bpf-gaps-backlog.md`](./2026-05-08-bpf-gaps-backlog.md) (rank **#1–#8**).

**Scope:** Detect-mode egress telemetry + agent wiring unless noted. **IPv6 / QUIC / full io_uring** are out of this execution plan except research stubs.

**Verification gate:** `scripts/build-agent-linux.sh` + `go test -tags=integration ./internal/agent/...` on Linux (Docker or CI); never Windows `go test` for BPF semantics.

---

## Principles

1. **Verifier-first:** Any new branch in `trace_connect.bpf.c` / includes must stay within patterns already proven on **ubuntu-latest / arm** matrices (bounded reads, constant probe sizes).
2. **Wire compatibility:** Prefer extending existing ringbufs/events before adding new JSONL `type` values; document any new digest KPI fields.
3. **Incremental PRs:** One BG-ID per PR when possible; merge smallest vertical slice (BPF + agent read path + test + CHANGELOG).

---

## Phase A — BG-04: `pwrite*` TCP sniff parity

**Goal:** When `(tgid,fd)` has a cached IPv4 tuple, run the same TLS ClientHello + HTTP/80 sniff path as `write`/`writev` for **`pwrite64`**, **`pwritev`**, **`pwritev2`** on that fd — instead of only incrementing `unobserved_egress_syscalls_observed`.

### Steps

1. **Args audit:** Confirm syscall argument layout for **`COLDSTEP_NR_PWRITE64`**, **`PWRITEV`**, **`PWRITEV2`** on x86_64 and arm64 (`bpf/trace_connect_obs.h`). Document fd index, user buffer pointer, length (and iov pointer for *v variants).
2. **BPF:** Extend **`trace_tls_write.inc`** `handle_tls_obs_sys_enter()` with branches for the three NR values (mirror **`NR_WRITE`** / **`NR_WRITEV`** logic; reuse **`try_emit_tls_clienthello`**). For HTTP port 80 sniff parity, either call existing **`handle_http_obs_emit`** path from **`trace_connect.bpf.c`** or factor a shared helper — **avoid duplicating** HTTP prefix logic if it stays in sendto/connect arms only today (grep `handle_http_obs` call sites).
3. **Dispatch:** In **`trace_connect.bpf.c`**, replace the **`pwrite*`** branch that only calls **`note_unobserved_egress_syscall()`** with a call into extended TLS handler (and HTTP if applicable), falling back to counter only when tuple lookup fails or fd is not TCP-correlated (preserve current “best effort” semantics).
4. **Tests:** Integration test under **`internal/agent`** (Linux + root + `integration` tag): minimal program using **`pwrite`** / **`pwritev`** on a connected TCP socket to **:80** or **:443** with feature gates, asserting JSONL presence analogous to existing **`write`** tests.
5. **Docs:** **`README.md`** / **`internal/report/digest.go`** bullets only if user-visible behavior changes; **`CHANGELOG.md`** `[Unreleased]`.

### Risks

- **Wrong register mapping** on one arch breaks verifier or silently reads garbage — mitigate with **`abi_test.go`** / static asserts where structs permit.
- **Offset argument on pwrite:** Must not confuse length vs offset when reading **buf** pointer.

### Exit criteria

- **`coldstep-ci`** integration jobs green; no regression in **`unobserved`** counter for non-socket fds if current behavior was “always bump”.

---

## Phase B — BG-01: Per-syscall unobserved egress triage

**Goal:** Operators can see **which** syscall numbers drive blind egress, not a single aggregate.

### Steps

1. Replace or augment **`unobserved_egress_syscalls_observed`** with a **bounded map** (e.g. **PERCPU_ARRAY** or small hash keyed by **NR** capped to `{ pwrite*, … }`) — design max slots **≤ 16** to keep verifier load predictable.
2. **`internal/agent`:** Read new map(s), expose optional JSONL summary fields or readiness counters (follow **`agent_linux_policy_maps.go`** patterns).
3. **Digest:** One row or KPI line when non-zero (avoid noisy per-event spam).
4. **Tests:** Unit tests for map readers; integration optional if JSONL shape changes.

### Dependency

- Prefer landing **after Phase A** so **`pwrite*`** stops dominating the aggregate counter and triage reflects remaining gaps.

---

## Phase C — BG-02: Multi-iovec visibility (bounded)

**Goal:** Reduce silent drops when **`msg_iovlen > 1`** or **`writev` vlen > 1** for TLS/HTTP sniff.

### Steps

1. **Design choice (pick one in PR):**  
   - **C1:** Second-iov peek only if first **`bpf_probe_read_user`** fails TLS/HTTP fingerprint; or  
   - **C2:** Unrolled **N=2** iov read max (verifier budget).
2. Implement in **`trace_udp_sendmsg.inc`** / **`trace_tls_write.inc`** / **`trace_http_obs.inc`** as appropriate; **do not** walk arbitrary iov depth.
3. **Counters:** Keep or refine **`udp_sendmsg_multi_iovec_observed`** / **`tls_writev_multi_iovec_observed`** semantics; update digest copy if behavior changes.
4. **Tests:** Synthetic **`writev`** or **`sendmsg`** with **2 ioves** in integration harness.

---

## Phase D — BG-03: `sendmmsg` multi-message counter

**Goal:** Separate **multi-message** (`vlen > 1`) from **multi-iovec** (`msg_iovlen > 1`) per M-01 comment.

### Steps

1. Add dedicated map counter **`sendmmsg_multi_message_observed`** (name TBD) increment when **`vlen_ul > 1`** on **`NR_SENDMMSG`**.
2. **`internal/agent`:** Wire counter to JSONL/readiness (mirror **`UdpSendmsgMultiIovecObserved`** naming clarity — avoid conflation in variable names).
3. **Docs:** One paragraph in **`README`** or digest honesty layer.

---

## Phase E — BG-08: Tuple LRU hygiene (optional)

**Goal:** Reduce stale **`connect4_by_tgid_fd`** correlation.

### Steps

1. Evaluate **`sys_enter_close`** tracepoint vs **`raw_tp/sys_enter`** close NR — attachment order vs existing programs.
2. **`bpf_map_delete_elem`** on **`(tgid,fd)`** when fd matches; guard verifier bounds.
3. **Metrics:** LRU overflow / delete failure counts if applicable.

**Defer** if attach complexity risks CI flake.

---

## Research tracks (no production SLA)

| ID | Output | Deliverable |
| --- | --- | --- |
| BG-05 | io_uring completions | Vault memo + kernel tracepoint matrix (`knowledge/wiki/`). |
| BG-06 | IPv6 | Epic doc + policy/BPF shape RFC — **not** started here. |
| BG-07 | QUIC | Memo citing RFC 9000 / TLS-in-UDP limits; detect honesty only. |

---

## Suggested PR sequence

| Order | PR focus | Backlog IDs |
| ----- | -------- | ------------- |
| 1 | BG-04 `pwrite*` parity | BG-04 |
| 2 | BG-01 unobserved breakdown | BG-01 |
| 3 | BG-02 multi-iovec (chosen strategy) | BG-02 |
| 4 | BG-03 sendmmsg counter | BG-03 |
| 5 | BG-08 close cleanup (optional) | BG-08 |

---

## References

- **`bpf/trace_connect.bpf.c`** — PR-D, PR-E, M-01 comments.  
- **`documentation/2026-05-08-bpf-gaps-wiki-memo.md`** — theme narrative.
