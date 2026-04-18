# Network egress BPF hook notes (`ubuntu-latest`)

**Scope:** GitHub-hosted **`ubuntu-latest` (amd64) only** — not other Linux distros, self-hosted images, or `ubuntu-arm` runners unless explicitly expanded later.

**Repository state (2026-04-12):** This note matches **`bpf/trace_connect.bpf.c`** (`raw_tp/sys_enter` multiplex: TCP connect, UDP sendto, cleartext HTTP/80, optional **TLS ClientHello / SNI** sniff on `write` when enabled). **`bpf/trace_dns.bpf.c`** covers DNS reply sniffing separately.

## Chosen primary hook (TCP IPv4 destination)

**Tracepoint:** unified `sys_enter` (covers all syscalls; filter by NR)  
**SEC name:** `raw_tp/sys_enter` (must use **raw** tracepoint so `bpf_raw_tracepoint_args` matches `TP_ARGS(regs, id)`; `tp/...` loads `BPF_PROG_TYPE_TRACEPOINT` with a different context)  
**Userspace attach:** `link.AttachRawTracepoint` with name **`sys_enter`** (see `available_events` / libbpf raw_tp conventions).  
**Access pattern:** `struct bpf_raw_tracepoint_args`; `ctx->args[0]` holds the `struct pt_regs *` value, `ctx->args[1]` = syscall number. For **x86_64**, user `sockaddr *` for `connect` is in `pt_regs.si`. **`trace_connect.bpf.c`** uses **`bpf_core_read`** into **`unsigned long`** locals **only inside** `handle_raw_sys_enter`, then passes scalars into helpers (verifier **6.17** `azure` can reject **`bpf_core_read`** on **`&regs->…`** after **`regs`** crosses deep inlined callees). **`trace_dns.bpf.c`** reads **`&regs->…`** directly in smaller programs. `NIGHTSTALKER_NR_CONNECT` defaults to **42** (see `trace_connect.bpf.c`).

**Rationale:** Programs attached to `syscalls/sys_enter_connect` receive the **syscall trace record layout** (see `perf_call_bpf_enter` in the kernel), not `(fd, uservaddr, addrlen)` as `ctx->args[0..2]`. That mismatch dropped real connects when using `bpf_raw_tracepoint_args`. The generic `raw_syscalls/sys_enter` tracepoint exposes `pt_regs` + NR, so the user pointer matches the syscall ABI.

**Userspace read:** `bpf_probe_read_user` at fixed **IPv4 `sockaddr_in`** offsets (family at +0, port at +2, addr at +4). Emit only **`AF_INET`** (2) in v1; skip `AF_INET6` until a follow-up. **Connected `sendto`** with **`dest_addr == NULL`** has no user `sockaddr`; **`trace_connect.bpf.c`** resolves **`sin_port` / `sin_addr`** from **`connect4_by_tgid_fd`** (filled on **`connect(2)`**) so UDP KPI / HTTP / **TLS sniff** still see a tuple (OpenSSL often sends the ClientHello via **`sendto`** on a connected TCP socket).

## Alternatives considered

| Hook | Why not v1 |
|------|------------|
| `tp/syscalls/sys_enter_connect` with `ctx->args[1]` = `sockaddr *` | Incorrect for BPF; args are not laid out as raw syscall parameters (see above). |
| `fentry` / `kprobe` on `__x64_sys_connect` | Same portability risk as prior `sched_process_exec` fentry issues on some runner kernels. |
| `inet_sock_set_state` | Powerful but heavier; more state to filter for “egress connect” vs connect intent. |
| `syscalls/sys_exit_connect` | Gives return value (success/fail) but needs pairing or duplicate work; v1 logs **attempt** at enter. |

## Validation

Confirm on a live `ubuntu-latest` job: `test -f /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/id` (debugfs may require privileges; CI integration tests run as root).

---

## UDP IPv4 egress (`sendto`)

**Tracepoint:** same `raw_tp/sys_enter` as TCP (single attach, filter by NR).  
**x86_64 `__NR_sendto`:** **44** (userspace `unistd_64.h`).  
**Registers:** `pt_regs.si` = `const void *buf`, `pt_regs.dx` = `size_t len`, `pt_regs.r8` = `const struct sockaddr *addr` (flags in `r10`, `addrlen` in `r9`; not required for IPv4 dst extraction).  
**Userspace read:** `bpf_probe_read_user` on `sockaddr_in` at `addr` (family +2 port +4 IPv4), same layout as `connect`. Skip non-`AF_INET`.

**Emit:** one **`udp`** ringbuf record per qualifying `sendto` (destination IPv4 + port + tgid/tid + comm + syscall `len`). This is **noisy** on busy hosts; caps rely on ringbuf sizing and userspace. For GitHub-hosted runners, volume is acceptable for nightstalker-demo.

**Alternatives considered**

| Hook | Why not v1 |
|------|------------|
| `recvfrom` for ingress | Plan targets **egress** visibility first; ingress doubles attach surface and mixes direction semantics. |
| `sendmsg` / `recvmsg` only | Many tools use `sendto`; v1 covers common CLI (`dig`, `nc -u`). `sendmsg` can be a follow-up for iovec paths. |
| cgroup/socket filters | Harder to keep portable on shared runners; syscall tracepoint pattern already proven for TCP. |

---

## HTTP/1.x cleartext (request sniff)

**Reality:** There is no kernel “HTTP” tracepoint. Visibility is **payload-adjacent** only.

**Chosen approach (v1):** On `sendto` when **`sockaddr_in.sin_port == 80`** (network order), copy the first **N** bytes (e.g. 192) of the user buffer with `bpf_probe_read_user`, emit a separate **`http_sniff`** ringbuf record. Userspace parses for `GET`/`POST`/`HEAD`/`PUT` and `Host:` / request-line (best-effort on partial buffers).

**Port filter:** **dport 80** only in v1 to cut noise and match cleartext HTTP expectations. **HTTPS** is out of scope here (no TLS decryption; optional later **ClientHello/SNI** track).

**Alternatives considered**

| Hook | Why not v1 |
|------|------------|
| `write(2)` on socket fd | fd→socket typing is unreliable at syscall enter without extra state. |
| `sys_enter_sendmsg` only | Misses `sendto` users (e.g. scripted probes); dual hooks duplicate logic unless merged into one `sys_enter` multiplexer. |
| Full request body | BPF instruction / ringbuf budget; bounded capture + JSONL as source of truth. |

**Limitations:** Partial writes, pipelining, and chunked encoding can produce **fragments**; parser must tolerate incomplete lines. Summary view may redact query strings; JSONL policy can carry fuller paths where allowed.

---

## TLS ClientHello / SNI (detect, IPv4, optional)

**Goal:** Emit **`tls`** JSONL (and digest rows) with **SNI hostname** from the first **ClientHello** bytes on **IPv4 TCP** egress, **without** TLS decryption.

**Tracepoint:** same **`raw_tp/sys_enter`** multiplexer.

**x86_64 syscalls**

| Syscall | `__NR_*` | First arg (fd) | Notes |
|---------|----------|------------------|-------|
| `connect` | 42 | `pt_regs.di` | Existing path reads **`sockaddr *` from `si`**; also record **`(tgid,fd) → {daddr,dport}`** in a BPF **HASH** for later correlation. |
| `write` | 1 | `di` | User buffer **`si`**, length **`dx`**. Only sampled when a **userspace flag map** enables TLS sniffing (default **0** at load; set to **1** when `NIGHTSTALKER_FEATURE_GATES=tls_sni=1`). |
| `close` | 3 | `di` | **Delete** `(tgid,fd)` map entry to limit **fd reuse** false positives. **`close` is processed even when TLS sniffing is disabled** so the map stays bounded. |

**Fast reject on `write`:** Require `len >= 11` (record header + first byte of handshake payload). Check **`buf[0]==0x16`**, **`buf[1]==0x03`**, **`buf[5]==0x01`** (ClientHello **after** the 5-byte TLS record header). Do **not** treat “first 5 bytes” as including `0x01`—that byte is at index **5**.

**Known gaps (v1)**

- **Multi-write ClientHello:** if the handshake is split across several **`write`** calls, only the first chunk starting with **`0x16`** is captured; continuation writes are skipped (no reassembly buffer in v1).
- **`sendmsg` / `writev`:** stacks that never use **`write(2)`** for the first flight need a follow-up multiplexer branch (**`__NR_sendmsg` = 46** on x86_64; fd still in **`di`**).
- **Inherited sockets:** a process may **`write`** TLS on a connected fd without a **`connect`** in the **same** `tgid` → **no** map entry → **false negative**.

**Perf:** The raw tracepoint already runs on **every** syscall; the **`write`** path should **`return 0` immediately** when the **enable** map is **0** (single `bpf_map_lookup_elem` + byte test) before heavier work.
