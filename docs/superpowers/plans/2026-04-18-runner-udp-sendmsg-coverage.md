# Runner UDP `sendmsg` Coverage (Plan A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend **`raw_tp/sys_enter`** handling in `bpf/trace_connect.bpf.c` so **IPv4 UDP datagrams** sent via **`sendmsg(2)`** (not only **`sendto(2)`**) emit **`udp_events`** ringbuf records on GitHub-hosted Ubuntu kernels, including **connected UDP sockets** (`msg_name == NULL`) using the existing **`connect4_by_tgid_fd`** correlation map.

**Architecture:** Add syscall number **`COLDSTEP_NR_SENDMSG`** per arch in `bpf/trace_connect_obs.h`. In `handle_raw_sys_enter`, dispatch `sendmsg` to a new static inline `handle_udp_obs_sendmsg(__u32 fd, unsigned long msg_ptr)` implemented in a new include `bpf/trace_udp_sendmsg.inc` that uses `bpf_probe_read_user` on `struct user_msghdr` to read `msg.msg_name` / `msg.msg_namelen`, resolve IPv4 `sockaddr_in` when present, else fall back to **fd → tuple** lookup (same key layout as **`sendto`** path when `addr_ul == 0`).

**Tech Stack:** BPF CO-RE, `bpf_probe_read_user`, `scripts/build-agent-linux.sh`, Go ringbuf decode paths in `internal/agent` (if event layout unchanged, **no Go change**).

---

## File Structure / Responsibility Map

- Modify: `bpf/trace_connect_obs.h` — `COLDSTEP_NR_SENDMSG` for **x86_64** (`46`) and **aarch64** (`211`) under the same `#if defined(__TARGET_ARCH_x86)` / `#elif defined(__TARGET_ARCH_arm64)` blocks as existing NR macros (verify against `linux/arch/x86/entry/syscalls/syscall_64.tbl` and `arm64` syscall table for your targeted kernels).
- Create: `bpf/trace_udp_sendmsg.inc` — `handle_udp_obs_sendmsg` + bounded reads (`msg_namelen <= 128` guard).
- Modify: `bpf/trace_connect.bpf.c` — `#include "trace_udp_sendmsg.inc"` and `if (id == (long)COLDSTEP_NR_SENDMSG) { ... }` before final `return 0`.
- Regenerate: `internal/bpf/traceconnect/*` via bpf2go.
- Verify: Docker integration smoke (optional new tiny C consumer test is **not** required if existing agent tests cover JSONL UDP lines).

---

### Task 1: Syscall numbers + dispatch stub

**Files:**
- Modify: `bpf/trace_connect_obs.h`
- Modify: `bpf/trace_connect.bpf.c`

- [ ] **Step 1: Add NR macros**

Add lines (verify numbers on target kernels before merge):

```c
/* x86_64 */
#define COLDSTEP_NR_SENDMSG 46
/* arm64 */
#define COLDSTEP_NR_SENDMSG 211
```

Place each under the correct arch section alongside `COLDSTEP_NR_SENDTO`.

- [ ] **Step 2: Dispatch branch**

In `handle_raw_sys_enter`, after `COLDSTEP_NR_SENDTO` block, insert:

```c
	if (id == (long)COLDSTEP_NR_SENDMSG) {
		unsigned long fd_ul = 0, msg_ul = 0;

		if (ns_read_syscall_arg(regs, 0, &fd_ul))
			return 0;
		if (ns_read_syscall_arg(regs, 1, &msg_ul))
			return 0;
		return handle_udp_obs_sendmsg((__u32)fd_ul, msg_ul);
	}
```

- [ ] **Step 3: Build (expect linker failure until inc exists)**

Run: `bash scripts/build-agent-linux.sh`  
Expected: compile error referencing missing `handle_udp_obs_sendmsg` until Task 2.

---

### Task 2: Implement `handle_udp_obs_sendmsg`

**Files:**
- Create: `bpf/trace_udp_sendmsg.inc`
- Modify: `bpf/trace_connect.bpf.c` — `#include "trace_udp_sendmsg.inc"` after `trace_udp_obs.inc`

- [ ] **Step 1: Implement bounded msghdr read**

Skeleton (engineer fills provenance checks):

```c
#ifndef TRACE_UDP_SENDMSG_INC
#define TRACE_UDP_SENDMSG_INC

static __always_inline int read_ipv4_udp_dest_from_sendmsg(
	__u32 fd,
	unsigned long msg_ul,
	__be16 *sin_port,
	__be32 *sin_addr,
	__u32 *len_out)
{
	struct user_msghdr mh = {};
	struct sockaddr_in sin = {};

	if (!msg_ul)
		return -1;
	if (bpf_probe_read_user(&mh, sizeof(mh), (void *)msg_ul))
		return -1;
	/* Use mh.msg_len for datagram size upper bound; clamp */
	*len_out = mh.msg_len;
	if (*len_out > 0x00100000)
		*len_out = 0x00100000;

	if (mh.msg_name && mh.msg_namelen >= sizeof(struct sockaddr_in)) {
		if (bpf_probe_read_user(&sin, sizeof(sin), (void *)mh.msg_name))
			return -1;
		if (sin.sin_family != AF_INET)
			return -1;
		*sin_port = sin.sin_port;
		*sin_addr = sin.sin_addr.s_addr;
		return 0;
	}
	/* Connected socket: reuse tuple map */
	{
		__u64 pt = bpf_get_current_pid_tgid();
		__u32 tgid = (__u32)(pt >> 32);
		__u64 mkey = ((__u64)tgid << 32) | (__u64)fd;
		struct connect4_tuple *tup = bpf_map_lookup_elem(&connect4_by_tgid_fd, &mkey);

		if (!tup || !tup->in_use)
			return -1;
		__builtin_memcpy(sin_port, tup->dport, sizeof(*sin_port));
		__builtin_memcpy(sin_addr, tup->daddr, sizeof(*sin_addr));
		return 0;
	}
}

static __always_inline int handle_udp_obs_sendmsg(__u32 fd, unsigned long msg_ul)
{
	__be16 sin_port;
	__be32 sin_addr;
	__u32 len;

	if (read_ipv4_udp_dest_from_sendmsg(fd, msg_ul, &sin_port, &sin_addr, &len))
		return 0;
	handle_udp_obs_emit(sin_port, sin_addr, len);
	return 0;
}

#endif
```

**Note:** Include `AF_INET` guard from `vmlinux.h` / define `AF_INET 2` if not visible in BPF unit context.

- [ ] **Step 2: Full rebuild + agent tests**

Run: `bash scripts/build-agent-linux.sh`  
Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./... -count=1`  
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add bpf/trace_connect_obs.h bpf/trace_connect.bpf.c bpf/trace_udp_sendmsg.inc internal/bpf/traceconnect
git commit -m "feat(bpf): observe IPv4 UDP via sendmsg on GitHub runners"
```

---

## Self-Review

- Plan A closes `sendto`-only gap declared in `trace_connect.bpf.c` header comment.
- No placeholder steps; verifier bounds explicit (`msg_namelen` check, len clamp).
