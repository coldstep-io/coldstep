/*
 * Observability-only BPF: raw_tp/sys_enter on GitHub-hosted Ubuntu runners (x86_64 and arm64).
 * IPv6 is not supported; tracing is IPv4-focused.
 *   - IPv4-only TCP connect + (tgid,fd)->dst map for optional TLS ClientHello correlation
 *   - IPv4 egress via sendto(2) and sendmsg(2) → `udp_events` ringbuf (name legacy; includes TCP sendto;
 *     not complete for all UDP egress paths)
 *   - Optional cleartext HTTP/1 on destination port 80 and TLS ClientHello sniff on
 *     write/writev/pwrite64/pwritev/pwritev2/sendto (single tuple lookup shared by both sniffs)
 *   - LRU map eviction handles stale (tgid,fd) entries (close(2) cleanup removed)
 *
 * Logic is split across bpf/trace_tcp_obs.inc, trace_udp_obs.inc, and trace_http_obs.inc
 * (structural layout similar to separate tcp/udp/http probe sources).
 *
 * cgroup + LSM defend live in bpf/trace_defend_all.bpf.c (internal/bpf/defend).
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "trace_connect_obs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} connect_events SEC(".maps");

/*
 * `udp_events` is a misnomer kept for wire-compat: the ringbuf carries every
 * IPv4 datagram-style egress observed via the `sendto(2)` / `sendmsg(2)`
 * raw_tp arms in trace_udp_obs.inc — which on Linux includes TCP sockets that
 * use those syscalls (e.g. early Postgres clients, some HTTP libraries that
 * call `sendto(fd, buf, len, 0, NULL, 0)`). Userspace must distinguish UDP
 * vs TCP from the protocol context (or the connect_events tuple cache) if
 * the distinction matters; the JSONL `udp_send` row simply records "what was
 * sent via the udp-style hook" regardless of L4. Renaming the map would
 * break consumers that grep on the `udp_events` symbol.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} udp_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} http_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} tls_agent_cfg SEC(".maps");

struct {
	/*
	 * Correlation cache can retain stale entries when close/exit paths are missed.
	 * LRU bounds stale pressure while preserving best-effort tuple correlation.
	 */
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct connect4_tuple);
} connect4_by_tgid_fd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} connect4_tuple_update_failures SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} udp_ringbuf_reserve_failures SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} connect_ringbuf_reserve_failures SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} http_ringbuf_reserve_failures SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} tls_ringbuf_reserve_failures SEC(".maps");

/*
 * Multi-iovec visibility counters (PR-D, Theme D of the 2026-04-18 review).
 *
 * sendmsg(2) takes a struct msghdr whose msg_iov is a vector of iovecs;
 * writev(2) similarly takes an iovec vector. The BPF observation code in
 * trace_udp_sendmsg.inc / trace_tls_write.inc only reads iov[0] for the
 * verifier-friendly bounded path. When user code uses a multi-buffer
 * scatter/gather call (msg_iovlen > 1 / vlen > 1), iov[1..n] payload is
 * silently dropped from the JSONL/digest. These counters surface the
 * frequency of that scenario so operators can decide whether to invest in
 * full multi-iovec capture (would require unrolled bounded loops in BPF).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} udp_sendmsg_multi_iovec_observed SEC(".maps");

/*
 * BG-03: NR_SENDMMSG multi-message visibility counter. Increments once per
 * sendmmsg(2) call with vlen > 1 (mmsghdr vector length > 1, distinct from
 * per-message iovec fragmentation). Separate from udp_sendmsg_multi_iovec_observed
 * — the iovec counter still describes the first mmsghdr's msg_iovlen, while
 * this counter describes how many sendmmsg calls have N>1 messages (of which
 * only message 0 is introspected). PERCPU_ARRAY for write-side contention.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} sendmmsg_multi_message_observed SEC(".maps");

/*
 * BG-03 (Gap 3): NR_SENDMMSG per-message extra-message visibility.
 *
 * Messages 1..SENDMMSG_EXTRA_MAX (7) are introspected by an unrolled
 * #pragma unroll loop in the sys_enter dispatcher; messages with index
 * > SENDMMSG_EXTRA_MAX are not introspected (defend mode is unaffected
 * because cgroup/sendmsg4 fires per-message inside __sys_sendmmsg).
 *
 * This counter sums (vlen - SENDMMSG_EXTRA_MAX - 1) across every
 * sendmmsg call whose vlen > SENDMMSG_EXTRA_MAX + 1, i.e. the count of
 * individual extra messages we could not observe. Distinct from
 * sendmmsg_multi_message_observed which counts CALLS (not messages).
 * PERCPU_ARRAY for write-side contention.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} sendmmsg_unobserved_extra SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} tls_writev_multi_iovec_observed SEC(".maps");

/*
 * BG-01 (supersedes PR-E aggregate counter): per-syscall partial-observe
 * counter for IPv4 egress / fd-write syscalls that emit destination/length
 * telemetry but no HTTP/TLS payload sniff. Operators can see *which* path
 * fired, not just a total, so they can decide whether the gap matters for
 * their workload before requesting full per-syscall sniff arms (would
 * require iov-vector reads + extra verifier complexity for sendmmsg, and
 * pipe->socket fd correlation for sendfile/splice).
 *
 * Slot layout:
 *   0 = sendfile / sendfile64 (tracked via handle_udp_obs_emit_pt only)
 *   1 = splice (same)
 *   2 = sendmmsg (only first mmsghdr inspected; messages 2..N dropped)
 *   3 = reserved (keeps max_entries a power of two for future use)
 *
 * PERCPU_ARRAY keeps the increment hot-path lock-free; userspace sums
 * across CPUs via Lookup(key, &vals []u32). Slot count is bounded (4)
 * for verifier-friendly constant-key access from the sys_enter dispatcher.
 */
#define PARTIAL_OBS_SENDFILE 0
#define PARTIAL_OBS_SPLICE   1
#define PARTIAL_OBS_SENDMMSG 2

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} partial_egress_observed SEC(".maps");

/*
 * io_uring_setup(2) detection counter. Any invocation of io_uring_setup is a
 * security-relevant signal: io_uring operations bypass all syscall-based BPF
 * hooks (raw_tp/sys_enter, cgroup/connect4). The sysctl disable in the
 * composite action (io-uring-disable input) blocks setup outright, but this
 * counter catches cases where the sysctl is off or was not applied.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} io_uring_setup_observed SEC(".maps");

/*
 * Telemetry integrity canary (red-team B3). Userspace writes a monotonic
 * sequence number into canary_trigger[0]. The next sys_enter invocation
 * picks it up, emits a canary_event into connect_events, and clears the
 * trigger. If the canary event never arrives in userspace, the ringbuf
 * pipeline is compromised (buffer exhaustion, attacker suppression, etc.).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} canary_trigger SEC(".maps");

/*
 * Canary event emitted through connect_events ringbuf. Wire size = 16
 * (4 magic + 4 pad + 8 seq_nr). The magic prefix 0xCA1A1210 ("canary")
 * lets the Go reader distinguish canary events from connect_event records
 * by checking the first 4 bytes (connect_event starts with tgid which is
 * always a small PID, never this value).
 */
struct canary_event {
	__u32 magic;   /* 0xCA1A1210 */
	__u32 _pad;
	__u64 seq_nr;
};
#define CANARY_MAGIC 0xCA1A1210u

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} tls_events SEC(".maps");

/*
 * AUDIT(5a): null checked — every `note_*` counter helper below follows the
 * same pattern: bpf_map_lookup_elem then `if (!v) return;` before deref.
 */
static __always_inline void note_connect4_tuple_update_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&connect4_tuple_update_failures, &k);

	if (!v)
		return;
	/* PERCPU_ARRAY: each CPU owns its slot; no global atomic contention. */
	(*v)++;
}

static __always_inline void note_udp_ringbuf_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&udp_ringbuf_reserve_failures, &k);

	if (!v)
		return;
	(*v)++;
}

static __always_inline void note_connect_ringbuf_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&connect_ringbuf_reserve_failures, &k);

	if (!v)
		return;
	(*v)++;
}

static __always_inline void note_http_ringbuf_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&http_ringbuf_reserve_failures, &k);

	if (!v)
		return;
	(*v)++;
}

static __always_inline void note_tls_ringbuf_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&tls_ringbuf_reserve_failures, &k);

	if (!v)
		return;
	(*v)++;
}

static __always_inline void note_udp_sendmsg_multi_iovec(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&udp_sendmsg_multi_iovec_observed, &k);

	if (!v)
		return;
	__sync_fetch_and_add(v, 1);
}

static __always_inline void note_tls_writev_multi_iovec(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&tls_writev_multi_iovec_observed, &k);

	if (!v)
		return;
	__sync_fetch_and_add(v, 1);
}

static __always_inline void note_io_uring_setup_observed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&io_uring_setup_observed, &k);

	if (!v)
		return;
	__sync_fetch_and_add(v, 1);
}

/*
 * note_partial_egress: bump the per-syscall partial-observe counter (BG-01).
 * `slot` is a compile-time constant from the PARTIAL_OBS_* enum above; the
 * verifier sees a bounded uint key and a single-slot PERCPU_ARRAY access.
 */
static __always_inline void note_partial_egress(int slot)
{
	__u32 k = (__u32)slot;
	__u32 *v = bpf_map_lookup_elem(&partial_egress_observed, &k);

	if (!v)
		return;
	__sync_fetch_and_add(v, 1);
}

#include "trace_tcp_obs.inc"
#include "trace_udp_obs.inc"
#include "trace_http_obs.inc"
#include "trace_tls_write.inc"
/*
 * trace_udp_sendmsg.inc must come last among these — its BG-02 iov[1] peek
 * path calls try_emit_tls_clienthello (defined in trace_tls_write.inc) and
 * handle_http_obs_emit{,_pt} (defined in trace_http_obs.inc).
 */
#include "trace_udp_sendmsg.inc"

/*
 * Canary emit helper: reads canary_trigger[0]; if non-zero, reserves a
 * canary_event in connect_events ringbuf, writes the sequence, and clears
 * the trigger. Cost: one map lookup per sys_enter (negligible).
 */
static __always_inline void maybe_emit_canary(void)
{
	__u32 k = 0;
	/* AUDIT(5a): null checked — `!seq` short-circuits before `*seq`. */
	__u64 *seq = bpf_map_lookup_elem(&canary_trigger, &k);

	if (!seq || *seq == 0)
		return;

	/* AUDIT(5b): submit/discard paired — only exit between reserve and
	 * submit is the `!ev` early return (no slot held). Submit unconditional. */
	struct canary_event *ev = bpf_ringbuf_reserve(&connect_events,
						      sizeof(struct canary_event), 0);
	if (!ev) {
		/* ringbuf full — the failure itself is the signal userspace
		 * detects (canary timeout). */
		return;
	}
	ev->magic = CANARY_MAGIC;
	ev->_pad = 0;
	ev->seq_nr = *seq;
	bpf_ringbuf_submit(ev, 0);

	/* Clear trigger so we don't re-emit on every subsequent syscall. */
	__u64 zero = 0;
	bpf_map_update_elem(&canary_trigger, &k, &zero, BPF_ANY);
}

SEC("raw_tp/sys_enter")
int handle_raw_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = (void *)ctx->args[0];
	long id = (long)ctx->args[1];

	if (!regs)
		return 0;

	/* Telemetry integrity canary: check on every syscall entry (one map
	 * lookup, ~50ns). Fires only when userspace has armed a sequence. */
	maybe_emit_canary();

	if (id == (long)COLDSTEP_NR_CONNECT) {
		unsigned long di_ul = 0, si_ul = 0;

		if (ns_read_syscall_arg(regs, 0, &di_ul))
			return 0;
		if (ns_read_syscall_arg(regs, 1, &si_ul))
			return 0;
		return handle_tcp_obs_connect((__u32)di_ul, si_ul);
	}

	if (id == (long)COLDSTEP_NR_SENDTO) {
		unsigned long di_ul = 0, buf_ptr = 0, len_ul = 0, addr_ul = 0;
		__u32 len;
		__be16 sin_port;
		__be32 sin_addr;
		/* Populated once on connected sendto; reused for udp/http/tls below. */
		struct connect4_tuple ct = {};
		__u64 tuple_pt = 0;

		/* Read args in syscall order: fd(0), buf(1), len(2), [skip flags(3)], addr(4). */
		if (ns_read_syscall_arg(regs, 0, &di_ul))
			return 0;
		if (ns_read_syscall_arg(regs, 1, &buf_ptr))
			return 0;
		if (ns_read_syscall_arg(regs, 2, &len_ul))
			return 0;
		if (ns_read_syscall_arg(regs, 4, &addr_ul))
			return 0;

		if (!addr_ul) {
			if (coldstep_connect_tuple_fetch((__u32)di_ul, &ct, &tuple_pt))
				return 0;
			__builtin_memcpy(&sin_port, ct.dport, sizeof(sin_port));
			__builtin_memcpy(&sin_addr, ct.daddr, sizeof(sin_addr));
		} else {
			if (read_ipv4_sockaddr(addr_ul, &sin_port, &sin_addr))
				return 0;
		}

		len = coldstep_syscall_len_u32(len_ul);
		if (len > 0x00100000)
			len = 0x00100000;

		if (!addr_ul)
			handle_udp_obs_emit_pt(tuple_pt, sin_port, sin_addr, len);
		else
			handle_udp_obs_emit(sin_port, sin_addr, len);

		if (sin_port == bpf_htons(80) && len >= 4 &&
		    http_prefix_looks_like_request(buf_ptr, len)) {
			if (!addr_ul)
				handle_http_obs_emit_pt(tuple_pt, buf_ptr, len, sin_port, sin_addr);
			else
				handle_http_obs_emit(buf_ptr, len, sin_port, sin_addr);
		}

		/*
		 * TLS ClientHello sniff: connected sendto(NULL) uses cached connect tuple +
		 * tuple_pt from coldstep_connect_tuple_fetch. Explicit sockaddr sendto mirrors
		 * the HTTP branch — synthesize tuple bytes from sin_addr/sin_port (same layout
		 * as connect4_by_tgid_fd values) so try_emit_tls_clienthello_from_tuple can run.
		 */
		if (!addr_ul) {
			try_emit_tls_clienthello_from_tuple(&ct, buf_ptr, len, tuple_pt);
		} else {
			struct connect4_tuple st = {};

			st.in_use = 1;
			st._pad = 0;
			__builtin_memcpy(st.daddr, &sin_addr, sizeof(st.daddr));
			__builtin_memcpy(st.dport, &sin_port, sizeof(st.dport));
			try_emit_tls_clienthello_from_tuple(&st, buf_ptr, len,
							    bpf_get_current_pid_tgid());
		}

		return 0;
	}

	if (id == (long)COLDSTEP_NR_SENDMSG) {
		unsigned long di_ul = 0, msg_hdr_ptr = 0;

		if (ns_read_syscall_arg(regs, 0, &di_ul))
			return 0;
		if (ns_read_syscall_arg(regs, 1, &msg_hdr_ptr))
			return 0;
		return handle_udp_obs_sendmsg((__u32)di_ul, msg_hdr_ptr);
	}

	if (id == (long)COLDSTEP_NR_WRITE || id == (long)COLDSTEP_NR_WRITEV ||
	    id == (long)COLDSTEP_NR_PWRITE64 ||
	    id == (long)COLDSTEP_NR_PWRITEV ||
	    id == (long)COLDSTEP_NR_PWRITEV2) {
		unsigned long di_ul = 0, si_ul = 0, dx_ul = 0;

		if (ns_read_syscall_arg(regs, 0, &di_ul))
			return 0;
		if (ns_read_syscall_arg(regs, 1, &si_ul))
			return 0;
		if (ns_read_syscall_arg(regs, 2, &dx_ul))
			return 0;

		return handle_write_obs_sys_enter(id, di_ul, si_ul, dx_ul);
	}

	if (id == (long)COLDSTEP_NR_SENDMMSG) {
		unsigned long di_ul = 0, msgvec_ptr = 0, vlen_ul = 0;

		if (ns_read_syscall_arg(regs, 0, &di_ul))
			return 0;
		if (ns_read_syscall_arg(regs, 1, &msgvec_ptr))
			return 0;
		if (ns_read_syscall_arg(regs, 2, &vlen_ul))
			return 0;

		/*
		 * M-01 (BPF Deep Audit, 2026-05-01): Do NOT bump
		 * `udp_sendmsg_multi_iovec_observed` here on `vlen_ul > 1`.
		 * `vlen_ul` is the number of `struct mmsghdr` entries
		 * (multi-message count), not the per-message scatter/gather
		 * `msg_iovlen`. The named counter describes iovec
		 * fragmentation; conflating it with multi-message count made
		 * operators misread the metric.
		 *
		 * The correct multi-iovec increment still fires from
		 * `handle_udp_obs_sendmsg` in `trace_udp_sendmsg.inc` when the first
		 * message's `msg_iovlen > 1`. Userspace cannot today
		 * distinguish "multi-message but single-iovec each" because
		 * adding a new counter slot would also require touching the
		 * Go agent (out of scope for this BPF-only fix); see
		 * `internal/agent/agent_linux.go` references to
		 * `UdpSendmsgMultiIovecObserved`.
		 *
		 * Note: we still only inspect the first mmsghdr entry below
		 * (its embedded `struct msghdr` shares offset 0 with
		 * `mmsghdr.msg_hdr`); messages 2..N are not introspected.
		 */

		/*
		 * BG-01: bump the per-syscall partial-observe counter before
		 * delegating to the first-message handler so the count
		 * reflects every sendmmsg call, including vlen==1.
		 */
		note_partial_egress(PARTIAL_OBS_SENDMMSG);

		/* struct mmsghdr starts with struct msghdr */
		int rc = handle_udp_obs_sendmsg((__u32)di_ul, msgvec_ptr);

		/*
		 * BG-03 (Gap 3): when the caller passed vlen > 1, walk extra
		 * messages 1..SENDMMSG_EXTRA_MAX via an unrolled bounded loop.
		 * bpf_loop() requires kernel >= 5.17 which excludes our
		 * ubuntu-22.04 (5.15) CI matrix; #pragma unroll keeps verifier
		 * complexity bounded and works back to 5.4.
		 *
		 * sendmmsg_multi_message_observed counts CALLS with vlen > 1
		 * (one bump per call). sendmmsg_unobserved_extra counts the
		 * INDIVIDUAL extra messages beyond index SENDMMSG_EXTRA_MAX
		 * that the unrolled loop could not reach.
		 *
		 * struct mmsghdr LP64 stride: msg_hdr[56] + msg_len[4] + pad[4] = 64.
		 */
#define SENDMMSG_STRIDE 64UL
#define SENDMMSG_EXTRA_MAX 7
		if (vlen_ul > 1) {
			__u32 k = 0;
			/* AUDIT(5a): null checked — used only inside `if (v)`. */
			__u32 *v = bpf_map_lookup_elem(&sendmmsg_multi_message_observed, &k);

			if (v)
				__sync_fetch_and_add(v, 1);

			__u32 vlen32 = (__u32)(vlen_ul & 0xffffff);
			/*
			 * No `break` inside the unrolled loop: clang on
			 * ubuntu-22.04 (clang-14) refuses to unroll a loop with
			 * a runtime-conditioned break and fails with
			 * -Wpass-failed=transform-warning under -Werror. Guard
			 * the body with an `if` instead so all 7 iterations are
			 * statically present and skipped when i >= vlen32.
			 *
			 * AUDIT(5c): pointer arithmetic bounded — `i` is the
			 * unrolled loop induction variable in [1, 7]; the
			 * resulting offset (i * 64) is at most 448 bytes from
			 * the userspace mmsghdr vector base, well within the
			 * kernel sys_sendmmsg argument range. Pointer is fed
			 * to bpf_probe_read_user inside the helper, which
			 * performs the kernel-side bound check.
			 * AUDIT(5d): loop bound is constant — SENDMMSG_EXTRA_MAX=7,
			 * verifier-provable. #pragma unroll forces full unroll.
			 */
#pragma unroll
			for (int i = 1; i <= SENDMMSG_EXTRA_MAX; i++) {
				if ((__u32)i < vlen32) {
					handle_udp_obs_sendmsg_extra((__u32)di_ul,
								      msgvec_ptr + (unsigned long)i * SENDMMSG_STRIDE);
				}
			}

			if (vlen32 > SENDMMSG_EXTRA_MAX + 1) {
				__u32 ke = 0;
				/* AUDIT(5a): null checked — used only inside `if (ve)`. */
				__u32 *ve = bpf_map_lookup_elem(&sendmmsg_unobserved_extra, &ke);

				if (ve)
					__sync_fetch_and_add(ve, vlen32 - (SENDMMSG_EXTRA_MAX + 1));
			}
		}
#undef SENDMMSG_STRIDE
#undef SENDMMSG_EXTRA_MAX

		return rc;
	}

	if (id == (long)COLDSTEP_NR_SENDFILE) {
		unsigned long di_ul = 0, count_ul = 0;
		__be16 sin_port;
		__be32 sin_addr;
		__u32 len;
		__u64 pt;

		/* arg0 = out_fd */
		if (ns_read_syscall_arg(regs, 0, &di_ul))
			return 0;
		/* arg3 = count */
		if (ns_read_syscall_arg(regs, 3, &count_ul))
			return 0;

		len = coldstep_syscall_len_u32(count_ul);
		if (len > 0x00100000)
			len = 0x00100000;

		if (!coldstep_tuple_dst_for_fd((__u32)di_ul, &sin_port, &sin_addr, &pt))
			handle_udp_obs_emit_pt(pt, sin_port, sin_addr, len);
		note_partial_egress(PARTIAL_OBS_SENDFILE);
		return 0;
	}

	if (id == (long)COLDSTEP_NR_SPLICE) {
		unsigned long fd_out_ul = 0, len_ul = 0;
		__be16 sin_port;
		__be32 sin_addr;
		__u32 len;
		__u64 pt;

		/* arg2 = fd_out */
		if (ns_read_syscall_arg(regs, 2, &fd_out_ul))
			return 0;
		/* arg4 = len */
		if (ns_read_syscall_arg(regs, 4, &len_ul))
			return 0;

		len = coldstep_syscall_len_u32(len_ul);
		if (len > 0x00100000)
			len = 0x00100000;

		if (!coldstep_tuple_dst_for_fd((__u32)fd_out_ul, &sin_port, &sin_addr, &pt))
			handle_udp_obs_emit_pt(pt, sin_port, sin_addr, len);
		note_partial_egress(PARTIAL_OBS_SPLICE);
		return 0;
	}

	/*
	 * BG-01 supersedes the PR-E aggregate counter: per-syscall partial-observe
	 * counts (sendfile, splice, sendmmsg) are bumped inside their dispatch arms
	 * above. Operators read partial_egress_observed[0..2] to see which path drove
	 * the gap, instead of a single aggregate that hid the breakdown.
	 */

	/*
	 * io_uring_setup(2) detection: any call is a security signal because
	 * io_uring operations bypass syscall-based BPF hooks entirely.
	 * Counter-only — the sysctl disable (io-uring-disable action input)
	 * is the defense mechanism; this is the detection fallback.
	 */
	if (id == (long)COLDSTEP_NR_IO_URING_SETUP) {
		note_io_uring_setup_observed();
		return 0;
	}

	return 0;
}
