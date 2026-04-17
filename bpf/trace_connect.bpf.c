/*
 * Observability-only BPF: raw_tp/sys_enter on GitHub-hosted Ubuntu runners (x86_64 and arm64):
 *   - IPv4-only TCP connect + (tgid,fd)->dst map for optional TLS ClientHello correlation
 *   - IPv4-only UDP via sendto(2) (not complete for all UDP egress paths)
 *   - Optional cleartext HTTP/1 on destination port 80 and TLS ClientHello sniff on write/sendto
 *   - close(2) clears (tgid,fd) map entries
 *
 * Logic is split across bpf/trace_tcp_obs.inc, trace_udp_obs.inc, and trace_http_obs.inc
 * (structural layout similar to separate tcp/udp/http probe sources).
 *
 * cgroup enforcement lives in bpf/trace_enforce.bpf.c (internal/bpf/traceenforce).
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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} connect4_tuple_update_failures SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} tls_events SEC(".maps");

static __always_inline void note_connect4_tuple_update_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&connect4_tuple_update_failures, &k);

	if (!v)
		return;
	/* Shared map value may be updated concurrently; use atomic increment. */
	__sync_fetch_and_add(v, 1);
}

#include "trace_tcp_obs.inc"
#include "trace_udp_obs.inc"
#include "trace_http_obs.inc"
#include "trace_tls_write.inc"

SEC("raw_tp/sys_enter")
int handle_raw_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = (void *)ctx->args[0];
	long id = (long)ctx->args[1];

	if (!regs)
		return 0;

	if (id == (long)COLDSTEP_NR_CONNECT) {
		unsigned long di_ul = 0, si_ul = 0;

		if (ns_read_syscall_arg(regs, 0, &di_ul))
			return 0;
		if (ns_read_syscall_arg(regs, 1, &si_ul))
			return 0;
		return handle_tcp_obs_connect((__u32)di_ul, si_ul);
	}

	if (id == (long)COLDSTEP_NR_SENDTO) {
		unsigned long buf_ptr, len_ul, addr_ul, di_ul = 0;
		__u32 len;
		__be16 sin_port;
		__be32 sin_addr;

		if (ns_read_syscall_arg(regs, 1, &buf_ptr))
			return 0;
		if (ns_read_syscall_arg(regs, 2, &len_ul))
			return 0;
		if (ns_read_syscall_arg(regs, 0, &di_ul))
			return 0;
		if (ns_read_syscall_arg(regs, 4, &addr_ul))
			return 0;

		if (!addr_ul) {
			__u64 pt = bpf_get_current_pid_tgid();
			__u32 tgid = (__u32)(pt >> 32);
			__u64 mkey = ((__u64)tgid << 32) | (__u64)(__u32)di_ul;
			struct connect4_tuple *tup = bpf_map_lookup_elem(&connect4_by_tgid_fd, &mkey);

			if (!tup || !tup->in_use)
				return 0;
			__builtin_memcpy(&sin_port, tup->dport, sizeof(sin_port));
			__builtin_memcpy(&sin_addr, tup->daddr, sizeof(sin_addr));
		} else {
			if (read_ipv4_sockaddr(addr_ul, &sin_port, &sin_addr))
				return 0;
		}

		len = (__u32)len_ul;
		if (len > 0x00100000)
			len = 0x00100000;

		handle_udp_obs_emit(sin_port, sin_addr, len);

		if (sin_port == bpf_htons(80) && len >= 4 &&
		    http_prefix_looks_like_request((void *)buf_ptr, len))
			handle_http_obs_emit(buf_ptr, len, sin_port, sin_addr);

		try_emit_tls_clienthello((__u32)di_ul, buf_ptr, len);
		return 0;
	}

	if (id == (long)COLDSTEP_NR_WRITE || id == (long)COLDSTEP_NR_CLOSE) {
		unsigned long di_ul = 0, si_ul = 0, dx_ul = 0;

		if (ns_read_syscall_arg(regs, 0, &di_ul))
			return 0;
		if (id == (long)COLDSTEP_NR_WRITE) {
			if (ns_read_syscall_arg(regs, 1, &si_ul))
				return 0;
			if (ns_read_syscall_arg(regs, 2, &dx_ul))
				return 0;
		}
		return handle_tls_obs_sys_enter(id, di_ul, si_ul, dx_ul);
	}

	return 0;
}
