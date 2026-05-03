/*
 * DNS response sniff (IPv4 A records) — pairs recvfrom sys_enter with sys_exit.
 * Syscall ABI matches trace_connect (x86_64 + arm64 via trace_connect_obs.h).
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "trace_connect_obs.h"
#include "dns_cache.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * DNS_SNIFF_MAX bounds the capture buffer for both the BPF event struct and the
 * bpf_probe_read_user call (which must use sizeof(ev->data) — a compile-time constant —
 * not a runtime scalar; strict 6.x azure verifiers reject dynamic R2 sizes).
 * 4096 covers EDNS0-extended UDP payloads (RFC 6891); standard DNS fits in 512.
 * bpf_probe_read_user always reads the full buffer regardless of copy_len:
 * ev->len records the logical length for userspace to slice correctly.
 */
#define DNS_SNIFF_MAX 4096

struct recvfrom_pending {
	__u64 buf_user;
	__u32 max_len;
	__u32 pad;
};

struct dns_sniff_event {
	__u32 len;
	__u8 is_tcp; /* 1 if record came from TCP read(2); userspace strips RFC 1035 2-byte prefix */
	__u8 _pad[3];
	__u8 data[DNS_SNIFF_MAX];
};
_Static_assert(sizeof(struct dns_sniff_event) == 4 + 1 + 3 + DNS_SNIFF_MAX,
	       "dns_sniff_event wire size must match dnsSniffEventWireSize in agent_linux.go");

struct {
	/*
	 * LRU map so entries from processes that exit between sys_enter and
	 * sys_exit (killed, signalled) are automatically evicted. A plain
	 * BPF_MAP_TYPE_HASH would fill up on runner process churn, causing
	 * bpf_map_update_elem to fail and silently miss DNS responses.
	 */
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct recvfrom_pending);
} recvfrom_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	/*
	 * 1<<24 = 16 MiB: at DNS_SNIFF_MAX=4096 bytes/event this holds ~4,000 events
	 * before back-pressure, matching connect_events and deny_events capacity.
	 * Previously 1<<22 (4 MiB) was sized for 512-byte events (~8,000 events).
	 */
	__uint(max_entries, 1 << 24);
} dns_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} dns_ringbuf_reserve_failures SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} dns_recvfrom_buf_update_failures SEC(".maps");

/*
 * PR-E (Theme C, F-K8-08): TCP DNS response visibility scaffold.
 *
 * UDP DNS sniff (above) covers ~95% of public-internet name resolution. TCP
 * DNS responses occur for:
 *   - Truncated UDP responses: client retries over TCP (RFC 7766; common for
 *     DNSSEC, large TXT records, AXFR/IXFR).
 *   - Stub resolvers configured to use TCP unconditionally (rare but legal).
 *   - DNS-over-TCP (DoT/DoH wire formats use HTTPS — not this path).
 *
 * Full TCP DNS sniff would require:
 *   1. recv(2)/read(2)/recvmsg(2) sys_exit instrumentation (not just recvfrom).
 *   2. Reassembling the 2-byte length prefix (RFC 1035 §4.2.2) followed by
 *      the actual DNS message — multiple TCP reads can split this header.
 *   3. Per-fd buffer state in a map (similar to recvfrom_buf but stateful),
 *      indexed by (tgid, fd) and torn down on close(2).
 *   4. Verifier-friendly bounded read with constant payload size — DNS_SNIFF_MAX
 *      already accommodates the 16-bit length-prefix message size space.
 *
 * For now this PR ships a counter scaffold that always reads zero (no path
 * bumps it yet) so userspace sees the symbol and the digest can flag the gap
 * once a future PR fills in the read/recvmsg sys_exit handler.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} tcp_dns_responses_observed SEC(".maps");

static __always_inline void note_dns_ringbuf_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&dns_ringbuf_reserve_failures, &k);

	if (!v)
		return;
	(*v)++;
}

static __always_inline void note_dns_recvfrom_buf_update_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&dns_recvfrom_buf_update_failures, &k);

	if (!v)
		return;
	__sync_fetch_and_add(v, 1);
}

static __always_inline void note_tcp_dns_response(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&tcp_dns_responses_observed, &k);

	if (!v)
		return;
	__sync_fetch_and_add(v, 1);
}

SEC("raw_tp/sys_enter")
int handle_raw_sys_enter_dns(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = (void *)ctx->args[0];
	long id = (long)ctx->args[1];
	unsigned long buf_user;
	unsigned long max_len_u;
	struct recvfrom_pending val = {};

	if (!regs)
		return 0;

	if (id == (long)COLDSTEP_NR_RECVFROM) {
		if (ns_read_syscall_arg(regs, 1, &buf_user))
			return 0;
		if (ns_read_syscall_arg(regs, 2, &max_len_u))
			return 0;
	} else if (id == (long)COLDSTEP_NR_READ) {
		if (ns_read_syscall_arg(regs, 1, &buf_user))
			return 0;
		if (ns_read_syscall_arg(regs, 2, &max_len_u))
			return 0;
	} else {
		return 0;
	}

	if (!buf_user)
		return 0;

	val.buf_user = buf_user;
	if (max_len_u > DNS_SNIFF_MAX)
		val.max_len = DNS_SNIFF_MAX;
	else
		val.max_len = (__u32)max_len_u;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (bpf_map_update_elem(&recvfrom_buf, &pid_tgid, &val, BPF_ANY))
		note_dns_recvfrom_buf_update_failed();
	return 0;
}

SEC("raw_tp/sys_exit")
int handle_raw_sys_exit_dns(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = (void *)ctx->args[0];
	long ret = (long)ctx->args[1];
	unsigned long orig_nr;
	struct recvfrom_pending *pending;
	struct dns_sniff_event *ev;
	__u32 copy_len;
	__u8 hdr[3];

	if (!regs)
		return 0;

	if (coldstep_read_orig_syscall_nr(regs, &orig_nr))
		return 0;
	if (orig_nr != (unsigned long)COLDSTEP_NR_RECVFROM && orig_nr != (unsigned long)COLDSTEP_NR_READ)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pending = bpf_map_lookup_elem(&recvfrom_buf, &pid_tgid);
	if (!pending)
		return 0;
	bpf_map_delete_elem(&recvfrom_buf, &pid_tgid);

	if (orig_nr == (unsigned long)COLDSTEP_NR_RECVFROM) {
		if (bpf_probe_read_user(hdr, sizeof(hdr), (void *)pending->buf_user))
			return 0;
		/* QR bit must be 1 (response) */
		if ((hdr[2] & 0x80) == 0)
			return 0;
	} else {
		/*
		 * TCP DNS path: RFC 1035 §4.2.2 frames each DNS message with a
		 * 2-byte length prefix, so the DNS header begins at offset 2
		 * and the QR bit lives at byte 2 of that header (= offset 4
		 * of the userspace buffer). We sniff the QR bit only and bump
		 * `tcp_dns_responses_observed` for visibility.
		 *
		 * KNOWN GAP — M-03 (BPF Deep Audit, 2026-05-01): this path
		 * does NOT reassemble TCP streams. We assume the entire
		 * `length-prefix + DNS message` fits in a single `read(2)` /
		 * `recvfrom(2)` call. In practice large responses (DNSSEC,
		 * AXFR/IXFR, big TXT) split across multiple reads — the
		 * length prefix may land in one read and the DNS header in
		 * the next, in which case our offset-4 QR-bit check is
		 * reading payload bytes and the result is meaningless. Full
		 * reassembly would need per-(tgid,fd) parser state plus a
		 * bounded buffer, which is heavy work for the verifier and
		 * was deliberately deferred. The `tcp_dns_responses_observed`
		 * counter surfaces "we saw a TCP DNS reply byte sequence" not
		 * "we successfully decoded one"; userspace digest copy makes
		 * that distinction explicit. TODO: add a sibling
		 * `tcp_dns_responses_skipped_multi_read` counter when the
		 * Go agent is widened (out of scope here).
		 */
		__u8 tcp_hdr[5];
		if (bpf_probe_read_user(tcp_hdr, sizeof(tcp_hdr), (void *)pending->buf_user))
			return 0;
		/* QR bit (byte 2 of DNS header) is at offset 4 */
		if ((tcp_hdr[4] & 0x80) == 0)
			return 0;
		note_tcp_dns_response();
	}

	if (ret < 12 || ret > DNS_SNIFF_MAX)
		return 0;

	copy_len = (__u32)ret;
	if (copy_len > pending->max_len)
		copy_len = pending->max_len;
	if (copy_len < 12)
		return 0;
	/*
	 * Verifier safety: bpf_probe_read_user R2 (size) must be a compile-time
	 * constant. The scalar copy_len is map-derived and opaque to the verifier.
	 * We always read sizeof(ev->data) bytes into the ring buffer slot; ev->len
	 * records the logical length so userspace slices only the valid bytes.
	 * This matches the established pattern in trace_http_obs.inc and
	 * trace_tls_write.inc (both use sizeof(ev->payload) for the same reason).
	 */
	if (copy_len > DNS_SNIFF_MAX)
		copy_len = DNS_SNIFF_MAX;

	ev = bpf_ringbuf_reserve(&dns_events, sizeof(*ev), 0);
	if (!ev) {
		note_dns_ringbuf_reserve_failed();
		return 0;
	}

	ev->len = copy_len;
	ev->is_tcp = (__u8)(orig_nr == (unsigned long)COLDSTEP_NR_READ);
	__builtin_memset(ev->_pad, 0, sizeof(ev->_pad));
	_Static_assert(sizeof(ev->data) == DNS_SNIFF_MAX,
		       "dns sniff data array vs DNS_SNIFF_MAX");
	if (bpf_probe_read_user(ev->data, sizeof(ev->data), (void *)pending->buf_user)) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
