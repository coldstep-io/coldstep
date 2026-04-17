/*
 * DNS response sniff (IPv4 A records) — pairs recvfrom sys_enter with sys_exit.
 * Syscall ABI matches trace_connect (x86_64 + arm64 via trace_connect_obs.h).
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "trace_connect_obs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * Keep user-read size bounded for verifier/runtime safety. Note this can miss
 * larger EDNS-enabled DNS responses; telemetry is best-effort, not full replay.
 */
#define DNS_SNIFF_MAX 512

struct recvfrom_pending {
	__u64 buf_user;
	__u32 max_len;
	__u32 pad;
};

struct dns_sniff_event {
	__u32 len;
	__u8 data[DNS_SNIFF_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct recvfrom_pending);
} recvfrom_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} dns_events SEC(".maps");

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

	if (id != (long)COLDSTEP_NR_RECVFROM)
		return 0;

	if (ns_read_syscall_arg(regs, 1, &buf_user))
		return 0;
	if (!buf_user)
		return 0;

	if (ns_read_syscall_arg(regs, 2, &max_len_u))
		return 0;

	val.buf_user = buf_user;
	if (max_len_u > DNS_SNIFF_MAX)
		val.max_len = DNS_SNIFF_MAX;
	else
		val.max_len = (__u32)max_len_u;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&recvfrom_buf, &pid_tgid, &val, BPF_ANY);
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
	if (orig_nr != (unsigned long)COLDSTEP_NR_RECVFROM)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pending = bpf_map_lookup_elem(&recvfrom_buf, &pid_tgid);
	if (!pending)
		return 0;
	bpf_map_delete_elem(&recvfrom_buf, &pid_tgid);

	if (ret < 12 || ret > DNS_SNIFF_MAX)
		return 0;

	copy_len = (__u32)ret;
	if (copy_len > pending->max_len)
		copy_len = pending->max_len;
	if (copy_len < 12)
		return 0;
	/* Verifier: bpf_probe_read_user size must be bounded by a constant; map max_len is opaque. */
	if (copy_len > DNS_SNIFF_MAX)
		copy_len = DNS_SNIFF_MAX;

	if (bpf_probe_read_user(hdr, sizeof(hdr), (void *)pending->buf_user))
		return 0;
	/* QR bit must be 1 (response) */
	if ((hdr[2] & 0x80) == 0)
		return 0;

	ev = bpf_ringbuf_reserve(&dns_events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->len = copy_len;
	if (bpf_probe_read_user(ev->data, copy_len, (void *)pending->buf_user)) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
