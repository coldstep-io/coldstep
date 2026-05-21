/*
 * KTLS (kernel-TLS) offload detection.
 *
 * Filters raw_tp/sys_enter for setsockopt(2) at level SOL_TLS (282) and
 * optname TLS_TX (1) or TLS_RX (2). After a successful KTLS handshake the
 * kernel takes over TLS encryption — the application writes plaintext and
 * the kernel encrypts on the wire — so trace_tls_write.inc's ClientHello
 * sniffer only sees record fragments and can no longer resolve SNI on the
 * affected fd. Emitting an event at setsockopt-enter is how userspace marks
 * those sockets as deliberately SNI-invisible (P3-1).
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "trace_connect_obs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* setsockopt syscall number; differs between x86_64 and arm64. */
#if defined(bpf_target_arm64)
#define KTLS_NR_SETSOCKOPT 208
#elif defined(bpf_target_x86)
#define KTLS_NR_SETSOCKOPT 54
#else
#error "coldstep trace_ktls: unsupported BPF arch (need bpf_target_x86/arm64)"
#endif

/* setsockopt(fd, SOL_TLS, optname, ...) constants from <linux/tls.h>. */
#define KTLS_SOL_TLS 282
#define KTLS_TLS_TX  1
#define KTLS_TLS_RX  2

struct ktls_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u32 fd;
	__u8 direction; /* 1 = tx, 2 = rx */
	__u8 _pad[3];
};
_Static_assert(sizeof(struct ktls_event) == 32,
	       "ktls_event wire size must match ktlsEventWireSize=32 in agent_linux.go");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	/*
	 * 64 KiB. Earlier sizing (4 KiB) assumed KTLS setsockopt is rare per
	 * run, but a single Go binary using crypto/tls + KTLS handshakes
	 * during dependency fetch can burst dozens of offload events in the
	 * first second — the ringbuf reserve-failure counter then climbed
	 * before the userspace reader drained it. 64 KiB gives the reader
	 * room to absorb that burst without dropping events on the floor
	 * (P3-bug-audit Bug 4).
	 */
	__uint(max_entries, 1 << 16);
} ktls_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ktls_ringbuf_reserve_failures SEC(".maps");

static __always_inline void note_ktls_reserve_failed(void)
{
	__u32 k = 0;
	/* AUDIT(5a): null checked — `!v` returns before deref. */
	__u32 *v = bpf_map_lookup_elem(&ktls_ringbuf_reserve_failures, &k);

	if (!v)
		return;
	(*v)++;
}

SEC("raw_tp/sys_enter")
int handle_raw_sys_enter_ktls(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = (void *)ctx->args[0];
	long id = (long)ctx->args[1];
	unsigned long fd_ul = 0, level_ul = 0, optname_ul = 0;
	__u8 dir;

	if (!regs)
		return 0;
	if (id != (long)KTLS_NR_SETSOCKOPT)
		return 0;

	if (ns_read_syscall_arg(regs, 0, &fd_ul))
		return 0;
	if (ns_read_syscall_arg(regs, 1, &level_ul))
		return 0;
	if ((int)level_ul != KTLS_SOL_TLS)
		return 0;
	if (ns_read_syscall_arg(regs, 2, &optname_ul))
		return 0;

	switch ((int)optname_ul) {
	case KTLS_TLS_TX:
		dir = 1;
		break;
	case KTLS_TLS_RX:
		dir = 2;
		break;
	default:
		return 0;
	}

	/* AUDIT(5b): submit/discard paired — only exit between reserve and
	 * submit is the `!ev` early return (no slot held). Submit unconditional. */
	struct ktls_event *ev = bpf_ringbuf_reserve(&ktls_events, sizeof(*ev), 0);
	if (!ev) {
		note_ktls_reserve_failed();
		return 0;
	}

	__u64 pt = bpf_get_current_pid_tgid();
	ev->tgid = (__u32)(pt >> 32);
	ev->tid = (__u32)pt;
	ev->fd = (__u32)fd_ul;
	ev->direction = dir;
	ev->_pad[0] = 0;
	ev->_pad[1] = 0;
	ev->_pad[2] = 0;
	__builtin_memset(ev->comm, 0, sizeof(ev->comm));
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
