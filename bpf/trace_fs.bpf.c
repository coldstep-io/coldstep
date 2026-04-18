#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "trace_connect_obs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#if defined(bpf_target_arm64)
#define FS_NR_OPENAT    56
#define FS_NR_UNLINKAT  35
#define FS_NR_RENAMEAT2 276
#define FS_NR_FCHMODAT  53
/*
 * arm64 has no legacy NR_open: glibc on aarch64 always rewrites open(2)
 * to openat(AT_FDCWD, ...) — closing F-K12-04 on arm64 is a no-op.
 * We define FS_NR_OPEN to a sentinel that can never match a real syscall ID
 * so the dispatch branch below compiles uniformly across both arches without
 * an additional per-arch #if at the call site.
 */
#define FS_NR_OPEN -1
#elif defined(bpf_target_x86)
#define FS_NR_OPENAT    257
#define FS_NR_UNLINKAT  263
#define FS_NR_RENAMEAT2 316
#define FS_NR_FCHMODAT  268
/* PR-E (Theme C): legacy open(2) — present on x86_64; signature: open(path, flags, mode). */
#define FS_NR_OPEN 2
#else
#error "coldstep trace_fs: unsupported BPF arch (need bpf_target_x86/arm64)"
#endif

/* O_CREAT = 0100 octal = 0x40: consistent on x86_64 and aarch64 (guarded by #else #error above). */
#define O_CREAT 0x40

#define FS_PATH_MAX 256

/* Op codes embedded in the event (single byte to keep struct small). */
#define FS_OP_CREATE 1
#define FS_OP_UNLINK 2
#define FS_OP_RENAME 3
#define FS_OP_CHMOD  4

struct fs_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 op;
	__u8 path[FS_PATH_MAX];
	__u8 _pad[3]; /* explicit 4-byte alignment; matches Go fsEventWire layout */
};
_Static_assert(sizeof(struct fs_event) == 284,
	       "fs_event wire size must match fsEventWireSize=284 in agent_linux.go");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} fs_agent_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} fs_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} fs_ringbuf_reserve_failures SEC(".maps");

static __always_inline void note_fs_ringbuf_reserve_failed(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&fs_ringbuf_reserve_failures, &k);

	if (!v)
		return;
	__sync_fetch_and_add(v, 1);
}

static __always_inline int fs_enabled(void)
{
	__u32 k = 0;
	__u8 *v = bpf_map_lookup_elem(&fs_agent_cfg, &k);

	return v && *v;
}

static __always_inline void submit_fs_event(unsigned long path_ptr, __u8 op)
{
	struct fs_event *ev;
	__u64 pt;

	if (!path_ptr)
		return;
	ev = bpf_ringbuf_reserve(&fs_events, sizeof(*ev), 0);
	if (!ev) {
		note_fs_ringbuf_reserve_failed();
		return;
	}

	pt = bpf_get_current_pid_tgid();
	ev->tgid = (__u32)(pt >> 32);
	ev->tid = (__u32)pt;
	ev->op = op;
	__builtin_memset(ev->comm, 0, sizeof(ev->comm));
	__builtin_memset(ev->path, 0, sizeof(ev->path));
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	bpf_probe_read_user_str(ev->path, sizeof(ev->path), (const void *)path_ptr);

	bpf_ringbuf_submit(ev, 0);
}

/*
 * raw_tp/sys_enter: ctx->args[0] is struct pt_regs *; ctx->args[1] is syscall number.
 * Args via ns_read_syscall_arg (x86_64 + arm64).
 */
SEC("raw_tp/sys_enter")
int handle_fs_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	unsigned long regs_ptr = ctx->args[0];
	long id = (long)ctx->args[1];
	struct pt_regs *regs = (struct pt_regs *)regs_ptr;

	if (!fs_enabled())
		return 0;
	if (!regs)
		return 0;

	if (id == FS_NR_OPENAT) {
		unsigned long arg1, arg2;

		if (ns_read_syscall_arg(regs, 1, &arg1))
			return 0;
		if (ns_read_syscall_arg(regs, 2, &arg2))
			return 0;
		if (!(arg2 & O_CREAT))
			return 0;
		submit_fs_event(arg1, FS_OP_CREATE);
	} else if (id == FS_NR_OPEN) {
		/*
		 * PR-E: legacy open(2) — signature open(path, flags, mode).
		 * On arm64 FS_NR_OPEN is sentinel -1 (no real syscall) so this
		 * branch is dead code there but kept uniform for source-shape parity.
		 * On x86_64 it catches Python/Ruby/old C code that calls glibc
		 * `open()` directly without going through openat(AT_FDCWD, ...).
		 */
		unsigned long arg0, arg1;

		if (ns_read_syscall_arg(regs, 0, &arg0))
			return 0;
		if (ns_read_syscall_arg(regs, 1, &arg1))
			return 0;
		if (!(arg1 & O_CREAT))
			return 0;
		submit_fs_event(arg0, FS_OP_CREATE);
	} else if (id == FS_NR_UNLINKAT) {
		unsigned long arg1;

		if (ns_read_syscall_arg(regs, 1, &arg1))
			return 0;
		submit_fs_event(arg1, FS_OP_UNLINK);
	} else if (id == FS_NR_RENAMEAT2) {
		unsigned long arg3;

		/* emit destination path (arg3 = newpath) */
		if (ns_read_syscall_arg(regs, 3, &arg3))
			return 0;
		submit_fs_event(arg3, FS_OP_RENAME);
	} else if (id == FS_NR_FCHMODAT) {
		unsigned long arg1;

		if (ns_read_syscall_arg(regs, 1, &arg1))
			return 0;
		submit_fs_event(arg1, FS_OP_CHMOD);
	}

	return 0;
}
