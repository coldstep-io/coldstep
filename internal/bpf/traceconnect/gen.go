// Package traceconnect loads the trace_connect.bpf.c BPF object via cilium/ebpf
// bpf2go-generated bindings.
//
// trace_connect.bpf.c contains `raw_tp/sys_enter` programs that switch on
// architecture-specific syscall numbers (NR_connect/NR_sendto/NR_sendmsg/
// NR_write …) declared in bpf/trace_connect_obs.h behind
// `#if defined(bpf_target_arm64)` / `bpf_target_x86` macros. Those macros
// are set by bpf_tracing.h which keys off `__TARGET_ARCH_x86` /
// `__TARGET_ARCH_arm64`. Because a single `//go:generate` line cannot easily
// derive `-D__TARGET_ARCH_<arch>` from `runtime.GOARCH`, the shared helper
// at internal/bpf/bpfgen/main.go builds the cflags string at generate time.
//
// Sister probe packages that use this same indirect helper (their .bpf.c
// also dispatches by syscall NR): tracedns, tracefs, tracebpfaudit,
// tracelsmdefend. Probes that do NOT need per-arch flags (no syscall-NR
// dispatch) use the simpler direct bpf2go invocation in their own gen.go:
// tracedefend, traceexec, tracefork.
package traceconnect

//go:generate go run ../bpfgen/main.go Traceconnect trace_connect.bpf.c
