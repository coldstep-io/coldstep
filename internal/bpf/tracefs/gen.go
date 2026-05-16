// Package tracefs loads the trace_fs.bpf.c BPF object via cilium/ebpf
// bpf2go-generated bindings. trace_fs.bpf.c uses raw_tp/sys_enter on
// syscall numbers (openat, unlinkat, renameat2, fchmodat, …) which differ
// between x86_64 and arm64, so bpf2go must be invoked with
// `-D__TARGET_ARCH_<arch>` from `runtime.GOARCH`. See
// internal/bpf/bpfgen/main.go and internal/bpf/traceconnect/gen.go for the
// shared rationale.
package tracefs

//go:generate go run ../bpfgen/main.go Tracefs trace_fs.bpf.c
