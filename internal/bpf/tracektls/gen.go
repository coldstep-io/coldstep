// Package tracektls loads the trace_ktls.bpf.c BPF object via cilium/ebpf
// bpf2go-generated bindings. trace_ktls.bpf.c attaches a raw_tp/sys_enter
// program that filters on the setsockopt(2) syscall NR (KTLS_NR_SETSOCKOPT)
// declared in trace_ktls.bpf.c, whose value is keyed by the per-arch macros
// set from `__TARGET_ARCH_x86` / `__TARGET_ARCH_arm64`. See
// internal/bpf/bpfgen/main.go and internal/bpf/traceconnect/gen.go for the
// shared rationale.
package tracektls

//go:generate go run ../bpfgen/main.go Tracektls trace_ktls.bpf.c
