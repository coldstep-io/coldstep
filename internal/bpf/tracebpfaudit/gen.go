// Package tracebpfaudit loads the trace_bpf_audit.bpf.c BPF object via
// cilium/ebpf bpf2go-generated bindings. trace_bpf_audit.bpf.c attaches a
// `raw_tp/sys_enter` program that filters on the bpf(2) syscall NR
// (COLDSTEP_NR_BPF) declared in bpf/trace_connect_obs.h, whose
// syscall-number table is keyed by the per-arch macros set from
// `__TARGET_ARCH_x86` / `__TARGET_ARCH_arm64`. See
// internal/bpf/bpfgen/main.go and internal/bpf/traceconnect/gen.go for the
// shared rationale.
package tracebpfaudit

//go:generate go run ../bpfgen/main.go Tracebpfaudit trace_bpf_audit.bpf.c
