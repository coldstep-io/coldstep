// Package tracelsmdefend loads the trace_lsm_defend.bpf.c BPF object via
// cilium/ebpf bpf2go-generated bindings. trace_lsm_defend.bpf.c includes
// bpf/trace_connect_obs.h for read_ipv4_sockaddr on the sendmsg
// explicit-destination path; that header's syscall-NR table is keyed by
// bpf_target_* macros set from __TARGET_ARCH_*. See
// internal/bpf/bpfgen/main.go and internal/bpf/traceconnect/gen.go for the
// shared rationale.
package tracelsmdefend

//go:generate go run ../bpfgen/main.go Tracelsmdefend trace_lsm_defend.bpf.c
