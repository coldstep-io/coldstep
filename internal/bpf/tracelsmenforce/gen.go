// Package tracelsmenforce loads the trace_lsm_enforce.bpf.c BPF object via
// cilium/ebpf bpf2go-generated bindings.
//
// Loader pattern: indirect via run_bpf2go.go (//go:build ignore main program).
//
// trace_lsm_enforce.bpf.c includes bpf/trace_connect_obs.h for read_ipv4_sockaddr on
// the sendmsg explicit-destination path. That header's syscall-NR table is keyed by
// bpf_target_* macros set from __TARGET_ARCH_*; bpf2go must pass
// `-D__TARGET_ARCH_x86` or `-D__TARGET_ARCH_arm64` derived from runtime.GOARCH.
//
// See internal/bpf/traceconnect/gen.go for the two loader patterns used in this repo.
package tracelsmenforce

//go:generate go run ./run_bpf2go.go
