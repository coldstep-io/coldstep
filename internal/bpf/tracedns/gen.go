// Package tracedns loads the trace_dns.bpf.c BPF object via cilium/ebpf
// bpf2go-generated bindings. trace_dns.bpf.c includes trace_connect_obs.h
// which dispatches recvfrom by architecture-specific syscall NR
// (NR_recvfrom), so bpf2go must be invoked with `-D__TARGET_ARCH_<arch>`
// derived from `runtime.GOARCH`. See internal/bpf/bpfgen/main.go and
// internal/bpf/traceconnect/gen.go for the shared rationale.
package tracedns

//go:generate go run ../bpfgen/main.go Tracedns trace_dns.bpf.c
