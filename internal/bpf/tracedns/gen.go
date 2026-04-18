// Package tracedns loads the trace_dns.bpf.c BPF object via cilium/ebpf
// bpf2go-generated bindings.
//
// Loader pattern: indirect via run_bpf2go.go (//go:build ignore main program).
// trace_dns.bpf.c includes trace_connect_obs.h which dispatches recvfrom by
// architecture-specific syscall NR (NR_recvfrom). bpf2go must therefore be
// invoked with `-D__TARGET_ARCH_<arch>` derived from `runtime.GOARCH`; the
// run_bpf2go.go helper builds that flag string at generate time.
//
// See internal/bpf/traceconnect/gen.go for a fuller explanation of the two
// loader patterns used in this repo.
package tracedns

//go:generate go run ./run_bpf2go.go
