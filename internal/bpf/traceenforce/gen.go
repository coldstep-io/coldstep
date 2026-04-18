// Package traceenforce loads the trace_enforce.bpf.c BPF object via
// cilium/ebpf bpf2go-generated bindings.
//
// Loader pattern: direct `//go:generate` line — no per-arch flags needed.
// trace_enforce.bpf.c attaches `cgroup/connect4` and `cgroup/sendmsg4`
// hooks, which receive a kernel-defined `bpf_sock_addr` context. There are
// no architecture-specific syscall numbers to dispatch on, so the cflags
// string is the same for every GOARCH and a one-line `//go:generate`
// suffices (no run_bpf2go.go helper).
//
// Sister loaders that share this direct pattern: traceexec, tracefork.
// Loaders that need the indirect run_bpf2go.go pattern (because their
// .bpf.c uses raw_tp/sys_enter with arch-specific syscall NRs):
// traceconnect, tracedns, tracefs.
package traceenforce

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -cc clang -no-strip -target bpfel,bpfeb -cflags "-O2 -g -Wall -Werror -I../../../bpf -I/usr/include/bpf" Traceenforce ../../../bpf/trace_enforce.bpf.c -- -I../../../bpf -I/usr/include/bpf
