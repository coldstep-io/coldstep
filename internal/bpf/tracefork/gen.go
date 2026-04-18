// Package tracefork loads the trace_fork.bpf.c BPF object via cilium/ebpf
// bpf2go-generated bindings.
//
// Loader pattern: direct `//go:generate` line — no per-arch flags needed.
// trace_fork.bpf.c attaches a raw tracepoint at sched_process_fork using
// CO-RE on `struct task_struct *parent, *child` (TP_PROTO args), so no
// architecture-specific syscall-number constants are required.
//
// See internal/bpf/traceenforce/gen.go for an explanation of the two
// loader patterns used in this repo.
package tracefork

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -cc clang -no-strip -target bpfel,bpfeb -cflags "-O2 -g -Wall -Werror -I../../../bpf -I/usr/include/bpf" Tracefork ../../../bpf/trace_fork.bpf.c -- -I../../../bpf -I/usr/include/bpf
