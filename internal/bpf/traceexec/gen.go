// Package traceexec loads the trace_exec.bpf.c BPF object via cilium/ebpf
// bpf2go-generated bindings.
//
// Loader pattern: direct `//go:generate` line — no per-arch flags needed.
// trace_exec.bpf.c attaches a tracepoint at sched/sched_process_exec,
// which is a stable kernel tracepoint (not a syscall raw_tp), so no
// architecture-specific syscall-number constants are required.
//
// See internal/bpf/traceenforce/gen.go for an explanation of the two
// loader patterns used in this repo.
package traceexec

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -cc clang -no-strip -target bpfel,bpfeb -cflags "-O2 -g -Wall -Werror -I../../../bpf -I/usr/include/bpf" Traceexec ../../../bpf/trace_exec.bpf.c -- -I../../../bpf -I/usr/include/bpf
