// Package tracelsmenforce loads the trace_lsm_enforce.bpf.c BPF object via
// cilium/ebpf bpf2go-generated bindings.
//
// Loader pattern: direct `//go:generate` line — no per-arch flags needed.
// trace_lsm_enforce.bpf.c attaches LSM hooks (BPF LSM programs) that
// receive kernel-defined LSM hook arguments and do not include
// bpf/trace_connect_obs.h, so the per-arch syscall-NR table is not
// referenced and no `-D__TARGET_ARCH_<arch>` define is required. A
// one-line `//go:generate` therefore suffices (no run_bpf2go.go helper).
//
// See internal/bpf/traceenforce/gen.go for an explanation of the two
// loader patterns used in this repo.
package tracelsmenforce

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -cc clang -no-strip -target bpfel,bpfeb -cflags "-O2 -g -Wall -Werror -I../../../bpf -I/usr/include/bpf" Tracelsmenforce ../../../bpf/trace_lsm_enforce.bpf.c -- -I../../../bpf -I/usr/include/bpf
