// Package tracefs loads the trace_fs.bpf.c BPF object via cilium/ebpf
// bpf2go-generated bindings.
//
// Loader pattern: indirect via run_bpf2go.go (//go:build ignore main program).
// trace_fs.bpf.c uses raw_tp/sys_enter on syscall numbers (openat, unlinkat,
// renameat2, fchmodat, …) which differ between x86_64 and arm64; bpf2go is
// therefore invoked with `-D__TARGET_ARCH_<arch>` from `runtime.GOARCH`.
//
// See internal/bpf/traceconnect/gen.go for a fuller explanation of the two
// loader patterns used in this repo.
package tracefs

//go:generate go run ./run_bpf2go.go
