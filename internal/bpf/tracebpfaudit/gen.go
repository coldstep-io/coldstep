// Package tracebpfaudit loads the trace_bpf_audit.bpf.c BPF object via
// cilium/ebpf bpf2go-generated bindings.
//
// Loader pattern: indirect via run_bpf2go.go (//go:build ignore main program).
// trace_bpf_audit.bpf.c attaches a `raw_tp/sys_enter` program that filters
// on the bpf(2) syscall NR (COLDSTEP_NR_BPF) declared in
// bpf/trace_connect_obs.h, whose syscall-number table is keyed by the
// per-arch macros set from `__TARGET_ARCH_x86` / `__TARGET_ARCH_arm64`.
// bpf2go must therefore be invoked with `-D__TARGET_ARCH_<arch>` derived
// from `runtime.GOARCH`; the run_bpf2go.go helper builds that flag string
// at generate time.
//
// See internal/bpf/traceconnect/gen.go for a fuller explanation of the two
// loader patterns used in this repo.
package tracebpfaudit

//go:generate go run ./run_bpf2go.go
