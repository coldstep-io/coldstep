// Package traceconnect loads the trace_connect.bpf.c BPF object via cilium/ebpf
// bpf2go-generated bindings.
//
// Loader pattern: indirect via run_bpf2go.go (//go:build ignore main program).
//
// trace_connect.bpf.c contains `raw_tp/sys_enter` programs that switch on
// architecture-specific syscall numbers (NR_connect/NR_sendto/NR_sendmsg/
// NR_write …) declared in bpf/trace_connect_obs.h behind
// `#if defined(bpf_target_arm64)` / `bpf_target_x86` macros. Those macros
// are set by bpf_tracing.h which keys off `__TARGET_ARCH_x86` /
// `__TARGET_ARCH_arm64`. Therefore the bpf2go invocation must pass
// `-D__TARGET_ARCH_<arch>` derived from `runtime.GOARCH`, which is awkward
// to express in a single `//go:generate` line; we use a tiny Go program
// (run_bpf2go.go) to build the cflags string at generate time.
//
// Sister loaders that use this same pattern (because their .bpf.c also
// dispatches by syscall NR): tracedns, tracefs, tracebpfaudit.
// tracebpfaudit belongs to this indirect-loader family because it also
// includes bpf/trace_connect_obs.h for COLDSTEP_NR_BPF — the bpf(2)
// syscall NR table is arch-specific (x86_64 vs arm64), so the
// `-D__TARGET_ARCH_<arch>` define must be derived from `runtime.GOARCH`
// at generate time.
//
// Loaders that do NOT need per-arch flags (no syscall-NR dispatch) use the
// simpler direct `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go …`
// line in their own gen.go: traceenforce, traceexec, tracefork.
package traceconnect

//go:generate go run ./run_bpf2go.go
