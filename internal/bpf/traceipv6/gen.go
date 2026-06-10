// Package traceipv6 loads the observe-only IPv6 egress hooks
// (bpf/trace_ipv6_obs.bpf.c) via cilium/ebpf bpf2go-generated bindings.
//
// Loader pattern: direct `//go:generate` line — no per-arch flags needed.
// trace_ipv6_obs.bpf.c attaches cgroup/connect6 + cgroup/sendmsg6 and
// reads only `struct bpf_sock_addr` fields (user_ip6, user_port), so the
// translation unit needs no syscall-NR dispatch.
//
// H7: detect-mode IPv6 visibility. The defend BPF object already carries
// its own IPv6 cgroup hooks (P0-1 Phase 1 counters + P2-1 Phase 2
// enforcement); this object is loaded in detect mode only, where the
// defend object never attaches and IPv6 would otherwise be invisible.
//
// See internal/bpf/bpfgen/main.go for an explanation of the two loader
// patterns used in this repo.
package traceipv6

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -cc clang -no-strip -target bpfel -cflags "-O2 -g -Wall -Werror -I../../../bpf -I/usr/include/bpf" Traceipv6 ../../../bpf/trace_ipv6_obs.bpf.c -- -I../../../bpf -I/usr/include/bpf
