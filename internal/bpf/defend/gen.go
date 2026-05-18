// Package defend loads the combined cgroup + LSM defend BPF object via
// cilium/ebpf bpf2go-generated bindings.
//
// trace_defend_all.bpf.c includes both the cgroup connect4/sendmsg4 hooks
// (from trace_defend_cgroup.inc) and the LSM socket_connect/socket_sendmsg
// hooks (from trace_lsm_defend_lsm.inc). The LSM section pulls in
// bpf/trace_connect_obs.h for read_ipv4_sockaddr, whose syscall-NR
// dispatch is keyed by __TARGET_ARCH_*. The shared bpfgen helper injects
// -D__TARGET_ARCH_<runtime.GOARCH>, so this package generates through
// ../bpfgen/main.go rather than a direct one-line bpf2go invocation.
//
// `go generate ./internal/bpf/defend/...` requires clang + libbpf-dev on
// Linux; CI runs this via scripts/build-agent-linux.sh.
package defend

//go:generate go run ../bpfgen/main.go Defend trace_defend_all.bpf.c
