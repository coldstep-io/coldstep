/*
 * Combined cgroup + LSM defend programs for mode: defend — IPv4 only.
 *
 * Two SEC families share one bpf2go object so Go-side loaders can attach
 * both paths from a single defend.DefendObjects. The cgroup hooks
 * (`cgroup/connect4`, `cgroup/sendmsg4`) provide the always-on enforcement
 * path. The LSM hooks (`lsm/socket_connect`, `lsm/socket_sendmsg`) attach
 * when CONFIG_BPF_LSM is enabled and "bpf" is in the kernel's lsm= chain.
 *
 * Map name layout:
 *   cgroup section — bare names (deny_events, allowed_ipv4, …)
 *   LSM section    — lsm_ prefix (lsm_deny_events, lsm_allowed_ipv4, …)
 *   shared         — dns_cache + allowed_domains (from bpf/dns_cache.h)
 *
 * trace_connect_obs.h supplies read_ipv4_sockaddr (used by the LSM
 * sendmsg path) and dispatches syscall NRs via __TARGET_ARCH_* macros —
 * therefore the package generator uses ../bpfgen/main.go (which injects
 * -D__TARGET_ARCH_*) rather than the simpler direct bpf2go line.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace_connect_obs.h"
#include "defend_lpm_key.h"
#include "dns_cache.h"
#include "deny_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef EPERM
#define EPERM 1
#endif

#define COLDSTEP_DEFEND_KEY_MODE 0
#define COLDSTEP_DEFEND_MODE_DETECT 0
#define COLDSTEP_DEFEND_MODE_DEFEND 1

#define COLDSTEP_PROTO_TCP 1
#define COLDSTEP_PROTO_UDP 2

#define COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED 1

_Static_assert(sizeof(struct deny_event) == 46,
	       "deny_event wire size must match denyEventWireSize=46 in agent_linux.go");

#include "trace_defend_cgroup.inc"
#include "trace_lsm_defend_lsm.inc"
