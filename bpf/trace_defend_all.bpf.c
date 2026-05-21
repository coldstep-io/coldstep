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
#include <bpf/bpf_endian.h>
#include "trace_connect_obs.h"
#include "defend_lpm_key.h"
#include "defend_lpm_v6_key.h"
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

#ifndef AF_INET6
#define AF_INET6 10
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

/*
 * AUDIT(H18): safety annotations (5a/5b/5c/5d/5e/5f) live in the included
 * translation units below — defend_policy.inc supplies the shared LPM /
 * ringbuf emit path, while trace_defend_cgroup.inc and trace_lsm_defend_lsm.inc
 * carry the cgroup IPv4/IPv6 and LSM-specific hooks respectively. Each
 * `bpf_map_lookup_elem`, `bpf_ringbuf_reserve`, and `bpf_probe_read_*` call
 * site there has an AUDIT(5x) annotation describing why it is safe (or, for
 * the LSM `bpf_probe_read_kernel` arms whose return is intentionally not
 * checked, why the zero-init defense-in-depth pattern is enough). Cgroup
 * attach cleanup (5g) is audited in `internal/agent/agent_linux.go`.
 */

#include "trace_defend_cgroup.inc"
#include "trace_lsm_defend_lsm.inc"
