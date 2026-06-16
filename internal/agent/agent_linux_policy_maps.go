//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/coldstep-io/coldstep/internal/bpf/defend"
	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func compileDefendAllowlist(ctx context.Context, cfg config.Config, resolver policy.LookupIPFunc, maxAttempts int) (policy.CompileResult, error) {
	if !cfg.ModeConfig().Defend {
		return policy.CompileResult{}, nil
	}
	if len(cfg.AllowedDomains) == 0 {
		return policy.CompileResult{}, fmt.Errorf("defend mode requires non-empty allowlist")
	}
	compiled := policy.CompileDomainAllowlist(ctx, cfg.AllowedDomains, resolver, maxAttempts)
	if len(compiled.Domains) == 0 {
		return policy.CompileResult{}, fmt.Errorf("defend mode requires non-empty allowlist after normalization")
	}
	pol, perr := cfg.Policy()
	if perr != nil {
		return policy.CompileResult{}, perr
	}
	pol.MergeLiteralAllowedIPv4Into(&compiled.AllowedIPv4)
	// SP-2: literal IPv6 addresses count toward the effective allowlist too.
	pol.MergeLiteralAllowedIPv6Into(&compiled.AllowedIPv6)
	literalV6CIDRs := len(pol.AllowedIPv6Nets())
	// IPv4 CIDRs from allowed-ips are programmed into allowed_ipv4 by
	// buildDefendAllowedPlan (pol.AllowedIPv4Nets()) but are NOT merged into
	// compiled.AllowedIPv4 (that set only holds A-record resolutions + bare
	// /32 literals), so they must be counted here alongside the IPv6 CIDRs —
	// otherwise an `allowed-ips 10.0.0.0/8` fallback is wrongly rejected as
	// empty whenever the domains fail to resolve.
	literalV4CIDRs := len(pol.AllowedIPv4Nets())
	// P2-1 Phase 2: an IPv6-only allowlist (AAAA resolutions, no A) is
	// valid — both BPF defend hooks attach, IPv4 cgroup denies everything,
	// IPv6 cgroup denies everything outside allowed_ipv6. Only reject
	// when ALL families are empty (every domain failed both A and AAAA and
	// no IPv4/IPv6 literals or CIDRs were given).
	if compiled.AllowedIPv4.Len() == 0 && compiled.AllowedIPv6.Len() == 0 && literalV4CIDRs == 0 && literalV6CIDRs == 0 {
		msg := "defend allowlist effective allowlist is empty (no A/AAAA resolutions; add literals to allowed-ips if needed)"
		if len(compiled.UnresolvedDomains) > 0 {
			msg += fmt.Sprintf(" — check DNS for: %s", strings.Join(compiled.UnresolvedDomains, ", "))
		}
		return policy.CompileResult{}, fmt.Errorf("%s", msg)
	}
	return compiled, nil
}

// autoAllowSystemResolvers folds the host's configured DNS resolver addresses
// into the compiled defend allowlist (issue: defend mode breaks DNS on hosted
// runners). The systemd-resolved stub hop (127.0.0.53) is covered by the BPF
// loopback bypass; this covers the second hop — resolved's upstream query to
// the platform resolver (168.63.129.16 on Azure-hosted runners), a public IP
// outside the default ignored nets. Without it every workload getaddrinfo in
// defend mode fails with EAI_AGAIN, since the runner cannot resolve even
// allowlisted domains.
//
// Trust note: this allows ALL traffic to the resolver IPs (the LPM allowlist
// has no port dimension), not just UDP/53. Resolvers are already infrastructure
// a workload can tunnel data through (DNS exfil), so this does not widen the
// inherent destination-allowlisting trust model; every auto-allowed address is
// logged at startup for auditability. Returns the addresses added per family.
func autoAllowSystemResolvers(compiled *policy.CompileResult, paths ...string) (v4 []net.IP, v6 []net.IP) {
	v4, v6 = policy.SystemResolverIPs(paths...)
	for _, ip := range v4 {
		compiled.AllowedIPv4.Add(ip)
	}
	for _, ip := range v6 {
		compiled.AllowedIPv6.Add(ip)
	}
	return v4, v6
}

// loadIgnoredLPMMap programs the BPF LPM trie used to bypass denies for ignored IPv4 CIDRs.
func loadIgnoredLPMMap(m *ebpf.Map, nets []*net.IPNet) (int, error) {
	if len(nets) == 0 {
		return 0, nil
	}
	if m == nil {
		return 0, fmt.Errorf("ignored_ipv4_lpm map is nil with %d ignored CIDR(s)", len(nets))
	}
	if len(nets) > policy.MaxIgnoredIPv4Nets {
		return 0, fmt.Errorf("ignored_ipv4_lpm: %d CIDRs exceeds max %d", len(nets), policy.MaxIgnoredIPv4Nets)
	}
	val := uint8(1)
	programmed := 0
	for i := 0; i < len(nets); i++ {
		n := nets[i]
		if n == nil {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits != 32 || ones < 0 || ones > 32 {
			continue
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			continue
		}
		network := ip4.Mask(n.Mask)
		if network == nil {
			continue
		}
		var key [8]byte
		binary.LittleEndian.PutUint32(key[0:4], uint32(ones))
		binary.BigEndian.PutUint32(key[4:8], binary.BigEndian.Uint32(network))
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			return 0, fmt.Errorf("ignored_ipv4_lpm update %s: %w", n.String(), err)
		}
		programmed++
	}
	if programmed == 0 {
		slog.Warn("ignored_ipv4_lpm: 0 entries programmed (all filtered); continuing without ignored-nets defense",
			"configured", len(nets))
		return 0, nil
	}
	return programmed, nil
}

// readUint32PerCPUArraySum sums all CPU slots for a BPF_MAP_TYPE_PERCPU_ARRAY map
// with uint32 values at key 0. Used after migrating all hot-path counters off
// contended global ARRAY slots — every uint32 observability/reserve counter is
// now per-CPU so the increment side stays lock-free (cgroup-scoped writer code
// runs with preemption disabled per syscall).
//
// Failure semantics (M-07): "key not found" is the legitimate zero state and is
// returned silently. Any other Lookup error (map closed, wrong type, EBADF,
// program unloaded) is logged at WARN and surfaced as zero so digest rendering
// keeps progressing — losing the distinction between "counter is genuinely
// zero" and "map is unreadable" was the M-07 anti-pattern.
// readUint32PerCPUKeySum sums every CPU slot for a single key of a
// BPF_MAP_TYPE_PERCPU_ARRAY with uint32 values. Failure semantics (M-07):
// "key not found" is the legitimate zero state and is returned silently; any
// other Lookup error is logged at WARN and surfaced as zero so callers keep
// progressing. Shared core for readUint32PerCPUArraySum (key 0) and the
// per-syscall partial-observe counters.
func readUint32PerCPUKeySum(m *ebpf.Map, key uint32, helperName string) int {
	if m == nil {
		return 0
	}
	var vals []uint32
	if err := m.Lookup(&key, &vals); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0
		}
		slog.Warn("percpu uint32 map lookup failed", "helper", helperName, "err", err)
		return 0
	}
	n := 0
	for _, v := range vals {
		n += int(v)
	}
	return n
}

func readUint32PerCPUArraySum(m *ebpf.Map, helperName string) int {
	return readUint32PerCPUKeySum(m, 0, helperName)
}

// readPartialEgressCounts returns the BG-01 per-syscall partial-observe
// counters (sendfile, splice, sendmmsg) summed across CPUs. Slots:
//
//	0 = sendfile / sendfile64
//	1 = splice
//	2 = sendmmsg (first-message-only observed)
//
// Reads each slot independently because PERCPU_ARRAY Lookup is per-key.
func readPartialEgressCounts(m *ebpf.Map) (sendfile, splice, sendmmsg int) {
	return readUint32PerCPUKeySum(m, 0, "readPartialEgressCounts(sendfile)"),
		readUint32PerCPUKeySum(m, 1, "readPartialEgressCounts(splice)"),
		readUint32PerCPUKeySum(m, 2, "readPartialEgressCounts(sendmmsg)")
}

// readIPv6ConnectObservedCount returns the per-CPU sum of the
// ipv6_connect_observed counter populated by the cgroup/connect6
// observe-only hook (P0-1 Phase 1). ipv6_connect_observed is
// unconditionally compiled into the cgroup section and required
// fail-closed by the loader, so objs.Ipv6ConnectObserved is non-nil
// whenever defend loaded.
func readIPv6ConnectObservedCount(objs *defend.DefendObjects) uint32 {
	if objs == nil {
		return 0
	}
	return clampPerCPUSumToUint32(readUint32PerCPUArraySum(objs.Ipv6ConnectObserved, "readIPv6ConnectObservedCount"))
}

// readIPv6SendmsgObservedCount mirrors readIPv6ConnectObservedCount for
// the cgroup/sendmsg6 observe-only hook (P0-1 Phase 1). ipv6_sendmsg_observed
// is unconditionally compiled into the cgroup section and required
// fail-closed by the loader, so objs.Ipv6SendmsgObserved is non-nil
// whenever defend loaded.
func readIPv6SendmsgObservedCount(objs *defend.DefendObjects) uint32 {
	if objs == nil {
		return 0
	}
	return clampPerCPUSumToUint32(readUint32PerCPUArraySum(objs.Ipv6SendmsgObserved, "readIPv6SendmsgObservedCount"))
}

// readSendpageObservedCount returns the per-CPU sum of the sendpage_observed
// counter populated by the lsm/socket_sendpage hook. The hook closes the
// kernel-5.15 sendfile(2)/splice(2) egress gap (sock_sendpage path skips
// cgroup/sendmsg4 and lsm/socket_sendmsg); non-zero values mean sendfile or
// splice fired in defend mode and was gated against the IPv4 allowlist.
// Returns 0 when the map is absent — a permanent runtime state, not a stale
// stub: kernel 6.5+ removed the socket_sendpage LSM hook (so
// LoadDefendObjectsForKernel strips the map) and the map is likewise absent
// when LSM was disabled at load time.
func readSendpageObservedCount(objs *defend.DefendObjects) uint32 {
	if objs == nil {
		return 0
	}
	return clampPerCPUSumToUint32(readUint32PerCPUArraySum(objs.SendpageObserved, "readSendpageObservedCount"))
}

// clampPerCPUSumToUint32 narrows the int sum returned by
// readUint32PerCPUArraySum down to uint32 with explicit saturation. The
// per-cpu values are uint32 but summed into an int across the CPU set;
// in practice the result fits, but gosec G115 wants an explicit bounded
// conversion before the narrowing cast. The comparison goes through int64
// so the function is correct (and compiles) independent of the platform
// int width rather than assuming the 64-bit int of amd64/arm64.
func clampPerCPUSumToUint32(n int) uint32 {
	if n <= 0 {
		return 0
	}
	if int64(n) > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n) // #nosec G115 -- saturation bounds checked above //nolint:gosec
}

// buildDefendAllowedPlan unifies the compile-and-merge sequence shared by the
// cgroup and LSM defend loaders: take compiled domain resolutions, fold in the
// literal IPv4 entries from the policy, and produce an LPM plan ready to write
// into the BPF allowlist map identified by mapName. The two callers differ only
// in which BPF map (allowed_ipv4 vs lsm_allowed_ipv4) receives the result.
//
// Empty IPv4 plan is allowed: under Phase 2 a defend mode run can have
// AAAA-only resolutions and still defend coherently — the IPv4 cgroup
// hook simply blocks every non-ignored destination. compileDefendAllowlist
// already rejects the truly-empty case (both families empty) before this
// builder runs.
func buildDefendAllowedPlan(mapName string, compiled policy.CompileResult, pol *policy.Policy) (allowedLPMPlan, error) {
	v4keys := make(map[[4]byte]struct{}, compiled.AllowedIPv4.Len())
	compiled.AllowedIPv4.ForEach(func(k [4]byte) { v4keys[k] = struct{}{} })
	pol.MergeLiteralAllowedIPv4Keys(v4keys)

	plan, err := buildAllowedLPMPlan(mapName, v4keys, pol.AllowedIPv4Nets())
	if err != nil {
		return allowedLPMPlan{}, err
	}
	if plan.totalEntries > policy.MaxAllowedDefendIPv4Keys {
		return allowedLPMPlan{}, fmt.Errorf("%s: %d entries exceeds BPF max %d", mapName, plan.totalEntries, policy.MaxAllowedDefendIPv4Keys)
	}
	return plan, nil
}

// defendMapSet groups the four BPF maps loadDefendMapsForBackend programs,
// plus the map-name strings used for diagnostics. cgroup and LSM backends
// supply different *ebpf.Map field references; the load steps are identical.
type defendMapSet struct {
	cfgName, allowedName                        string
	cfg, ignoredLPM, allowedLPM, allowedDomains *ebpf.Map
}

// loadDefendMapsForBackend programs BPF allowlist maps from compiled domain
// resolutions + literal policy entries for a single defend backend.
//
// PR-G: allowed_ipv4 is a BPF_MAP_TYPE_LPM_TRIE (was HASH). Single-IP allowlist
// entries (resolved domain IPs + literal /32s from --allowed-ips) are programmed
// individually with prefixlen=32. Literal CIDR entries from --allowed-ips (e.g.
// "10.0.0.0/8") are programmed once as a single LPM key covering the range.
//
// AUDIT(5h): allowlist is fixed-point at startup; runtime DNS changes are not
// reflected. The agent resolves domains once during compileDefendAllowlist and
// writes the resulting /32 set + literal CIDRs into the LPM trie here. If a
// domain's A-record set changes after this point (DNS rotation, CDN edge
// migration), the BPF allowlist still reflects the startup snapshot until the
// next agent restart. Operators relying on DNS-backed domain rules should treat
// the agent's lifetime as the freshness window for the allowlist and add literal
// CIDRs / IPs for any destinations that need to survive DNS rotation. The
// defend dns_cache map is consulted as an owner-fallback in
// defend_policy.inc:dst_is_allowlisted, but the primary LPM map is
// snapshot-only. SECURITY (dns-cache-trust): that defend dns_cache is seeded
// ONLY from the agent's own resolver (seedDefendOwners / policy.ResolveOwners)
// and refreshed by the DNS drift watcher — it is deliberately NOT fed by
// trace_dns.bpf.c sniffed traffic (which writes the separate detection-side
// dnsObjs.DnsCache). Feeding sniffed replies into enforcement would let a
// hostile build step forge an allowlisted-FQDN→attacker-IP mapping and bypass
// the allowlist; see the wiring note in agent_linux.go where SetBPFMaps
// registers only the detection map.
func loadDefendMapsForBackend(maps defendMapSet, compiled policy.CompileResult, pol *policy.Policy) (int, int, error) {
	keyMode := uint32(0)
	modeDefend := uint32(1)
	if err := maps.cfg.Update(&keyMode, &modeDefend, ebpf.UpdateAny); err != nil {
		return 0, 0, fmt.Errorf("load %s map: %w", maps.cfgName, err)
	}
	ignoredCount := 0
	if pol != nil {
		var err error
		ignoredCount, err = loadIgnoredLPMMap(maps.ignoredLPM, pol.IgnoredIPv4Nets())
		if err != nil {
			return 0, 0, err
		}
	}
	plan, err := buildDefendAllowedPlan(maps.allowedName, compiled, pol)
	if err != nil {
		return 0, 0, err
	}
	if err := loadAllowedLPMMap(maps.allowedLPM, plan); err != nil {
		return 0, 0, err
	}
	if err := loadAllowedDomainsMap(maps.allowedDomains, pol); err != nil {
		return 0, 0, err
	}
	slog.Info("allowlist loaded into BPF map", "map", maps.allowedName, "ipv4_entries", plan.totalEntries, "ignored_cidrs", ignoredCount)
	return plan.totalEntries, ignoredCount, nil
}

func loadLSMDefendMaps(objs *defend.DefendObjects, compiled policy.CompileResult, pol *policy.Policy) (int, int, error) {
	if objs == nil {
		return 0, 0, fmt.Errorf("defend objects are required for LSM defend mode")
	}
	return loadDefendMapsForBackend(defendMapSet{
		cfgName:        "lsm_defend_cfg",
		allowedName:    "lsm_allowed_ipv4",
		cfg:            objs.LsmDefendCfg,
		ignoredLPM:     objs.LsmIgnoredIpv4Lpm,
		allowedLPM:     objs.LsmAllowedIpv4,
		allowedDomains: objs.AllowedDomains,
	}, compiled, pol)
}

// loadDefendMaps programs BPF allowlist maps from compiled domain resolutions + literal policy entries.
//
// PR-G: allowed_ipv4 is now a BPF_MAP_TYPE_LPM_TRIE (was HASH). Single-IP
// allowlist entries (resolved domain IPs + literal /32s from --allowed-ips)
// are still programmed individually but with prefixlen=32. Literal CIDR
// entries from --allowed-ips (e.g. "10.0.0.0/8") are programmed once as a
// single LPM key and cover every address inside the range.
//
// Returns (ipv4Entries, ipv6Entries, ignoredCidrs, error). The IPv6 count
// flows into defendState.setIPv6AllowlistSize so the digest can choose
// between ✅ "gated" and 🚨 "block-all" Phase 2 verdicts.
func loadDefendMaps(objs *defend.DefendObjects, compiled policy.CompileResult, pol *policy.Policy) (int, int, int, error) {
	if objs == nil {
		return 0, 0, 0, fmt.Errorf("defend objects are required for cgroup defend mode")
	}
	ipv4Entries, ignoredCount, err := loadDefendMapsForBackend(defendMapSet{
		cfgName:        "defend_cfg",
		allowedName:    "allowed_ipv4",
		cfg:            objs.DefendCfg,
		ignoredLPM:     objs.IgnoredIpv4Lpm,
		allowedLPM:     objs.AllowedIpv4,
		allowedDomains: objs.AllowedDomains,
	}, compiled, pol)
	if err != nil {
		return 0, 0, 0, err
	}

	// P2-1 Phase 2: program AAAA-resolved destinations into allowed_ipv6
	// when the map is present in the loaded objects. Loader stripped this
	// to nil if the BPF stubs predate Phase 2 — populate returns (0, nil)
	// in that case, so older stubs continue to load IPv4-only defend.
	ipv6Programmed, err := populateAllowedIPv6Map(objs.AllowedIpv6, compiled, pol)
	if err != nil {
		return 0, 0, 0, err
	}
	if ipv6Programmed > 0 {
		slog.Info("allowlist loaded into BPF map", "map", "allowed_ipv6",
			"ipv6_entries", ipv6Programmed)
	}

	return ipv4Entries, ipv6Programmed, ignoredCount, nil
}

// loadAllowedLPMMap programs the allowed_ipv4 LPM trie (PR-G).
//
// Two-phase fill keeps the kernel call sequence deterministic for tests:
//  1. Single-IP keys (resolved domain IPs + literal /32s) → prefixlen=32.
//  2. Literal CIDRs from --allowed-ips → prefixlen from the mask.
//
// Key wire format mirrors loadIgnoredLPMMap: 8-byte buffer where bytes [0:4]
// are the prefix length in CPU/little-endian order (BPF_MAP_TYPE_LPM_TRIE
// reads it as a u32) and bytes [4:8] are the network address in network byte
// order. Don't reorder fields without also updating the BPF `struct ns_lpm4_key`
// definition in bpf/defend_lpm_key.h — they share wire format.
type allowedLPMPlan struct {
	singleIPKeys [][8]byte
	cidrKeys     [][8]byte
	totalEntries int
}

func buildAllowedLPMPlan(mapName string, ipKeys map[[4]byte]struct{}, nets []*net.IPNet) (allowedLPMPlan, error) {
	plan := allowedLPMPlan{}
	seen := make(map[[8]byte]struct{}, len(ipKeys)+len(nets))

	addKey := func(key [8]byte, dst *[][8]byte) {
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		*dst = append(*dst, key)
	}

	// Build deterministic ordering for /32 entries.
	ipAddrs := make([][4]byte, 0, len(ipKeys))
	for addr := range ipKeys {
		ipAddrs = append(ipAddrs, addr)
	}
	sort.Slice(ipAddrs, func(i, j int) bool {
		return bytes.Compare(ipAddrs[i][:], ipAddrs[j][:]) < 0
	})
	for _, addr := range ipAddrs {
		var key [8]byte
		binary.LittleEndian.PutUint32(key[0:4], 32)
		copy(key[4:8], addr[:])
		addKey(key, &plan.singleIPKeys)
	}

	for _, n := range nets {
		if n == nil {
			return allowedLPMPlan{}, fmt.Errorf("%s: nil CIDR entry in policy", mapName)
		}
		ones, bits := n.Mask.Size()
		if bits != 32 || ones < 0 || ones > 32 {
			return allowedLPMPlan{}, fmt.Errorf("%s: non-IPv4 CIDR mask %q (bits=%d ones=%d)", mapName, n.String(), bits, ones)
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			return allowedLPMPlan{}, fmt.Errorf("%s: non-IPv4 CIDR %q", mapName, n.String())
		}
		network := ip4.Mask(n.Mask)
		if network == nil {
			return allowedLPMPlan{}, fmt.Errorf("%s: invalid masked network for CIDR %q", mapName, n.String())
		}
		var key [8]byte
		binary.LittleEndian.PutUint32(key[0:4], uint32(ones))
		binary.BigEndian.PutUint32(key[4:8], binary.BigEndian.Uint32(network))
		addKey(key, &plan.cidrKeys)
	}

	plan.totalEntries = len(seen)
	return plan, nil
}

func loadAllowedLPMMap(m *ebpf.Map, plan allowedLPMPlan) error {
	if m == nil {
		if plan.totalEntries > 0 {
			return fmt.Errorf("allowed_ipv4 map is nil with %d entries", plan.totalEntries)
		}
		return nil
	}
	val := uint8(1)
	for _, key := range plan.singleIPKeys {
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			addr := key[4:8]
			return fmt.Errorf("load allowed_ipv4 map (/32 %d.%d.%d.%d): %w",
				addr[0], addr[1], addr[2], addr[3], err)
		}
	}
	for _, key := range plan.cidrKeys {
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			prefix := binary.LittleEndian.Uint32(key[0:4])
			return fmt.Errorf("load allowed_ipv4 map (cidr %d.%d.%d.%d/%d): %w", key[4], key[5], key[6], key[7], prefix, err)
		}
	}
	return nil
}

// populateAllowedIPv6Map writes AAAA-resolved /128 entries from the
// compiled allowlist into the BPF allowed_ipv6 LPM trie. Wire format is
// the userspace mirror of `struct lpm_v6_key`: 20-byte buffer where bytes
// [0:4] are the prefix length in CPU/little-endian order (BPF_MAP_TYPE_LPM_TRIE
// reads it as u32) and bytes [4:20] are the IPv6 address in network byte
// order. Drift between this layout and bpf/defend_lpm_v6_key.h equals
// silent EINVAL on Update at startup — both sides MUST move together.
//
// Returns the number of entries actually programmed. Missing map (older
// stubs that predate Phase 2) is tolerated: 0 returned, no error — the
// BPF program also degrades gracefully because cgroup/connect6 +
// sendmsg6 will be missing, leaving IPv4-only defend.
func populateAllowedIPv6Map(m *ebpf.Map, compiled policy.CompileResult, pol *policy.Policy) (int, error) {
	if m == nil {
		return 0, nil
	}
	// SP-2: union AAAA-resolved /128s with literal IPv6 addresses from
	// allowed-ips. Both are exact /128 entries; literal IPv6 CIDRs are
	// programmed as prefix entries below.
	pol.MergeLiteralAllowedIPv6Into(&compiled.AllowedIPv6)

	// Deterministic ordering for reproducibility (tests, logs).
	keys := make([][16]byte, 0, compiled.AllowedIPv6.Len())
	compiled.AllowedIPv6.ForEach(func(k [16]byte) { keys = append(keys, k) })
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i][:], keys[j][:]) < 0
	})
	cidrs := pol.AllowedIPv6Nets()
	if len(keys)+len(cidrs) > policy.MaxAllowedDefendIPv6Keys {
		return 0, fmt.Errorf("allowed_ipv6: %d entries exceeds BPF max %d",
			len(keys)+len(cidrs), policy.MaxAllowedDefendIPv6Keys)
	}
	val := uint8(1)
	programmed := 0
	for _, addr := range keys {
		var key [20]byte
		binary.LittleEndian.PutUint32(key[0:4], 128)
		copy(key[4:20], addr[:])
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			return programmed, fmt.Errorf("load allowed_ipv6 map (/128 %s): %w",
				net.IP(addr[:]).String(), err)
		}
		programmed++
	}
	// SP-2: literal IPv6 CIDRs as LPM prefix entries. net.ParseCIDR already
	// masked the network address; prefix length comes from the mask.
	for _, n := range cidrs {
		ones, bits := n.Mask.Size()
		if bits != 128 {
			continue // defensive: non-v6 mask should never reach here
		}
		ip16 := n.IP.To16()
		if ip16 == nil {
			continue
		}
		var key [20]byte
		// #nosec G115 -- ones is an IPv6 prefix length from net.IPMask.Size() (0..128); always fits uint32 //nolint:gosec
		binary.LittleEndian.PutUint32(key[0:4], uint32(ones))
		copy(key[4:20], ip16)
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			return programmed, fmt.Errorf("load allowed_ipv6 map (%s): %w", n.String(), err)
		}
		programmed++
	}
	return programmed, nil
}

func appendDenyFromRaw(cfg config.Config, raw []byte, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *defendState, signer *telemetry.Signer, hookFamily string, dns *DNSCache) (telemetry.DenyEvent, error) {
	tgid, tid, commb, protocolRaw, reasonRaw, af, daddr16, dport, ok := decodeDenyEvent(raw)
	if !ok {
		return telemetry.DenyEvent{}, fmt.Errorf("decode deny event")
	}
	protocol := denyProtocolLabel(protocolRaw)
	reason := denyReasonLabel(reasonRaw)
	var dstIP net.IP
	switch af {
	case linuxAFInet:
		dstIP = net.IPv4(daddr16[0], daddr16[1], daddr16[2], daddr16[3])
	case linuxAFInet6:
		// P2-1 Phase 2: IPv6 deny events. daddr16 holds the 16-byte address
		// in network byte order; net.IP shares that layout so we can copy
		// it verbatim. String() picks the canonical zero-compressed form.
		ip := make(net.IP, net.IPv6len)
		copy(ip, daddr16[:])
		dstIP = ip
	default:
		return telemetry.DenyEvent{}, fmt.Errorf("deny event: unsupported address family %d (IPv4/IPv6 only)", af)
	}
	dst := dstIP.String()
	// P1-5: sanitize attacker-controlled comm before it lands in JSONL — a
	// blocked process whose argv[0] embeds newline / control bytes must not
	// be able to forge an extra record in the event log.
	comm := telemetry.SanitizeField(string(bytes.TrimRight(commb[:], "\x00")), 16)
	now := time.Now()
	ts := now.UTC().Format(time.RFC3339Nano)
	matchKind := "unknown"
	if dns != nil && dns.Lookup(dstIP) != "" {
		matchKind = "dns_cache"
	}
	// Build the deny event without Seq up front; Seq is only assigned when the JSONL writer
	// branch fires, so it stays paired with the actual JSONL line under jsonlMu (M-05) and
	// avoids burning sequence numbers when EventsLogPath is empty (M-06). Other JSONL writers
	// follow the same lock-then-Seq.Next() pattern (e.g. exec/tcp paths).
	deny := telemetry.DenyEvent{
		Type:     "deny",
		TS:       ts,
		PID:      tgid,
		TGID:     tgid,
		ThreadID: tid,
		Comm:     comm,
		Protocol: protocol,
		Dst:      dst,
		Dport:    dport,
		Reason:   reason,
		Mode:     cfg.PublicMode(),
	}
	if hookFamily != "" {
		deny.HookFamily = hookFamily
	}
	deny.MatchKind = matchKind
	// Cross-layer dedup: on LSM-enabled kernels one blocked syscall fires both
	// the cgroup hook (connect4/sendmsg4) and the LSM hook (socket_connect/
	// socket_sendmsg), producing two deny ringbuf records for the same logical
	// event. Suppress the second (other-family) report within denyDedupWindow so
	// JSONL and the digest deny count are not doubled; the suppressed event is
	// tallied in denyCorroboratedN instead. Same-family repeats always emit.
	dedupKey := denyDedupKey{
		tgid:     deny.TGID,
		tid:      deny.ThreadID,
		dst:      deny.Dst,
		dport:    deny.Dport,
		protocol: deny.Protocol,
	}
	if !state.shouldEmitDeny(dedupKey, hookFamily, now.UnixNano()) {
		return deny, nil
	}
	if cfg.EventsLogPath != "" {
		jsonlMu.Lock()
		deny.Seq = seq.Next()
		err := telemetry.AppendJSONL(cfg.EventsLogPath, deny, signer)
		jsonlMu.Unlock()
		if err != nil {
			return telemetry.DenyEvent{}, fmt.Errorf("append deny jsonl: %w", err)
		}
	}
	if state != nil {
		state.noteDeny()
	}
	return deny, nil
}

// testAppendDenySample exercises appendDenyFromRaw JSONL emission and returns a sentinel error
// for unit tests. Production readDenyRing logs and skips decode/JSONL failures so defense
// keeps running; successful denies still flow through appendDenyFromRaw unchanged.
func testAppendDenySample(cfg config.Config, raw []byte, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *defendState, signer *telemetry.Signer, hookFamily string, dns *DNSCache) error {
	deny, err := appendDenyFromRaw(cfg, raw, seq, jsonlMu, state, signer, hookFamily, dns)
	if err != nil {
		return err
	}
	return newDefendDenyError(deny)
}

func readDenyRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *defendState, signer *telemetry.Signer, hookFamily string, dns *DNSCache) error {
	// Long-running deny consumer: drain a short burst per kernel wakeup for JSONL, then keep
	// reading. Do not fail-fast exit on the first deny — background egress on hosted runners can
	// emit denies immediately while the GitHub Action is still polling .coldstep-ready.json, which
	// would kill the agent before later job steps (nmap/curl) run. Exit only on ctx cancel / closed ring.
	backoff := newRingReadRetryBackoff()
	drainBackoff := newRingReadRetryBackoff()
	for {
		rd.SetDeadline(time.Time{})
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			delay := backoff.sleep()
			slog.Warn("ringbuf read (deny)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()

		if _, err := appendDenyFromRaw(cfg, record.RawSample, seq, jsonlMu, state, signer, hookFamily, dns); err != nil {
			slog.Warn("deny ring sample skipped", "err", err)
			continue
		}

		drainUntil := time.Now().Add(defendDenyDrainDuration)
		n := 1
		for n < defendDenyDrainMaxEvents && time.Now().Before(drainUntil) {
			rd.SetDeadline(time.Now().Add(defendDenyDrainReadSlice))
			rec2, err2 := rd.Read()
			if err2 != nil {
				if errors.Is(err2, ringbuf.ErrClosed) {
					break
				}
				if errors.Is(err2, os.ErrDeadlineExceeded) {
					continue
				}
				if ctx.Err() != nil {
					rd.SetDeadline(time.Time{})
					return ctx.Err()
				}
				rd.SetDeadline(time.Time{})
				delay := drainBackoff.sleep()
				slog.Warn("ringbuf read (deny drain)", "err", err2, "backoff", delay)
				continue
			}
			drainBackoff.reset()
			if _, err3 := appendDenyFromRaw(cfg, rec2.RawSample, seq, jsonlMu, state, signer, hookFamily, dns); err3 != nil {
				slog.Warn("deny ring drain sample skipped", "err", err3)
				continue
			}
			n++
		}
		rd.SetDeadline(time.Time{})
	}
}

// processDenyRingSample handles one deny ringbuf payload. Decode or JSONL failures are logged and
// dropped so readDenyRing never returns a fatal error (defense stays attached).
func processDenyRingSample(cfg config.Config, raw []byte, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *defendState, signer *telemetry.Signer, hookFamily string, dns *DNSCache) {
	deny, err := appendDenyFromRaw(cfg, raw, seq, jsonlMu, state, signer, hookFamily, dns)
	if err != nil {
		slog.Warn("deny ring sample skipped", "err", err, "raw_len", len(raw))
		return
	}
	slog.Debug("defend deny", "protocol", deny.Protocol, "dst", deny.Dst, "dport", deny.Dport,
		"reason", deny.Reason, "comm", deny.Comm)
}
