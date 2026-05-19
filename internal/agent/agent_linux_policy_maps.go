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
	"github.com/coldstep-io/coldstep/internal/bpf/tracebpfaudit"
	"github.com/coldstep-io/coldstep/internal/bpf/traceconnect"
	"github.com/coldstep-io/coldstep/internal/bpf/tracedns"
	"github.com/coldstep-io/coldstep/internal/bpf/traceexec"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefork"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefs"
	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func compileDefendAllowlist(ctx context.Context, cfg config.Config, resolver policy.LookupIPFunc, maxAttempts int) (policy.CompileResult, error) {
	if cfg.Mode != config.ModeDefend {
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
	if compiled.AllowedIPv4.Len() == 0 {
		msg := "defend allowlist effective allowlist is empty (no IPv4 A-record resolutions; add literals to allowed-ips if needed)"
		if len(compiled.UnresolvedDomains) > 0 {
			msg += fmt.Sprintf(" — check DNS for: %s", strings.Join(compiled.UnresolvedDomains, ", "))
		}
		return policy.CompileResult{}, fmt.Errorf("%s", msg)
	}
	return compiled, nil
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

// readUint32CounterMap reads a single-entry uint32-keyed/uint32-valued BPF counter map at key 0.
//
// Failure semantics (M-07): "key not found" is the legitimate zero state and is returned silently.
// Any other Lookup error (map closed, wrong type, EBADF, program unloaded) is logged at WARN and
// surfaced as zero so digest rendering keeps progressing — losing the distinction between "counter
// is genuinely zero" and "map is unreadable" was the M-07 anti-pattern. The H-05 instance of this
// pattern (defend_cfg) is owned by Group A; this helper deliberately stays scoped to read-only
// counter maps and never touches defend state.
func readUint32CounterMap(m *ebpf.Map, helperName string) int {
	if m == nil {
		return 0
	}
	var k uint32
	var v uint32
	if err := m.Lookup(&k, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0
		}
		slog.Warn("uint32 counter map lookup failed", "helper", helperName, "err", err)
		return 0
	}
	return int(v)
}

// readUint32PerCPUArraySum sums all CPU slots for a BPF_MAP_TYPE_PERCPU_ARRAY map
// with uint32 values at key 0. Used after migrating reserve-failure maps off a
// contended global ARRAY slot.
func readUint32PerCPUArraySum(m *ebpf.Map, helperName string) int {
	if m == nil {
		return 0
	}
	var k uint32
	var vals []uint32
	if err := m.Lookup(&k, &vals); err != nil {
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

func readDenyReserveFailureCount(objs *defend.DefendObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.DenyReserveFailures, "readDenyReserveFailureCount")
}

func readConnect4TupleUpdateFailureCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.Connect4TupleUpdateFailures, "readConnect4TupleUpdateFailureCount")
}

func readUDPRingbufReserveFailureCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.UdpRingbufReserveFailures, "readUDPRingbufReserveFailureCount")
}

func readDNSRingbufReserveFailureCount(objs *tracedns.TracednsObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.DnsRingbufReserveFailures, "readDNSRingbufReserveFailureCount")
}

func readConnectRingbufReserveFailureCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.ConnectRingbufReserveFailures, "readConnectRingbufReserveFailureCount")
}

func readBPFAuditRingbufReserveFailureCount(objs *tracebpfaudit.TracebpfauditObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.BpfAuditReserveFailures, "readBPFAuditRingbufReserveFailureCount")
}

func readHTTPRingbufReserveFailureCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.HttpRingbufReserveFailures, "readHTTPRingbufReserveFailureCount")
}

func readTLSRingbufReserveFailureCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.TlsRingbufReserveFailures, "readTLSRingbufReserveFailureCount")
}

func readUDPSendmsgMultiIovecObservedCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32CounterMap(objs.UdpSendmsgMultiIovecObserved, "readUDPSendmsgMultiIovecObservedCount")
}

func readSendmmsgMultiMessageCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.SendmmsgMultiMessageObserved, "readSendmmsgMultiMessageCount")
}

// readSendmmsgUnobservedExtraCount sums BG-03 Gap 3 per-message extra-message
// dropped counts across CPUs. Distinct from readSendmmsgMultiMessageCount,
// which counts CALLS with vlen > 1; this counter sums individual messages
// beyond index SENDMMSG_EXTRA_MAX (7) that the unrolled loop did not reach.
//
// TODO: regenerate BPF stubs after building on Linux — references
// `objs.SendmmsgUnobservedExtra` defined by `sendmmsg_unobserved_extra` map in
// bpf/trace_connect.bpf.c, which bpf2go will surface during CI regeneration.
func readSendmmsgUnobservedExtraCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.SendmmsgUnobservedExtra, "readSendmmsgUnobservedExtraCount")
}

func readTLSWritevMultiIovecObservedCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32CounterMap(objs.TlsWritevMultiIovecObserved, "readTLSWritevMultiIovecObservedCount")
}

// readPartialEgressCounts returns the BG-01 per-syscall partial-observe
// counters (sendfile, splice, sendmmsg) summed across CPUs. Slots:
//
//	0 = sendfile / sendfile64
//	1 = splice
//	2 = sendmmsg (first-message-only observed)
//
// Reads each slot independently because PERCPU_ARRAY Lookup is per-key.
func readPartialEgressCounts(objs *traceconnect.TraceconnectObjects) (sendfile, splice, sendmmsg int) {
	if objs == nil || objs.PartialEgressObserved == nil {
		return 0, 0, 0
	}
	read := func(key uint32, label string) int {
		var vals []uint32
		if err := objs.PartialEgressObserved.Lookup(&key, &vals); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return 0
			}
			slog.Warn("percpu uint32 map lookup failed", "helper", label, "err", err)
			return 0
		}
		n := 0
		for _, v := range vals {
			n += int(v)
		}
		return n
	}
	sendfile = read(0, "readPartialEgressCounts(sendfile)")
	splice = read(1, "readPartialEgressCounts(splice)")
	sendmmsg = read(2, "readPartialEgressCounts(sendmmsg)")
	return
}

func readIoUringSetupObservedCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32CounterMap(objs.IoUringSetupObserved, "readIoUringSetupObservedCount")
}

func readTCPDNSResponsesObservedCount(objs *tracedns.TracednsObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32CounterMap(objs.TcpDnsResponsesObserved, "readTCPDNSResponsesObservedCount")
}

func readTCPDNSSkippedShortReadCount(objs *tracedns.TracednsObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32CounterMap(objs.TcpDnsSkippedShortRead, "readTCPDNSSkippedShortReadCount")
}

func readExecRingbufReserveFailureCount(objs *traceexec.TraceexecObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.ExecRingbufReserveFailures, "readExecRingbufReserveFailureCount")
}

func readForkRingbufReserveFailureCount(objs *tracefork.TraceforkObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.ForkRingbufReserveFailures, "readForkRingbufReserveFailureCount")
}

func readFSRingbufReserveFailureCount(objs *tracefs.TracefsObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.FsRingbufReserveFailures, "readFSRingbufReserveFailureCount")
}

func readLSMDenyReserveFailureCount(objs *defend.DefendObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.LsmDenyReserveFailures, "readLSMDenyReserveFailureCount")
}

// readIPv6ConnectObservedCount returns the per-CPU sum of the
// ipv6_connect_observed counter populated by the cgroup/connect6
// observe-only hook (P0-1 Phase 1). Returns 0 when the map is absent
// (stubs predate the regeneration on Linux).
// TODO: wire to defend objects after regeneration on Linux — this is a
// no-op until defendObjs.Ipv6ConnectObserved is populated by the
// generated bindings.
func readIPv6ConnectObservedCount(objs *defend.DefendObjects) uint32 {
	if objs == nil {
		return 0
	}
	return clampPerCPUSumToUint32(readUint32PerCPUArraySum(objs.Ipv6ConnectObserved, "readIPv6ConnectObservedCount"))
}

// readIPv6SendmsgObservedCount mirrors readIPv6ConnectObservedCount for
// the cgroup/sendmsg6 observe-only hook (P0-1 Phase 1).
// TODO: wire to defend objects after regeneration on Linux.
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
// Returns 0 when the map is absent (stubs predate the regeneration on Linux
// or LSM was disabled at load time).
// TODO: remove the missing-map tolerance once defend objects are regenerated
// on Linux with bpf/trace_lsm_defend_lsm.inc's sendpage_observed map.
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
// conversion before the narrowing cast.
func clampPerCPUSumToUint32(n int) uint32 {
	if n <= 0 {
		return 0
	}
	if n > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}

// buildDefendAllowedPlan unifies the compile-and-merge sequence shared by the
// cgroup and LSM defend loaders: take compiled domain resolutions, fold in the
// literal IPv4 entries from the policy, and produce an LPM plan ready to write
// into the BPF allowlist map identified by mapName. The two callers differ only
// in which BPF map (allowed_ipv4 vs lsm_allowed_ipv4) receives the result.
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
	if plan.totalEntries == 0 {
		return allowedLPMPlan{}, fmt.Errorf("defend allowlist effective allowlist is empty (no map entries)")
	}
	return plan, nil
}

func loadLSMDefendMaps(objs *defend.DefendObjects, compiled policy.CompileResult, pol *policy.Policy) (int, int, error) {
	if objs == nil {
		return 0, 0, fmt.Errorf("defend objects are required for LSM defend mode")
	}
	keyMode := uint32(0)
	modeDefend := uint32(1)
	if err := objs.LsmDefendCfg.Update(&keyMode, &modeDefend, ebpf.UpdateAny); err != nil {
		return 0, 0, fmt.Errorf("load lsm_defend_cfg map: %w", err)
	}
	ignoredCount := 0
	if pol != nil {
		var err error
		ignoredCount, err = loadIgnoredLPMMap(objs.LsmIgnoredIpv4Lpm, pol.IgnoredIPv4Nets())
		if err != nil {
			return 0, 0, err
		}
	}

	plan, err := buildDefendAllowedPlan("lsm_allowed_ipv4", compiled, pol)
	if err != nil {
		return 0, 0, err
	}

	if err := loadAllowedLPMMap(objs.LsmAllowedIpv4, plan); err != nil {
		return 0, 0, err
	}

	if err := loadAllowedDomainsMap(objs.AllowedDomains, pol); err != nil {
		return 0, 0, err
	}

	// AUDIT(5h): allowlist is fixed-point at startup; runtime DNS changes are
	// not reflected. The agent resolves domains once during compileDefendAllowlist
	// and writes the resulting /32 set + literal CIDRs into the LPM trie here.
	// If a domain's A-record set changes after this point (DNS rotation, CDN
	// edge migration), the BPF allowlist still reflects the startup snapshot
	// until the next agent restart. Operators relying on DNS-backed domain
	// rules should treat the agent's lifetime as the freshness window for the
	// allowlist and add literal CIDRs / IPs for any destinations that need to
	// survive DNS rotation. The dns_cache map (populated by trace_dns.bpf.c at
	// runtime) is consulted as a fallback for reverse lookups in
	// defend_policy.inc:dst_is_allowlisted, but the primary LPM map is
	// snapshot-only.
	slog.Info("allowlist loaded into BPF map", "map", "lsm_allowed_ipv4", "ipv4_entries", plan.totalEntries, "ignored_cidrs", ignoredCount)

	return plan.totalEntries, ignoredCount, nil
}

// loadDefendMaps programs BPF allowlist maps from compiled domain resolutions + literal policy entries.
//
// PR-G: allowed_ipv4 is now a BPF_MAP_TYPE_LPM_TRIE (was HASH). Single-IP
// allowlist entries (resolved domain IPs + literal /32s from --allowed-ips)
// are still programmed individually but with prefixlen=32. Literal CIDR
// entries from --allowed-ips (e.g. "10.0.0.0/8") are programmed once as a
// single LPM key and cover every address inside the range.
func loadDefendMaps(objs *defend.DefendObjects, compiled policy.CompileResult, pol *policy.Policy) (int, int, error) {
	if objs == nil {
		return 0, 0, fmt.Errorf("defend objects are required for cgroup defend mode")
	}
	keyMode := uint32(0)
	modeDefend := uint32(1)
	if err := objs.DefendCfg.Update(&keyMode, &modeDefend, ebpf.UpdateAny); err != nil {
		return 0, 0, fmt.Errorf("load defend_cfg map: %w", err)
	}
	ignoredCount := 0
	if pol != nil {
		var err error
		ignoredCount, err = loadIgnoredLPMMap(objs.IgnoredIpv4Lpm, pol.IgnoredIPv4Nets())
		if err != nil {
			return 0, 0, err
		}
	}

	plan, err := buildDefendAllowedPlan("allowed_ipv4", compiled, pol)
	if err != nil {
		return 0, 0, err
	}

	if err := loadAllowedLPMMap(objs.AllowedIpv4, plan); err != nil {
		return 0, 0, err
	}

	if err := loadAllowedDomainsMap(objs.AllowedDomains, pol); err != nil {
		return 0, 0, err
	}

	// AUDIT(5h): allowlist is fixed-point at startup; runtime DNS changes are
	// not reflected. See loadLSMDefendMaps for the full rationale — both
	// loaders share the same compile-once / load-into-BPF lifecycle.
	slog.Info("allowlist loaded into BPF map", "map", "allowed_ipv4", "ipv4_entries", plan.totalEntries, "ignored_cidrs", ignoredCount)

	return plan.totalEntries, ignoredCount, nil
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

func appendDenyFromRaw(cfg config.Config, raw []byte, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *defendState, signer *telemetry.Signer, hookFamily string, dns *DNSCache) (telemetry.DenyEvent, error) {
	tgid, tid, commb, protocolRaw, reasonRaw, af, daddr16, dport, ok := decodeDenyEvent(raw)
	if !ok {
		return telemetry.DenyEvent{}, fmt.Errorf("decode deny event")
	}
	protocol := denyProtocolLabel(protocolRaw)
	reason := denyReasonLabel(reasonRaw)
	if af != linuxAFInet {
		return telemetry.DenyEvent{}, fmt.Errorf("deny event: unsupported address family %d (IPv4 only)", af)
	}
	dstIP := net.IPv4(daddr16[0], daddr16[1], daddr16[2], daddr16[3])
	dst := dstIP.String()
	// P1-5: sanitize attacker-controlled comm before it lands in JSONL — a
	// blocked process whose argv[0] embeds newline / control bytes must not
	// be able to forge an extra record in the event log.
	comm := telemetry.SanitizeField(string(bytes.TrimRight(commb[:], "\x00")), 16)
	ts := time.Now().UTC().Format(time.RFC3339Nano)
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
		state.noteDeny(denyDigestRowFromEvent(deny))
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
