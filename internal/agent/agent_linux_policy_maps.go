//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/coldstep-io/coldstep/internal/bpf/tracebpfaudit"
	"github.com/coldstep-io/coldstep/internal/bpf/traceconnect"
	"github.com/coldstep-io/coldstep/internal/bpf/tracedns"
	"github.com/coldstep-io/coldstep/internal/bpf/traceenforce"
	"github.com/coldstep-io/coldstep/internal/bpf/traceexec"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefork"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefs"
	"github.com/coldstep-io/coldstep/internal/bpf/tracelsmenforce"
	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func compileEnforceAllowlist(ctx context.Context, cfg config.Config, resolver policy.LookupIPFunc, maxAttempts int) (policy.CompileResult, error) {
	if cfg.Mode != config.ModeEnforce {
		return policy.CompileResult{}, nil
	}
	if len(cfg.AllowedDomains) == 0 {
		return policy.CompileResult{}, fmt.Errorf("enforce mode requires non-empty allowlist")
	}
	compiled := policy.CompileDomainAllowlist(ctx, cfg.AllowedDomains, resolver, maxAttempts)
	if len(compiled.Domains) == 0 {
		return policy.CompileResult{}, fmt.Errorf("enforce mode requires non-empty allowlist after normalization")
	}
	pol, perr := cfg.Policy()
	if perr != nil {
		return policy.CompileResult{}, perr
	}
	pol.MergeLiteralAllowedIPv4Into(&compiled.AllowedIPv4)
	if compiled.AllowedIPv4.Len() == 0 {
		msg := "enforce allowlist effective allowlist is empty (no IPv4 A-record resolutions; add literals to allowed-ips if needed)"
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
		return 0, fmt.Errorf(
			"ignored_ipv4_lpm: no entries programmed from %d configured CIDR(s) (need usable IPv4 prefixes for this LPM map)",
			len(nets),
		)
	}
	return programmed, nil
}

// readUint32CounterMap reads a single-entry uint32-keyed/uint32-valued BPF counter map at key 0.
//
// Failure semantics (M-07): "key not found" is the legitimate zero state and is returned silently.
// Any other Lookup error (map closed, wrong type, EBADF, program unloaded) is logged at WARN and
// surfaced as zero so digest rendering keeps progressing — losing the distinction between "counter
// is genuinely zero" and "map is unreadable" was the M-07 anti-pattern. The H-05 instance of this
// pattern (enforce_cfg) is owned by Group A; this helper deliberately stays scoped to read-only
// counter maps and never touches enforcement state.
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

func readDenyReserveFailureCount(objs *traceenforce.TraceenforceObjects) int {
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

func readTLSWritevMultiIovecObservedCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32CounterMap(objs.TlsWritevMultiIovecObserved, "readTLSWritevMultiIovecObservedCount")
}

func readUnobservedEgressSyscallsCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32CounterMap(objs.UnobservedEgressSyscallsObserved, "readUnobservedEgressSyscallsCount")
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

func readLSMDenyReserveFailureCount(objs *tracelsmenforce.TracelsmenforceObjects) int {
	if objs == nil {
		return 0
	}
	return readUint32PerCPUArraySum(objs.LsmDenyReserveFailures, "readLSMDenyReserveFailureCount")
}

func loadLSMEnforceMaps(objs *tracelsmenforce.TracelsmenforceObjects, compiled policy.CompileResult, pol *policy.Policy) (int, int, error) {
	if objs == nil {
		return 0, 0, fmt.Errorf("tracelsmenforce objects are required for enforce mode")
	}
	keyMode := uint32(0)
	modeEnforce := uint32(1)
	if err := objs.LsmEnforceCfg.Update(&keyMode, &modeEnforce, ebpf.UpdateAny); err != nil {
		return 0, 0, fmt.Errorf("load lsm_enforce_cfg map: %w", err)
	}
	ignoredCount := 0
	if pol != nil {
		var err error
		ignoredCount, err = loadIgnoredLPMMap(objs.LsmIgnoredIpv4Lpm, pol.IgnoredIPv4Nets())
		if err != nil {
			return 0, 0, err
		}
	}

	v4keys := make(map[[4]byte]struct{}, compiled.AllowedIPv4.Len())
	compiled.AllowedIPv4.ForEach(func(k [4]byte) { v4keys[k] = struct{}{} })
	if pol != nil {
		pol.MergeLiteralAllowedIPv4Keys(v4keys)
	}
	var literalNets []*net.IPNet
	if pol != nil {
		literalNets = pol.AllowedIPv4Nets()
	}
	totalEntries := len(v4keys) + len(literalNets)
	if totalEntries > policy.MaxAllowedEnforceIPv4Keys {
		return 0, 0, fmt.Errorf("lsm_allowed_ipv4: %d entries exceeds BPF max %d", totalEntries, policy.MaxAllowedEnforceIPv4Keys)
	}

	if totalEntries == 0 {
		return 0, 0, fmt.Errorf("enforce allowlist effective allowlist is empty (no map entries)")
	}

	if err := loadAllowedLPMMap(objs.LsmAllowedIpv4, v4keys, literalNets); err != nil {
		return 0, 0, err
	}

	if err := loadAllowedDomainsMap(objs.AllowedDomains, pol); err != nil {
		return 0, 0, err
	}

	return totalEntries, ignoredCount, nil
}

// loadEnforceMaps programs BPF allowlist maps from compiled domain resolutions + literal policy entries.
//
// PR-G: allowed_ipv4 is now a BPF_MAP_TYPE_LPM_TRIE (was HASH). Single-IP
// allowlist entries (resolved domain IPs + literal /32s from --allowed-ips)
// are still programmed individually but with prefixlen=32. Literal CIDR
// entries from --allowed-ips (e.g. "10.0.0.0/8") are programmed once as a
// single LPM key and cover every address inside the range.
func loadEnforceMaps(objs *traceenforce.TraceenforceObjects, compiled policy.CompileResult, pol *policy.Policy) (int, int, error) {
	if objs == nil {
		return 0, 0, fmt.Errorf("traceenforce objects are required for enforce mode")
	}
	keyMode := uint32(0)
	modeEnforce := uint32(1)
	if err := objs.EnforceCfg.Update(&keyMode, &modeEnforce, ebpf.UpdateAny); err != nil {
		return 0, 0, fmt.Errorf("load enforce_cfg map: %w", err)
	}
	ignoredCount := 0
	if pol != nil {
		var err error
		ignoredCount, err = loadIgnoredLPMMap(objs.IgnoredIpv4Lpm, pol.IgnoredIPv4Nets())
		if err != nil {
			return 0, 0, err
		}
	}

	v4keys := make(map[[4]byte]struct{}, compiled.AllowedIPv4.Len())
	compiled.AllowedIPv4.ForEach(func(k [4]byte) { v4keys[k] = struct{}{} })
	if pol != nil {
		pol.MergeLiteralAllowedIPv4Keys(v4keys)
	}
	var literalNets []*net.IPNet
	if pol != nil {
		literalNets = pol.AllowedIPv4Nets()
	}
	totalEntries := len(v4keys) + len(literalNets)
	if totalEntries > policy.MaxAllowedEnforceIPv4Keys {
		return 0, 0, fmt.Errorf("allowed_ipv4: %d entries exceeds BPF max %d", totalEntries, policy.MaxAllowedEnforceIPv4Keys)
	}

	if totalEntries == 0 {
		return 0, 0, fmt.Errorf("enforce allowlist effective allowlist is empty (no map entries)")
	}

	if err := loadAllowedLPMMap(objs.AllowedIpv4, v4keys, literalNets); err != nil {
		return 0, 0, err
	}

	if err := loadAllowedDomainsMap(objs.AllowedDomains, pol); err != nil {
		return 0, 0, err
	}

	return totalEntries, ignoredCount, nil
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
// definition in bpf/trace_enforce.bpf.c — they share wire format.
func loadAllowedLPMMap(m *ebpf.Map, ipKeys map[[4]byte]struct{}, nets []*net.IPNet) error {
	if m == nil {
		if len(ipKeys) > 0 || len(nets) > 0 {
			return fmt.Errorf("allowed_ipv4 map is nil with %d entries", len(ipKeys)+len(nets))
		}
		return nil
	}
	val := uint8(1)
	for addr := range ipKeys {
		var key [8]byte
		binary.LittleEndian.PutUint32(key[0:4], 32)
		copy(key[4:8], addr[:])
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("load allowed_ipv4 map (/32 %d.%d.%d.%d): %w",
				addr[0], addr[1], addr[2], addr[3], err)
		}
	}
	for _, n := range nets {
		if n == nil {
			slog.Warn("allowed_ipv4: skipping nil CIDR entry in allowed_ipv4 LPM load")
			continue
		}
		ones, bits := n.Mask.Size()
		if bits != 32 || ones < 0 || ones > 32 {
			slog.Warn("allowed_ipv4: skipping CIDR with non-IPv4 mask (unexpected from policy parse)", "cidr", n.String(), "bits", bits, "ones", ones)
			continue
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			slog.Warn("allowed_ipv4: skipping non-IPv4 CIDR (unexpected from policy parse)", "cidr", n.String())
			continue
		}
		network := ip4.Mask(n.Mask)
		if network == nil {
			slog.Warn("allowed_ipv4: skipping CIDR with nil masked network (unexpected)", "cidr", n.String())
			continue
		}
		var key [8]byte
		binary.LittleEndian.PutUint32(key[0:4], uint32(ones))
		binary.BigEndian.PutUint32(key[4:8], binary.BigEndian.Uint32(network))
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("load allowed_ipv4 map (cidr %s): %w", n.String(), err)
		}
	}
	return nil
}

func appendDenyFromRaw(cfg config.Config, raw []byte, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *enforcementState, signer *telemetry.Signer) (telemetry.DenyEvent, error) {
	tgid, tid, commb, protocolRaw, reasonRaw, af, daddr16, dport, ok := decodeDenyEvent(raw)
	if !ok {
		return telemetry.DenyEvent{}, fmt.Errorf("decode deny event")
	}
	protocol := denyProtocolLabel(protocolRaw)
	reason := denyReasonLabel(reasonRaw)
	if af != linuxAFInet {
		return telemetry.DenyEvent{}, fmt.Errorf("deny event: unsupported address family %d (IPv4 only)", af)
	}
	dst := net.IPv4(daddr16[0], daddr16[1], daddr16[2], daddr16[3]).String()
	comm := string(bytes.TrimRight(commb[:], "\x00"))
	ts := time.Now().UTC().Format(time.RFC3339Nano)
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
// for unit tests. Production readDenyRing logs and skips decode/JSONL failures so enforcement
// keeps running; successful denies still flow through appendDenyFromRaw unchanged.
func testAppendDenySample(cfg config.Config, raw []byte, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *enforcementState, signer *telemetry.Signer) error {
	deny, err := appendDenyFromRaw(cfg, raw, seq, jsonlMu, state, signer)
	if err != nil {
		return err
	}
	return newEnforceDenyError(deny)
}

func readDenyRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *enforcementState, signer *telemetry.Signer) error {
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

		if _, err := appendDenyFromRaw(cfg, record.RawSample, seq, jsonlMu, state, signer); err != nil {
			slog.Warn("deny ring sample skipped", "err", err)
			continue
		}

		drainUntil := time.Now().Add(enforceDenyDrainDuration)
		n := 1
		for n < enforceDenyDrainMaxEvents && time.Now().Before(drainUntil) {
			rd.SetDeadline(time.Now().Add(enforceDenyDrainReadSlice))
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
			if _, err3 := appendDenyFromRaw(cfg, rec2.RawSample, seq, jsonlMu, state, signer); err3 != nil {
				slog.Warn("deny ring drain sample skipped", "err", err3)
				continue
			}
			n++
		}
		rd.SetDeadline(time.Time{})
	}
}

// processDenyRingSample handles one deny ringbuf payload. Decode or JSONL failures are logged and
// dropped so readDenyRing never returns a fatal error (enforcement stays attached).
func processDenyRingSample(cfg config.Config, raw []byte, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *enforcementState, signer *telemetry.Signer) {
	deny, err := appendDenyFromRaw(cfg, raw, seq, jsonlMu, state, signer)
	if err != nil {
		slog.Warn("deny ring sample skipped", "err", err, "raw_len", len(raw))
		return
	}
	slog.Debug("enforce deny", "protocol", deny.Protocol, "dst", deny.Dst, "dport", deny.Dport,
		"reason", deny.Reason, "comm", deny.Comm)
}
