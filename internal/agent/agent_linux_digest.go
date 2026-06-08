//go:build linux

package agent

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// buildDroppedEventsMap returns a map of ringbuf reserve failures keyed by
// event-type slug (BPF counter name minus the `_ringbuf_reserve_failures`
// suffix). Returns nil when every counter is zero so MetaEvent.DroppedEvents
// omitempty hides the field entirely. The map is the H2 "silent event loss
// must be visible" surface — operators reading the JSONL shutdown meta can see
// at a glance which channels lost events without parsing the digest.
func buildDroppedEventsMap(stats *runStats, defendState *defendState) map[string]uint64 {
	m := make(map[string]uint64, 13)
	add := func(k string, v int) {
		if v > 0 {
			m[k] = uint64(v)
		}
	}
	add("connect", stats.connectRingbufReserveFailures())
	add("udp", stats.udpRingbufReserveFailures())
	add("dns", stats.dnsRingbufReserveFailures())
	add("http", stats.httpRingbufReserveFailures())
	add("tls", stats.tlsRingbufReserveFailures())
	add("exec", stats.execRingbufReserveFailures())
	add("fork", stats.forkRingbufReserveFailures())
	add("fs", stats.fsRingbufReserveFailures())
	add("ktls", stats.ktlsRingbufReserveFailures())
	add("bpf_audit", stats.bpfAuditRingbufReserveFailures())
	add("tcp_state", stats.tcpStateRingbufReserveFailures())
	add("io_uring", stats.ioUringRingbufReserveFailures())
	add("io_uring_tls", stats.ioUringTLSRingbufReserveFailures())
	add("egress_backstop", stats.egressBackstopReserveFailures())
	add("bpf_self_defense", stats.bpfSelfDefenseReserveFailures())
	if defendState != nil {
		add("deny", defendState.snapshot().denyReserveFailures)
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func preferRunError(current error, candidate error) error {
	if candidate == nil || errors.Is(candidate, context.Canceled) {
		return current
	}
	if current == nil {
		return candidate
	}
	if isDefendDenyError(candidate) && !isDefendDenyError(current) {
		return candidate
	}
	return current
}

func bpfDetail(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	const max = 180
	if len(s) <= max {
		return s
	}
	return truncateUTF8ToMaxBytes(s, max) + "…"
}

// truncateUTF8ToMaxBytes truncates s to at most max bytes without splitting a
// multi-byte rune (replaces report.TruncateUTF8ToMaxBytes).
func truncateUTF8ToMaxBytes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}

func hookDegraded(bpf []telemetry.BPFStatus, hookName string) bool {
	for _, row := range bpf {
		if row.Name == hookName {
			return !row.OK
		}
	}
	return true
}

func capabilityEnabled(gate bool, bpf []telemetry.BPFStatus, hookName string) bool {
	return gate && !hookDegraded(bpf, hookName)
}

// buildCoverageReport assembles the H5 v0.2.9 telemetry coverage stub embedded
// in the meta JSONL record. It is the structured (machine-readable) twin of
// the digest's "Coverage scope" table (rendered by H1 / writeCoverage). IPv4
// TCP and IPv4 UDP sendmsg are always wired by the agent's cgroup hooks, so
// they are reported as `true` independent of probe attach status; the BPF
// status rows on the same MetaEvent already carry the per-probe outcomes.
// IPv6 is "enforce" in defend mode with a populated allowed_ipv6 LPM trie
// (H14 v0.4.0 — P2-1 cgroup/connect6+sendmsg6 hooks attached and AAAA
// resolutions programmed); "off" otherwise. QUIC/HTTP3 enforcement is
// reported as `false` until the underlying probe lands; QuicObserved
// carries the H19 UDP/443 heuristic count. TLSSNI uses the same gate+hook
// composition as the `tls_sni` capability flag so a degraded BPF probe
// demotes coverage to "none".
func buildCoverageReport(bpf []telemetry.BPFStatus, tlsSNIGate, ioUringAttached, ipv6Enforced bool, quicObserved uint64) *telemetry.CoverageReport {
	tls := "none"
	if capabilityEnabled(tlsSNIGate, bpf, "raw_tp/sys_enter (connect, sendto, http sniff, tls)") {
		tls = "full"
	}
	ipv6 := telemetry.CoverageIPv6Off
	if ipv6Enforced {
		ipv6 = telemetry.CoverageIPv6Enforce
	}
	return &telemetry.CoverageReport{
		IPv4TCP:        true,
		IPv4UDPSendmsg: true,
		IPv6:           ipv6,
		QUICHTTP3:      false,
		QuicObserved:   quicObserved,
		TLSSNI:         tls,
		IoUring:        ioUringAttached,
	}
}

// digestDefendLabel maps internal defend snapshot + config to the digest/JSONL-facing mode name.
func digestDefendLabel(cfg config.Config, snap defendSnapshot) string {
	if cfg.Mode != config.ModeDefend {
		return snap.mode
	}
	if strings.TrimSpace(snap.mode) != "" {
		return snap.mode
	}
	return "defend"
}
