package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// hotEgressAgg aggregates digest rows by destination for the triage table.
type hotEgressAgg struct {
	key   string
	count int
	kinds map[string]struct{}
}

func normalizeDigestKey(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "`")
	return strings.TrimSpace(s)
}

func appendHotRow(m map[string]*hotEgressAgg, key, kind string) {
	k := normalizeDigestKey(key)
	if k == "" {
		return
	}
	e, ok := m[k]
	if !ok {
		e = &hotEgressAgg{key: k, kinds: make(map[string]struct{})}
		m[k] = e
	}
	e.count++
	e.kinds[kind] = struct{}{}
}

func buildHotEgressList(in DigestInput) []hotEgressAgg {
	m := make(map[string]*hotEgressAgg)
	for _, r := range in.TCPRows {
		appendHotRow(m, r.Remote, "tcp")
	}
	for _, r := range in.UDPRows {
		if fq := normalizeDigestKey(r.FQDN); fq != "" {
			appendHotRow(m, fq, "udp")
		} else {
			appendHotRow(m, r.Remote, "udp")
		}
	}
	for _, r := range in.HTTPRows {
		if h := normalizeDigestKey(r.Host); h != "" {
			appendHotRow(m, h, "http")
		} else {
			appendHotRow(m, r.Remote, "http")
		}
	}
	for _, r := range in.TLSRows {
		if sni := normalizeDigestKey(r.SNI); sni != "" {
			appendHotRow(m, sni, "tls")
		} else {
			appendHotRow(m, r.Remote, "tls")
		}
	}
	out := make([]hotEgressAgg, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].key < out[j].key
	})
	if len(out) > maxHotEgressEntities {
		out = out[:maxHotEgressEntities]
	}
	return out
}

func isBlockingDigestMode(m string) bool {
	m = strings.TrimSpace(m)
	if strings.EqualFold(m, "defend") {
		return true
	}
	return strings.HasPrefix(strings.ToLower(m), "defend+")
}

func digestModeCell(m string) string {
	m = strings.TrimSpace(m)
	if m == "" {
		return "detect"
	}
	return m
}

func hotKindTags(kinds map[string]struct{}) string {
	order := []string{"tcp", "udp", "http", "tls"}
	var tags []string
	for _, o := range order {
		if _, ok := kinds[o]; ok {
			tags = append(tags, o)
		}
	}
	return strings.Join(tags, ", ")
}

// hasPartialCoverageSignals is true when any counter indicates traffic was
// recorded with reduced fidelity: ringbuf reserve drops (events lost), the
// BG-01 per-syscall partial-observe paths (sendfile / splice / sendmmsg first-
// message-only), or scatter/gather syscalls whose iov[1..N] / msg[1..N] payload
// is not captured. Drives the headline note that the ✅ badge would otherwise
// imply complete observation.
func hasPartialCoverageSignals(in DigestInput) bool {
	return totalDetectRingbufReserveFailures(in) > 0 ||
		partialEgressTotal(in) > 0 ||
		in.UDPSendmsgMultiIovecObserved > 0 ||
		in.TLSWritevMultiIovecObserved > 0 ||
		in.SendmmsgMultiMessage > 0 ||
		in.DefendDenyReserveFailures > 0
}

// coveragePayloadState returns the "Payloads beyond iov[0]" cell text used in
// the headline Coverage block. Partial when any BG-01 partial-observe counter
// fired this run.
func coveragePayloadState(in DigestInput) string {
	if in.SendmmsgFirstOnly > 0 || in.SendfileObserved > 0 || in.SpliceObserved > 0 {
		return "⚠️ partial"
	}
	return "✓ observed"
}

// totalDetectRingbufReserveFailures sums ringbuf reserve failures across detect-path
// telemetry channels (excludes defend deny-event reserves; those are separate).
func totalDetectRingbufReserveFailures(in DigestInput) int {
	return telemetry.SumRingbufReserveFailuresDetectPath(
		in.UDPRingbufReserveFailures,
		in.DNSRingbufReserveFailures,
		in.ConnectRingbufReserveFailures,
		in.HTTPRingbufReserveFailures,
		in.TLSRingbufReserveFailures,
		in.ExecRingbufReserveFailures,
		in.ForkRingbufReserveFailures,
		in.FSRingbufReserveFailures,
		in.BPFAuditRingbufReserveFailures,
	)
}

// truthfulnessInterpretation adds triage text for partial syscall visibility and io_uring_setup
// (neutral wording; ringbuf pressure is its own triage row).
func truthfulnessInterpretation(in DigestInput) string {
	var parts []string
	if in.SendfileObserved > 0 || in.SpliceObserved > 0 || in.SendmmsgFirstOnly > 0 {
		parts = append(parts, "Some egress syscalls are counter-only; JSONL is not a full traffic map (SECURITY.md, Guarantees vs best-effort).")
	}
	if in.IoUringSetupObserved > 0 {
		parts = append(parts, "io_uring_setup(2) observed: async I/O may bypass syscall tracepoints; see io-uring-disable and SECURITY.md.")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

func procForkKPIVisible(in DigestInput) bool {
	return in.ProcForkTotal > 0 || in.ProcForkDegraded || len(in.ProcessTreeLines) > 0 || in.ProcForkReaderErrors > 0
}

func tlsKPIVisible(in DigestInput) bool {
	return in.TLSSNIGate
}

func fsKPIVisible(in DigestInput) bool {
	return in.FSGate
}

func protocolEmptyReason(degraded bool, errors int) string {
	if degraded {
		return "degraded hook"
	}
	if errors > 0 {
		return fmt.Sprintf("reader errors (%d)", errors)
	}
	return "no events"
}
