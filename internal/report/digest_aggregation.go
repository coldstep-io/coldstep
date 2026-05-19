package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// tcpResultBuckets is the rendering order for the TCP connections KPI
// breakdown. "other" sweeps up errno classes that don't have a friendly
// label (e.g. EADDRINUSE on rebind, EAGAIN in non-blocking flows).
var tcpResultBuckets = []string{"established", "refused", "timeout", "unreachable", "in_progress", "denied", "other"}

// hasTCPResultBreakdown reports whether the kretprobe-derived bucket
// counts have non-zero entries — used to decide whether to render the
// new "TCP connections" KPI row and to switch the TCP semantics
// footnote between the established/timeout/refused wording and the
// legacy attempt-only caveat.
func hasTCPResultBreakdown(counts map[string]int) bool {
	for _, v := range counts {
		if v > 0 {
			return true
		}
	}
	return false
}

// formatTCPResultBreakdown renders the kretprobe bucket counts as
// "18 established · 3 refused · 1 timeout" for the KPI row. Returns the
// empty string when there is nothing to show (no kretprobe events
// recorded yet, kretprobe attach failed, or the run captured no TCP
// connections at all) so callers can suppress the row entirely.
func formatTCPResultBreakdown(counts map[string]int) string {
	if !hasTCPResultBreakdown(counts) {
		return ""
	}
	var parts []string
	for _, bucket := range tcpResultBuckets {
		if n := counts[bucket]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, bucket))
		}
	}
	return strings.Join(parts, " · ")
}

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
//
// sendpage_observed (lsm/socket_sendpage) closes the kernel-5.15
// sendfile(2)/splice(2) sock_sendpage gap: when the hook is attached and
// firing in defend mode, the underlying payload is gated even though the
// detect path's HTTP/TLS sniff is still skipped. Treat the "Payloads beyond
// iov[0]" cell as observed when SendpageObserved > 0 *and* no other partial
// counter fired — operators reading this in defend mode should see that
// sendfile/splice are not silently unenforced.
func coveragePayloadState(in DigestInput) string {
	sendfileGapClosed := in.SendpageObserved > 0
	if !sendfileGapClosed && (in.SendfileObserved > 0 || in.SpliceObserved > 0) {
		return "⚠️ partial"
	}
	if in.SendmmsgFirstOnly > 0 {
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

// formatTLSConfidenceCell renders the per-tier TLS SNI confidence counters as
// a compact `full=N partial=M unknown=K` cell. Inferred is only included when
// non-zero (no enricher emits it today, so callers can keep the cell short).
// Callers should gate the row on TLSTotal > 0; we still defend with the same
// check so an accidental call with zero events does not show a misleading row.
func formatTLSConfidenceCell(in DigestInput) string {
	if in.TLSTotal == 0 {
		return "—"
	}
	parts := []string{
		fmt.Sprintf("full=%d", in.TLSConfidenceFull),
		fmt.Sprintf("partial=%d", in.TLSConfidencePartial),
	}
	if in.TLSConfidenceInferred > 0 {
		parts = append(parts, fmt.Sprintf("inferred=%d", in.TLSConfidenceInferred))
	}
	parts = append(parts, fmt.Sprintf("unknown=%d", in.TLSConfidenceUnknown))
	return strings.Join(parts, " · ")
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
