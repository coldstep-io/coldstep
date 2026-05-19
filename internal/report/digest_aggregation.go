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

// tlsConfidenceBreakdown renders the per-tier TLS SNI breakdown shown next to
// the tls KPI total — e.g. `42 names · 38 full · 3 partial · 1 inferred`. It
// returns an empty string when no rows or tier counters are present so that
// the KPI table stays terse for runs without TLS visibility.
func tlsConfidenceBreakdown(in DigestInput) string {
	total := in.TLSConfidenceFull + in.TLSConfidencePartial + in.TLSConfidenceInferred + in.TLSConfidenceUnknown
	if total == 0 {
		return ""
	}
	parts := []string{fmt.Sprintf("%d names", total)}
	if in.TLSConfidenceFull > 0 {
		parts = append(parts, fmt.Sprintf("%d full", in.TLSConfidenceFull))
	}
	if in.TLSConfidencePartial > 0 {
		parts = append(parts, fmt.Sprintf("%d partial", in.TLSConfidencePartial))
	}
	if in.TLSConfidenceInferred > 0 {
		parts = append(parts, fmt.Sprintf("%d inferred", in.TLSConfidenceInferred))
	}
	if in.TLSConfidenceUnknown > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown", in.TLSConfidenceUnknown))
	}
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
