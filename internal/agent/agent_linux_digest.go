//go:build linux

package agent

import (
	"context"
	"errors"
	"strings"

	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/proctree"
	"github.com/coldstep-io/coldstep/internal/report"
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
	return report.TruncateUTF8ToMaxBytes(s, max) + "…"
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
// IPv6 and QUIC/HTTP3 are reported as `false` until the underlying probes
// land. TLSSNI uses the same gate+hook composition as the `tls_sni`
// capability flag so a degraded BPF probe demotes coverage to "none".
func buildCoverageReport(bpf []telemetry.BPFStatus, tlsSNIGate, ioUringAttached bool) *telemetry.CoverageReport {
	tls := "none"
	if capabilityEnabled(tlsSNIGate, bpf, "raw_tp/sys_enter (connect, sendto, http sniff, tls)") {
		tls = "full"
	}
	return &telemetry.CoverageReport{
		IPv4TCP:        true,
		IPv4UDPSendmsg: true,
		IPv6:           false,
		QUICHTTP3:      false,
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

func buildDigestInput(
	cfg config.Config,
	stats *runStats,
	bpfSt []telemetry.BPFStatus,
	execRows []report.ExecDigestRow,
	tcpRows []report.TCPDigestRow,
	udpRows []report.UDPDigestRow,
	httpRows []report.HTTPDigestRow,
	tlsRows []report.TLSDigestRow,
	jsonlPath string,
	seqLast uint64,
	maxRows int,
	sectionState networkSectionSnapshot,
	defendState defendSnapshot,
	forkEdges []proctree.Edge,
	forkEdgesTrunc bool,
	forkSnap forkSectionSnapshot,
	procTreeGate bool,
	tlsSNIGate bool,
	fsRows []report.FSDigestRow,
	fsSnap fsSectionSnapshot,
	fsGate bool,
	canarySnap canarySnapshot,
) report.DigestInput {
	execN, tcpN, udpN, httpN, tlsN, fsN := stats.counts()
	tlsConfFull, tlsConfPartial, tlsConfInferred, tlsConfUnknown, tlsConfUnknownKTLS := stats.tlsConfidenceCounts()
	tcpStateTotal, tcpStateConfirmed, tcpStateRefused := stats.tcpStateTotals()
	rawTPName := "raw_tp/sys_enter (connect, sendto, http sniff, tls)"
	in := report.DigestInput{
		DetectProfile:                  cfg.DetectProfile,
		BPF:                            bpfSt,
		RunnerHasIPv6:                  cfg.RunnerHasIPv6,
		RunnerEnv:                      stats.snapshotRunnerEnv(),
		ExecTotal:                      execN,
		TCPTotal:                       tcpN,
		UDPTotal:                       udpN,
		HTTPTotal:                      httpN,
		TLSTotal:                       tlsN,
		TLSConfidenceFull:              tlsConfFull,
		TLSConfidencePartial:           tlsConfPartial,
		TLSConfidenceInferred:          tlsConfInferred,
		TLSConfidenceUnknown:           tlsConfUnknown,
		TLSConfidenceUnknownKTLS:       tlsConfUnknownKTLS,
		TLSSNIGate:                     tlsSNIGate,
		PolicyCounts:                   stats.snapshotPolicyCounts(),
		TCPResultCounts:                stats.snapshotTCPResultCounts(),
		ExecRows:                       execRows,
		TCPRows:                        tcpRows,
		UDPRows:                        udpRows,
		HTTPRows:                       httpRows,
		TLSRows:                        tlsRows,
		JSONLPath:                      jsonlPath,
		SeqFirst:                       1,
		SeqLast:                        seqLast,
		MaxRowsPerSection:              maxRows,
		TruncatedExec:                  execN > maxRows,
		TruncatedTCP:                   tcpN > maxRows,
		TruncatedUDP:                   udpN > maxRows,
		TruncatedHTTP:                  httpN > maxRows,
		TruncatedTLS:                   tlsN > maxRows,
		TCPDegradedHook:                hookDegraded(bpfSt, rawTPName),
		TCPReaderErrors:                sectionState.tcpReadErrors + sectionState.tcpDecodeErrors,
		UDPDegradedHook:                hookDegraded(bpfSt, rawTPName),
		UDPReaderErrors:                sectionState.udpReadErrors + sectionState.udpDecodeErrors,
		HTTPDegradedHook:               hookDegraded(bpfSt, rawTPName),
		HTTPReaderErrors:               sectionState.httpReadErrors + sectionState.httpDecodeErrors,
		TLSDegradedHook:                hookDegraded(bpfSt, rawTPName),
		TLSReaderErrors:                sectionState.tlsReadErrors + sectionState.tlsDecodeErrors,
		DefendMode:                     digestDefendLabel(cfg, defendState),
		DefendAllowlistSize:            defendState.allowlistSize,
		DefendIPv6AllowlistSize:        defendState.allowlistIPv6Size,
		DefendDenyCount:                defendState.denyCount,
		DefendDenyReserveFailures:      defendState.denyReserveFailures,
		DefendFirstDeny:                defendState.firstDeny,
		Connect4TupleUpdateFailures:    stats.connect4TupleUpdateFailures(),
		UDPRingbufReserveFailures:      stats.udpRingbufReserveFailures(),
		DNSRingbufReserveFailures:      stats.dnsRingbufReserveFailures(),
		ConnectRingbufReserveFailures:  stats.connectRingbufReserveFailures(),
		HTTPRingbufReserveFailures:     stats.httpRingbufReserveFailures(),
		TLSRingbufReserveFailures:      stats.tlsRingbufReserveFailures(),
		ExecRingbufReserveFailures:     stats.execRingbufReserveFailures(),
		ForkRingbufReserveFailures:     stats.forkRingbufReserveFailures(),
		FSRingbufReserveFailures:       stats.fsRingbufReserveFailures(),
		UDPSendmsgMultiIovecObserved:   stats.udpSendmsgMultiIovecObserved(),
		SendmmsgMultiMessage:           stats.sendmmsgMultiMessage(),
		SendmmsgUnobservedExtra:        stats.sendmmsgUnobservedExtra(),
		TLSWritevMultiIovecObserved:    stats.tlsWritevMultiIovecObserved(),
		SendfileObserved:               stats.sendfileObserved(),
		SpliceObserved:                 stats.spliceObserved(),
		SendmmsgFirstOnly:              stats.sendmmsgFirstOnly(),
		IPv6ConnectObserved:            stats.ipv6ConnectObserved(),
		IPv6SendmsgObserved:            stats.ipv6SendmsgObserved(),
		SendpageObserved:               stats.sendpageObserved(),
		IoUringSetupObserved:           stats.ioUringSetupObserved(),
		IoUringSendTotal:               stats.ioUringSendTotal(),
		IoUringRingbufReserveFailures:  stats.ioUringRingbufReserveFailures(),
		IoUringTLSHelloObserved:        stats.ioUringTLSHelloObserved(),
		CanaryPipelineOK:               canarySnap.pipelineOK,
		CanaryFailCount:                canarySnap.failCount,
		TCPDNSResponsesObserved:        stats.tcpDNSResponsesObserved(),
		TCPDNSSkippedShortRead:         stats.tcpDNSSkippedShortRead(),
		QUICCandidateCount:             stats.quicCandidateTotal(),
		BPFAuditTotal:                  stats.bpfAuditTotal(),
		BPFMapIntegrityFailures:        stats.bpfMapIntegrityFailures(),
		BPFAuditRingbufReserveFailures: stats.bpfAuditRingbufReserveFailures(),
		KTLSOffloadTotal:               stats.ktlsTotal(),
		KTLSRingbufReserveFailures:     stats.ktlsRingbufReserveFailures(),
		BPFHeartbeatFailures:           stats.bpfHeartbeatFailureCount(),
		DroppedCounts:                  stats.snapshotDroppedCounts(),
		TCPStateTotal:                  tcpStateTotal,
		TCPStateConfirmed:              tcpStateConfirmed,
		TCPStateRefused:                tcpStateRefused,
		TCPStateReaderErrors:           sectionState.tcpStateReadErrors + sectionState.tcpStateDecodeErrors,
		TCPStateRingbufReserveFailures: stats.tcpStateRingbufReserveFailures(),
		FSGate:                         fsGate,
		FSTotal:                        fsN,
		FSRows:                         fsRows,
		TruncatedFS:                    fsN > maxRows,
		FSDegradedHook:                 fsGate && hookDegraded(bpfSt, "raw_tp/sys_enter (fs)"),
		FSReaderErrors:                 fsSnap.readErrors,
	}
	if procTreeGate {
		in.ProcForkTotal = stats.procForkTotal()
		in.ProcForkDegraded = hookDegraded(bpfSt, "sched_process_fork")
		in.ProcForkReaderErrors = forkSnap.readErrors
		in.TruncatedProcessTree = forkEdgesTrunc
		execID := make(map[uint32]proctree.ExecIdentity, len(execRows)+8)
		for _, r := range execRows {
			execID[r.PID] = proctree.ExecIdentity{Comm: r.Comm, Exe: r.Exe}
		}
		in.ProcessTreeLines = proctree.FormatForestLines(forkEdges, execID, maxRows)
	}
	if seqLast == 0 {
		in.SeqFirst = 0
	}

	compileTime, _, unresolved, wildcardRisk := stats.allowlistSnapshot()
	in.UnresolvedAllowlistDomains = unresolved
	in.WildcardRiskDomains = wildcardRisk
	in.AllowlistCompileTime = compileTime
	in.AllowlistEntryCount = defendState.allowlistSize
	in.DomainContactCounts = stats.snapshotDomainCounts()

	return in
}
