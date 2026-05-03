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

func preferRunError(current error, candidate error) error {
	if candidate == nil || errors.Is(candidate, context.Canceled) {
		return current
	}
	if current == nil {
		return candidate
	}
	if isEnforceDenyError(candidate) && !isEnforceDenyError(current) {
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

// digestEnforcementLabel maps internal enforcement snapshot + config to the digest/JSONL-facing mode name.
func digestEnforcementLabel(cfg config.Config, snap enforcementSnapshot) string {
	if cfg.Mode != config.ModeEnforce {
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
	enforceState enforcementSnapshot,
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
	rawTPName := "raw_tp/sys_enter (connect, sendto, http sniff, tls)"
	in := report.DigestInput{
		DetectProfile:                  cfg.DetectProfile,
		BPF:                            bpfSt,
		ExecTotal:                      execN,
		TCPTotal:                       tcpN,
		UDPTotal:                       udpN,
		HTTPTotal:                      httpN,
		TLSTotal:                       tlsN,
		TLSSNIGate:                     tlsSNIGate,
		PolicyCounts:                   stats.snapshotPolicyCounts(),
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
		EnforcementMode:                digestEnforcementLabel(cfg, enforceState),
		EnforcementAllowlistSize:       enforceState.allowlistSize,
		EnforcementDenyCount:           enforceState.denyCount,
		EnforcementDenyReserveFailures: enforceState.denyReserveFailures,
		EnforcementFirstDeny:           enforceState.firstDeny,
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
		TLSWritevMultiIovecObserved:    stats.tlsWritevMultiIovecObserved(),
		UnobservedEgressSyscalls:       stats.unobservedEgressSyscalls(),
		IoUringSetupObserved:           stats.ioUringSetupObserved(),
		CanaryPipelineOK:               canarySnap.pipelineOK,
		CanaryFailCount:                canarySnap.failCount,
		TCPDNSResponsesObserved:        stats.tcpDNSResponsesObserved(),
		TCPDNSSkippedShortRead:         stats.tcpDNSSkippedShortRead(),
		BPFAuditTotal:                  stats.bpfAuditTotal(),
		BPFMapIntegrityFailures:        stats.bpfMapIntegrityFailures(),
		BPFAuditRingbufReserveFailures: stats.bpfAuditRingbufReserveFailures(),
		BPFHeartbeatFailures:           stats.bpfHeartbeatFailureCount(),
		DroppedCounts:                  stats.snapshotDroppedCounts(),
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
	return in
}
