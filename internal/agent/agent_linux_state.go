//go:build linux

// State held by a single agent.Run invocation, split across three files:
//
//   - agent_linux_state.go (this file): runStats (cumulative per-run counters),
//     newRunStats, the lock-protected accessors, snapshotSummary, and rowBuffer
//     + trimRing (kept here because the row buffer feeds dropped-event
//     accounting back into runStats).
//   - agent_linux_state_sections.go: per-section state structs that don't
//     touch runStats directly — fork/fs/network sections, the BPF wire-format
//     constants, the ring-read retry backoff, the integrity canary, and the
//     small fixed-cap row/edge buffers consumed by them.
//   - agent_linux_state_defend.go: defend state, backend selection
//     (LSM vs cgroup), and the typed defend deny error used to fail-fast.

package agent

import (
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/report"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

type runStats struct {
	mu                             sync.Mutex
	execN                          int
	tcpN                           int
	udpN                           int
	httpN                          int
	tlsN                           int
	procForkN                      int
	fsN                            int
	connect4TupleUpdateFailuresN   int
	udpRingbufReserveFailuresN     int
	dnsRingbufReserveFailuresN     int
	connectRingbufReserveFailuresN int
	httpRingbufReserveFailuresN    int
	tlsRingbufReserveFailuresN     int
	execRingbufReserveFailuresN    int
	forkRingbufReserveFailuresN    int
	fsRingbufReserveFailuresN      int
	udpSendmsgMultiIovecObservedN  int
	sendmmsgMultiMessageN          int
	tlsWritevMultiIovecObservedN   int
	sendfileObservedN              int
	spliceObservedN                int
	sendmmsgFirstOnlyN             int
	ioUringSetupObservedN          int
	// P6 Phase 2: io_uring SQE buffer-peek event totals. ioUringTLSEventsN
	// counts every SQE that reached the JSONL path (peek_failed events
	// included so the digest can surface unsuccessful peek attempts);
	// ioUringTLSSNIExtractedN counts the subset where SNI parsed cleanly.
	ioUringTLSEventsN               int
	ioUringTLSSNIExtractedN         int
	ioUringRingbufReserveFailuresN  int
	tcpDNSResponsesObservedN        int
	tcpDNSSkippedShortReadN         int
	bpfAuditN                       int
	bpfMapIntegrityFailuresN        int
	bpfDNSCacheUpdateFailuresN      int
	bpfAuditRingbufReserveFailuresN int
	bpfHeartbeatFailures            int
	policyCounts                    map[string]int
	droppedCounts                   map[string]int
}

func newRunStats() *runStats {
	return &runStats{
		policyCounts:  make(map[string]int),
		droppedCounts: make(map[string]int),
	}
}

func (s *runStats) addDropped(kind string) {
	if strings.TrimSpace(kind) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.droppedCounts[kind]++
}

func (s *runStats) snapshotDroppedCounts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.droppedCounts))
	for k, v := range s.droppedCounts {
		out[k] = v
	}
	return out
}

func (s *runStats) addExec() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execN++
}

func (s *runStats) addProcFork() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.procForkN++
}

func (s *runStats) procForkTotal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.procForkN
}

func (s *runStats) addFS() {
	s.mu.Lock()
	s.fsN++
	s.mu.Unlock()
}

func (s *runStats) addPolicyLocked(cl policy.Class) {
	s.policyCounts[string(cl)]++
}

func (s *runStats) addTCP(cl policy.Class) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpN++
	s.addPolicyLocked(cl)
}

func (s *runStats) addUDP(cl policy.Class) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpN++
	s.addPolicyLocked(cl)
}

func (s *runStats) addHTTP(cl policy.Class) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.httpN++
	s.addPolicyLocked(cl)
}

func (s *runStats) addTLS(cl policy.Class) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsN++
	s.addPolicyLocked(cl)
}

func (s *runStats) setConnect4TupleUpdateFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connect4TupleUpdateFailuresN = n
}

func (s *runStats) connect4TupleUpdateFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connect4TupleUpdateFailuresN
}

func (s *runStats) setUDPRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpRingbufReserveFailuresN = n
}

func (s *runStats) udpRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpRingbufReserveFailuresN
}

func (s *runStats) setDNSRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsRingbufReserveFailuresN = n
}

func (s *runStats) dnsRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dnsRingbufReserveFailuresN
}

func (s *runStats) setConnectRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connectRingbufReserveFailuresN = n
}

func (s *runStats) setHTTPRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.httpRingbufReserveFailuresN = n
}

func (s *runStats) setTLSRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsRingbufReserveFailuresN = n
}

func (s *runStats) setExecRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execRingbufReserveFailuresN = n
}

func (s *runStats) setForkRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forkRingbufReserveFailuresN = n
}

func (s *runStats) setFSRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fsRingbufReserveFailuresN = n
}

func (s *runStats) connectRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connectRingbufReserveFailuresN
}

func (s *runStats) httpRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.httpRingbufReserveFailuresN
}

func (s *runStats) tlsRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsRingbufReserveFailuresN
}

func (s *runStats) execRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execRingbufReserveFailuresN
}

func (s *runStats) forkRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forkRingbufReserveFailuresN
}

func (s *runStats) fsRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fsRingbufReserveFailuresN
}

func (s *runStats) setUDPSendmsgMultiIovecObserved(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpSendmsgMultiIovecObservedN = n
}

func (s *runStats) udpSendmsgMultiIovecObserved() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpSendmsgMultiIovecObservedN
}

func (s *runStats) setSendmmsgMultiMessage(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendmmsgMultiMessageN = n
}

func (s *runStats) sendmmsgMultiMessage() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendmmsgMultiMessageN
}

func (s *runStats) setTLSWritevMultiIovecObserved(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsWritevMultiIovecObservedN = n
}

func (s *runStats) tlsWritevMultiIovecObserved() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsWritevMultiIovecObservedN
}

// setPartialEgressObserved records the BG-01 per-syscall partial-observe
// counters (sendfile, splice, sendmmsg first-only) snapshotted from BPF on
// shutdown. The three slots replaced the aggregate UnobservedEgressSyscalls
// counter so operators can see which path drove the gap.
func (s *runStats) setPartialEgressObserved(sendfile, splice, sendmmsg int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendfileObservedN = sendfile
	s.spliceObservedN = splice
	s.sendmmsgFirstOnlyN = sendmmsg
}

func (s *runStats) sendfileObserved() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendfileObservedN
}

func (s *runStats) spliceObserved() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spliceObservedN
}

func (s *runStats) sendmmsgFirstOnly() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendmmsgFirstOnlyN
}

func (s *runStats) setIoUringSetupObserved(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ioUringSetupObservedN = n
}

func (s *runStats) ioUringSetupObserved() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ioUringSetupObservedN
}

func (s *runStats) addIoUringTLSEvent() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ioUringTLSEventsN++
}

func (s *runStats) ioUringTLSEvents() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ioUringTLSEventsN
}

func (s *runStats) addIoUringTLSSNIExtracted() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ioUringTLSSNIExtractedN++
}

func (s *runStats) ioUringTLSSNIExtracted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ioUringTLSSNIExtractedN
}

func (s *runStats) setIoUringRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ioUringRingbufReserveFailuresN = n
}

func (s *runStats) ioUringRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ioUringRingbufReserveFailuresN
}

func (s *runStats) setTCPDNSResponsesObserved(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpDNSResponsesObservedN = n
}

func (s *runStats) tcpDNSResponsesObserved() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcpDNSResponsesObservedN
}

func (s *runStats) setTCPDNSSkippedShortRead(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpDNSSkippedShortReadN = n
}

func (s *runStats) tcpDNSSkippedShortRead() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcpDNSSkippedShortReadN
}

func (s *runStats) addBPFHeartbeatFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bpfHeartbeatFailures++
}

func (s *runStats) bpfHeartbeatFailureCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bpfHeartbeatFailures
}

func (s *runStats) addBPFAudit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bpfAuditN++
}

func (s *runStats) setBPFAuditRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bpfAuditRingbufReserveFailuresN = n
}

func (s *runStats) bpfAuditTotal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bpfAuditN
}

func (s *runStats) addBPFMapIntegrityFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bpfMapIntegrityFailuresN++
}

func (s *runStats) bpfMapIntegrityFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bpfMapIntegrityFailuresN
}

// addDNSCacheUpdateFailure bumps the per-run counter for failed BPF
// dns_cache map mutations (Update or non-ErrKeyNotExist Delete). Wired to
// DNSCache.SetBPFFailureCallback so partial sync between userspace and the
// kernel-side dns_cache instances is observable in the digest (M-09).
func (s *runStats) addDNSCacheUpdateFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bpfDNSCacheUpdateFailuresN++
}

func (s *runStats) bpfAuditRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bpfAuditRingbufReserveFailuresN
}

func (s *runStats) snapshotSummary(kernel string, bpf []telemetry.BPFStatus) telemetry.Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	pc := make(map[string]int, len(s.policyCounts))
	for k, v := range s.policyCounts {
		pc[k] = v
	}
	dropped := make(map[string]int, len(s.droppedCounts))
	for k, v := range s.droppedCounts {
		dropped[k] = v
	}
	rbTotal := telemetry.SumRingbufReserveFailuresDetectPath(
		s.udpRingbufReserveFailuresN,
		s.dnsRingbufReserveFailuresN,
		s.connectRingbufReserveFailuresN,
		s.httpRingbufReserveFailuresN,
		s.tlsRingbufReserveFailuresN,
		s.execRingbufReserveFailuresN,
		s.forkRingbufReserveFailuresN,
		s.fsRingbufReserveFailuresN,
		s.bpfAuditRingbufReserveFailuresN,
	)
	return telemetry.Summary{
		Version:                        2,
		SchemaVersion:                  telemetry.SchemaVersion,
		ExecEvents:                     s.execN,
		TCPEvents:                      s.tcpN,
		UDPEvents:                      s.udpN,
		HTTPEvents:                     s.httpN,
		TLSEvents:                      s.tlsN,
		ProcForkEvents:                 s.procForkN,
		Connect4TupleUpdateFailures:    s.connect4TupleUpdateFailuresN,
		UDPRingbufReserveFailures:      s.udpRingbufReserveFailuresN,
		DNSRingbufReserveFailures:      s.dnsRingbufReserveFailuresN,
		ConnectRingbufReserveFailures:  s.connectRingbufReserveFailuresN,
		HTTPRingbufReserveFailures:     s.httpRingbufReserveFailuresN,
		TLSRingbufReserveFailures:      s.tlsRingbufReserveFailuresN,
		ExecRingbufReserveFailures:     s.execRingbufReserveFailuresN,
		ForkRingbufReserveFailures:     s.forkRingbufReserveFailuresN,
		FSRingbufReserveFailures:       s.fsRingbufReserveFailuresN,
		RingbufReserveFailuresTotal:    rbTotal,
		UDPSendmsgMultiIovecObserved:   s.udpSendmsgMultiIovecObservedN,
		SendmmsgMultiMessage:           s.sendmmsgMultiMessageN,
		TLSWritevMultiIovecObserved:    s.tlsWritevMultiIovecObservedN,
		SendfileObserved:               s.sendfileObservedN,
		SpliceObserved:                 s.spliceObservedN,
		SendmmsgFirstOnly:              s.sendmmsgFirstOnlyN,
		IoUringSetupObserved:           s.ioUringSetupObservedN,
		IoUringTLSEvents:               s.ioUringTLSEventsN,
		IoUringTLSSNIExtracted:         s.ioUringTLSSNIExtractedN,
		IoUringRingbufReserveFailures:  s.ioUringRingbufReserveFailuresN,
		TCPDNSResponsesObserved:        s.tcpDNSResponsesObservedN,
		TCPDNSSkippedShortRead:         s.tcpDNSSkippedShortReadN,
		BPFAuditEvents:                 s.bpfAuditN,
		BPFHeartbeatFailures:           s.bpfHeartbeatFailures,
		BPFMapIntegrityFailures:        s.bpfMapIntegrityFailuresN,
		BPFDNSCacheUpdateFailures:      s.bpfDNSCacheUpdateFailuresN,
		BPFAuditRingbufReserveFailures: s.bpfAuditRingbufReserveFailuresN,
		DroppedCounts:                  dropped,
		PolicyCounts:                   pc,
		KernelRelease:                  kernel,
		BPF:                            bpf,
	}
}

func (s *runStats) counts() (execN, tcpN, udpN, httpN, tlsN, fsN int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execN, s.tcpN, s.udpN, s.httpN, s.tlsN, s.fsN
}

// snapshotPolicyCounts returns a copy of policy classification counters for digests.
func (s *runStats) snapshotPolicyCounts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	pc := make(map[string]int, len(s.policyCounts))
	for k, v := range s.policyCounts {
		pc[k] = v
	}
	return pc
}

type rowBuffer struct {
	mu   sync.Mutex
	max  int
	exec []report.ExecDigestRow
	tcp  []report.TCPDigestRow
	udp  []report.UDPDigestRow
	http []report.HTTPDigestRow
	tls  []report.TLSDigestRow
}

func newRowBuffer(max int) *rowBuffer {
	return &rowBuffer{max: max}
}

// trimRing trims s to at most max entries (drops oldest); returns the number of dropped entries
// so callers can record the drop in stats (e.g. runStats.addDropped("<kind>_ring_trim")).
func trimRing[T any](s *[]T, max int) int {
	if max <= 0 || len(*s) <= max {
		return 0
	}
	droppedN := len(*s) - max
	*s = (*s)[droppedN:]
	slog.Debug("telemetry row buffer trimmed (ring full)", "dropped", droppedN, "retained", max)
	return droppedN
}

func (b *rowBuffer) addExec(r report.ExecDigestRow, stats *runStats) {
	b.mu.Lock()
	b.exec = append(b.exec, r)
	dropped := trimRing(&b.exec, b.max)
	b.mu.Unlock()
	if dropped > 0 && stats != nil {
		for i := 0; i < dropped; i++ {
			stats.addDropped("exec_ring_trim")
		}
	}
}

func (b *rowBuffer) addTCP(r report.TCPDigestRow, stats *runStats) {
	b.mu.Lock()
	b.tcp = append(b.tcp, r)
	dropped := trimRing(&b.tcp, b.max)
	b.mu.Unlock()
	if dropped > 0 && stats != nil {
		for i := 0; i < dropped; i++ {
			stats.addDropped("tcp_ring_trim")
		}
	}
}

func (b *rowBuffer) addUDP(r report.UDPDigestRow, stats *runStats) {
	b.mu.Lock()
	b.udp = append(b.udp, r)
	dropped := trimRing(&b.udp, b.max)
	b.mu.Unlock()
	if dropped > 0 && stats != nil {
		for i := 0; i < dropped; i++ {
			stats.addDropped("udp_ring_trim")
		}
	}
}

func (b *rowBuffer) addHTTP(r report.HTTPDigestRow, stats *runStats) {
	b.mu.Lock()
	b.http = append(b.http, r)
	dropped := trimRing(&b.http, b.max)
	b.mu.Unlock()
	if dropped > 0 && stats != nil {
		for i := 0; i < dropped; i++ {
			stats.addDropped("http_ring_trim")
		}
	}
}

func (b *rowBuffer) addTLS(r report.TLSDigestRow, stats *runStats) {
	b.mu.Lock()
	b.tls = append(b.tls, r)
	dropped := trimRing(&b.tls, b.max)
	b.mu.Unlock()
	if dropped > 0 && stats != nil {
		for i := 0; i < dropped; i++ {
			stats.addDropped("tls_ring_trim")
		}
	}
}

func (b *rowBuffer) snapshot() (exec []report.ExecDigestRow, tcp []report.TCPDigestRow, udp []report.UDPDigestRow, http []report.HTTPDigestRow, tls []report.TLSDigestRow) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.exec), slices.Clone(b.tcp), slices.Clone(b.udp), slices.Clone(b.http), slices.Clone(b.tls)
}
