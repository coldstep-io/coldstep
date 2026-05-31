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
	"time"

	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/report"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

type runStats struct {
	mu                     sync.Mutex
	execN                  int
	tcpN                   int
	udpN                   int
	httpN                  int
	tlsN                   int
	tlsConfidenceFullN     int
	tlsConfidencePartialN  int
	tlsConfidenceInferredN int
	tlsConfidenceUnknownN  int
	// tlsConfidenceUnknownKTLSN is the subset of tlsConfidenceUnknownN whose
	// Confidence was forced from full/partial/unknown to unknown by the P4
	// KTLS override in readTLSRing. Surfaced in the digest as the
	// `(N ktls-offloaded)` annotation on the TLS SNI KPI cell.
	tlsConfidenceUnknownKTLSN      int
	procForkN                      int
	fsN                            int
	ktlsN                          int
	ktlsRingbufReserveFailuresN    int
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
	sendmmsgUnobservedExtraN       int
	tlsWritevMultiIovecObservedN   int
	sendfileObservedN              int
	spliceObservedN                int
	sendmmsgFirstOnlyN             int
	ipv6ConnectObservedN           uint32
	ipv6SendmsgObservedN           uint32
	ipv6EventCountN                int
	ipv6RingbufReserveFailuresN    int
	sendpageObservedN              uint32
	ioUringSetupObservedN          int
	ioUringSendN                   int
	ioUringTLSHelloN               int
	ioUringRingbufReserveFailuresN int
	// ioUringTLSSNISet collects distinct SNI hostnames parsed from io_uring
	// ClientHello captures (P6 Phase 2.5). Rendered as the "io_uring TLS SNI"
	// digest KPI row. nil until the first SNI is observed.
	ioUringTLSSNISet                map[string]struct{}
	tcpDNSResponsesObservedN        int
	tcpDNSSkippedShortReadN         int
	quicCandidateN                  int
	quicObservedN                   uint64 // H19: count of UDPEvent.PossibleQUIC=true
	bpfAuditN                       int
	bpfMapIntegrityFailuresN        int
	bpfDNSCacheUpdateFailuresN      int
	bpfAuditRingbufReserveFailuresN int
	bpfHeartbeatFailures            int
	tcpStateN                       int
	tcpStateConfirmed               int // newstate == ESTABLISHED
	tcpStateRefused                 int // newstate == CLOSE (RST / timeout / unreach)
	tcpStateRingbufReserveFailuresN int
	policyCounts                    map[string]int
	droppedCounts                   map[string]int
	tcpResultCounts                 map[string]int // P3-2: established/refused/timeout/...

	// Allowlist compile snapshot (P1-1). Set once at startup after
	// CompileDomainAllowlist; read at shutdown by buildDigestInput.
	allowlistCompileTime         time.Time
	allowlistIPCount             int
	allowlistDomains             []string
	allowlistUnresolvedDomains   []string
	allowlistWildcardRiskDomains []string

	// dnsDriftN counts the number of times the H16 background re-resolution
	// goroutine observed IPv4 drift (added or removed) between the startup
	// snapshot and a periodic re-resolution. Each non-empty DriftReport
	// bumps this counter by 1. Live BPF policy is NOT updated on drift —
	// the counter is purely advisory and surfaces in the shutdown digest as
	// a "DNS drift detected" warning.
	dnsDriftN int

	// dstDomainCounts maps observed FQDN → connection-event count across TCP +
	// UDP egress (P1-1 6e). Empty FQDNs are ignored.
	dstDomainCounts map[string]int

	// runnerEnv mirrors the value DetectRunnerEnv() produced at agent startup
	// (H13). Set once in agent.Run and read at shutdown by buildDigestInput
	// to surface the ⚠️ DinD warning box in the digest. Empty/standard values
	// produce no extra surface.
	runnerEnv string
}

func newRunStats() *runStats {
	return &runStats{
		policyCounts:    make(map[string]int),
		droppedCounts:   make(map[string]int),
		tcpResultCounts: make(map[string]int),
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

// setRunnerEnv records the H13 runner-env classification at agent startup so
// the digest can render the ⚠️ DinD warning box later. Called once before any
// event readers start.
func (s *runStats) setRunnerEnv(env string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runnerEnv = env
}

func (s *runStats) snapshotRunnerEnv() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runnerEnv
}

func (s *runStats) addKTLS() {
	s.mu.Lock()
	s.ktlsN++
	s.mu.Unlock()
}

func (s *runStats) ktlsTotal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ktlsN
}

func (s *runStats) setKTLSRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ktlsRingbufReserveFailuresN = n
}

func (s *runStats) ktlsRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ktlsRingbufReserveFailuresN
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

// addTCPResult records a tcp_v4_connect outcome bucket emitted by the
// kretprobe-side connect_result_event (P3-2). Buckets are coarse strings
// from telemetry.ConnectResultString — established / refused / timeout /
// unreachable / in_progress / denied / other.
func (s *runStats) addTCPResult(bucket string) {
	if strings.TrimSpace(bucket) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpResultCounts[bucket]++
}

func (s *runStats) snapshotTCPResultCounts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.tcpResultCounts))
	for k, v := range s.tcpResultCounts {
		out[k] = v
	}
	return out
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

func (s *runStats) addTLS(cl policy.Class, conf telemetry.TLSConfidence, ktlsOverride bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsN++
	switch conf {
	case telemetry.TLSConfidenceFull:
		s.tlsConfidenceFullN++
	case telemetry.TLSConfidencePartial:
		s.tlsConfidencePartialN++
	case telemetry.TLSConfidenceInferred:
		s.tlsConfidenceInferredN++
	default:
		s.tlsConfidenceUnknownN++
		if ktlsOverride {
			s.tlsConfidenceUnknownKTLSN++
		}
	}
	s.addPolicyLocked(cl)
}

// tlsConfidenceCounts returns per-tier TLS confidence counters (full,
// partial, inferred, unknown) for digest reporting. unknownKTLS is the subset
// of unknown attributed to the P4 KTLS override; the digest renders it as a
// sub-bucket inside the unknown count.
func (s *runStats) tlsConfidenceCounts() (full, partial, inferred, unknown, unknownKTLS int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsConfidenceFullN, s.tlsConfidencePartialN, s.tlsConfidenceInferredN, s.tlsConfidenceUnknownN, s.tlsConfidenceUnknownKTLSN
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

func (s *runStats) setSendmmsgUnobservedExtra(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendmmsgUnobservedExtraN = n
}

func (s *runStats) sendmmsgUnobservedExtra() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendmmsgUnobservedExtraN
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

// setIPv6ConnectObserved / setIPv6SendmsgObserved record the P0-1 Phase 1
// IPv6 observe-only counters snapshotted from BPF on shutdown. cgroup/connect6
// and cgroup/sendmsg6 hooks bump per-cpu uint32 counters; userspace sums them
// across CPUs (see readIPv6ConnectObservedCount / readIPv6SendmsgObservedCount).
// Non-zero means traffic egressed via IPv6 — which the IPv4-only defend hooks
// could not gate. The digest surfaces this as a warning (detect) or alert
// (defend); Phase 2 will add actual IPv6 enforcement.
func (s *runStats) setIPv6ConnectObserved(n uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipv6ConnectObservedN = n
}

func (s *runStats) ipv6ConnectObserved() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ipv6ConnectObservedN
}

func (s *runStats) setIPv6SendmsgObserved(n uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipv6SendmsgObservedN = n
}

func (s *runStats) ipv6SendmsgObserved() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ipv6SendmsgObservedN
}

// addIPv6Event bumps the per-event counter populated by readIPv6ObsRing
// (H7). One increment per ringbuf record decoded — i.e. per non-loopback,
// non-link-local IPv6 connect / sendmsg observed in detect mode. Defend
// mode does not load the traceipv6 object, so this counter is always 0
// there; defend-mode IPv6 visibility flows through ipv6ConnectObservedN /
// ipv6SendmsgObservedN instead.
func (s *runStats) addIPv6Event() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipv6EventCountN++
}

func (s *runStats) ipv6EventCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ipv6EventCountN
}

func (s *runStats) setIPv6RingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipv6RingbufReserveFailuresN = n
}

func (s *runStats) ipv6RingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ipv6RingbufReserveFailuresN
}

// setSendpageObserved records the lsm/socket_sendpage observe counter
// snapshotted from BPF on shutdown. Non-zero means sendfile(2)/splice(2)
// fired through sock_sendpage on this kernel (5.15 path) — defend gating
// at the sendpage LSM closes the gap that cgroup/sendmsg4 misses.
// TODO: wire fully after BPF stubs are regenerated on Linux; today this
// is a no-op when the map is absent.
func (s *runStats) setSendpageObserved(n uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendpageObservedN = n
}

func (s *runStats) sendpageObserved() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendpageObservedN
}

func (s *runStats) setIoUringSetupObserved(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ioUringSetupObservedN = n
}

func (s *runStats) addIoUringSend() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ioUringSendN++
}

func (s *runStats) ioUringSendTotal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ioUringSendN
}

// addIoUringTLSSNI records a distinct SNI hostname parsed from an io_uring
// ClientHello capture (P6 Phase 2.5). Idempotent per hostname.
func (s *runStats) addIoUringTLSSNI(sni string) {
	if sni == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ioUringTLSSNISet == nil {
		s.ioUringTLSSNISet = make(map[string]struct{})
	}
	s.ioUringTLSSNISet[sni] = struct{}{}
}

// ioUringTLSSNIList returns the distinct io_uring TLS SNIs, sorted. Empty when
// none were observed (the digest row is then hidden).
func (s *runStats) ioUringTLSSNIList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ioUringTLSSNISet) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.ioUringTLSSNISet))
	for sni := range s.ioUringTLSSNISet {
		out = append(out, sni)
	}
	slices.Sort(out)
	return out
}

func (s *runStats) ioUringTLSHelloObserved() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ioUringTLSHelloN
}

func (s *runStats) setIoUringTLSHelloObserved(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ioUringTLSHelloN = n
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

func (s *runStats) ioUringSetupObserved() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ioUringSetupObservedN
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

// addQUICCandidate bumps the per-run counter for UDP/443 non-loopback egress
// classified as a likely QUIC/HTTP3 flow (payload not inspected). See
// IsQUICCandidate for the predicate.
func (s *runStats) addQUICCandidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quicCandidateN++
}

func (s *runStats) quicCandidateTotal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.quicCandidateN
}

// addQUICObserved increments the per-run total of UDPEvent records whose
// PossibleQUIC flag was set (H19 — UDP destination port 443). This is the
// counter surfaced as CoverageReport.QuicObserved. It is a heuristic only:
// QUIC payloads are encrypted and never inspected, so a non-zero value just
// quantifies the UDP/443 visibility gap, not a confirmed QUIC flow count.
func (s *runStats) addQUICObserved() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quicObservedN++
}

func (s *runStats) quicObservedTotal() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.quicObservedN
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

// addTCPState records a kernel-confirmed TCP state transition (P3-2b).
// confirmed=true when newstate is ESTABLISHED; refused=true when newstate
// is CLOSE (RST / unreachable / timeout). The two are mutually exclusive
// because the BPF program filters to oldstate == SYN_SENT.
func (s *runStats) addTCPState(confirmed, refused bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpStateN++
	if confirmed {
		s.tcpStateConfirmed++
	}
	if refused {
		s.tcpStateRefused++
	}
}

func (s *runStats) tcpStateTotals() (total, confirmed, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcpStateN, s.tcpStateConfirmed, s.tcpStateRefused
}

func (s *runStats) setTCPStateRingbufReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpStateRingbufReserveFailuresN = n
}

func (s *runStats) tcpStateRingbufReserveFailures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcpStateRingbufReserveFailuresN
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
		KTLSOffloadEvents:              s.ktlsN,
		KTLSRingbufReserveFailures:     s.ktlsRingbufReserveFailuresN,
		TLSConfidenceFull:              s.tlsConfidenceFullN,
		TLSConfidencePartial:           s.tlsConfidencePartialN,
		TLSConfidenceInferred:          s.tlsConfidenceInferredN,
		TLSConfidenceUnknown:           s.tlsConfidenceUnknownN,
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
		SendmmsgUnobservedExtra:        s.sendmmsgUnobservedExtraN,
		TLSWritevMultiIovecObserved:    s.tlsWritevMultiIovecObservedN,
		SendfileObserved:               s.sendfileObservedN,
		SpliceObserved:                 s.spliceObservedN,
		SendmmsgFirstOnly:              s.sendmmsgFirstOnlyN,
		IPv6ConnectObserved:            s.ipv6ConnectObservedN,
		IPv6SendmsgObserved:            s.ipv6SendmsgObservedN,
		IPv6Events:                     s.ipv6EventCountN,
		IPv6RingbufReserveFailures:     s.ipv6RingbufReserveFailuresN,
		SendpageObserved:               s.sendpageObservedN,
		IoUringSetupObserved:           s.ioUringSetupObservedN,
		IoUringSendTotal:               s.ioUringSendN,
		IoUringRingbufReserveFailures:  s.ioUringRingbufReserveFailuresN,
		IoUringTLSHelloObserved:        s.ioUringTLSHelloN,
		TCPDNSResponsesObserved:        s.tcpDNSResponsesObservedN,
		TCPDNSSkippedShortRead:         s.tcpDNSSkippedShortReadN,
		TCPStateTotal:                  s.tcpStateN,
		TCPStateConfirmed:              s.tcpStateConfirmed,
		TCPStateRefused:                s.tcpStateRefused,
		TCPStateRingbufReserveFailures: s.tcpStateRingbufReserveFailuresN,
		QuicObserved:                   s.quicObservedN,
		DNSDriftObservations:           s.dnsDriftN,
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

// setAllowlistCompileSnapshot records a one-shot snapshot of the resolved
// allowlist at agent startup. Inputs are copied so the caller can free the
// originals. Used by the shutdown digest to surface unresolved domains, the
// IPv4-count snapshot, the wildcard-risk list, the age-since-compile note,
// and (P1-1 6e) the full allowlist domain list for the per-domain contact
// cross-reference.
func (s *runStats) setAllowlistCompileSnapshot(t time.Time, ipCount int, domains, unresolved, wildcardRisk []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowlistCompileTime = t
	s.allowlistIPCount = ipCount
	s.allowlistDomains = slices.Clone(domains)
	s.allowlistUnresolvedDomains = slices.Clone(unresolved)
	s.allowlistWildcardRiskDomains = slices.Clone(wildcardRisk)
}

// allowlistSnapshot returns a copy of the recorded compile-time snapshot.
func (s *runStats) allowlistSnapshot() (compileTime time.Time, ipCount int, domains, unresolved, wildcardRisk []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowlistCompileTime, s.allowlistIPCount,
		slices.Clone(s.allowlistDomains),
		slices.Clone(s.allowlistUnresolvedDomains),
		slices.Clone(s.allowlistWildcardRiskDomains)
}

// addDNSDrift bumps the H16 drift-observation counter. Called by the
// background re-resolution goroutine's onDrift closure.
func (s *runStats) addDNSDrift() {
	s.mu.Lock()
	s.dnsDriftN++
	s.mu.Unlock()
}

// dnsDriftTotal returns the count of distinct drift observations during the
// run. Zero when DNS was stable or re-resolution never fired.
func (s *runStats) dnsDriftTotal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dnsDriftN
}

// incDomainCount bumps the per-FQDN observation counter (P1-1 6e). No-op for
// empty domain.
func (s *runStats) incDomainCount(domain string) {
	if domain == "" {
		return
	}
	s.mu.Lock()
	if s.dstDomainCounts == nil {
		s.dstDomainCounts = make(map[string]int)
	}
	s.dstDomainCounts[domain]++
	s.mu.Unlock()
}

// snapshotDomainCounts returns a copy of the per-FQDN observation counters.
func (s *runStats) snapshotDomainCounts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.dstDomainCounts) == 0 {
		return nil
	}
	out := make(map[string]int, len(s.dstDomainCounts))
	for k, v := range s.dstDomainCounts {
		out[k] = v
	}
	return out
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
