//go:build linux

package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/proctree"
	"github.com/coldstep-io/coldstep/internal/report"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

type runStats struct {
	mu                              sync.Mutex
	execN                           int
	tcpN                            int
	udpN                            int
	httpN                           int
	tlsN                            int
	procForkN                       int
	fsN                             int
	connect4TupleUpdateFailuresN    int
	udpRingbufReserveFailuresN      int
	dnsRingbufReserveFailuresN      int
	connectRingbufReserveFailuresN  int
	httpRingbufReserveFailuresN     int
	tlsRingbufReserveFailuresN      int
	execRingbufReserveFailuresN     int
	forkRingbufReserveFailuresN     int
	fsRingbufReserveFailuresN       int
	udpSendmsgMultiIovecObservedN   int
	tlsWritevMultiIovecObservedN    int
	unobservedEgressSyscallsN       int
	ioUringSetupObservedN           int
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

type forkSectionState struct {
	mu         sync.Mutex
	readErrors int
}

func newForkSectionState() *forkSectionState {
	return &forkSectionState{}
}

func (s *forkSectionState) addReadError() {
	s.mu.Lock()
	s.readErrors++
	s.mu.Unlock()
}

type forkSectionSnapshot struct {
	readErrors int
}

func (s *forkSectionState) snapshot() forkSectionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return forkSectionSnapshot{readErrors: s.readErrors}
}

type fsSectionState struct {
	mu         sync.Mutex
	readErrors int
}

func newFSSectionState() *fsSectionState { return &fsSectionState{} }

func (s *fsSectionState) addReadError() {
	s.mu.Lock()
	s.readErrors++
	s.mu.Unlock()
}

type fsSectionSnapshot struct {
	readErrors int
}

func (s *fsSectionState) snapshot() fsSectionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fsSectionSnapshot{readErrors: s.readErrors}
}

type fsRowBuffer struct {
	mu   sync.Mutex
	max  int
	rows []report.FSDigestRow
}

func newFSRowBuffer(max int) *fsRowBuffer { return &fsRowBuffer{max: max} }

func (b *fsRowBuffer) add(r report.FSDigestRow) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rows = append(b.rows, r)
	_ = trimRing(&b.rows, b.max) // overflow already accounted for via fs_cap counter in readFSRing.
}

func (b *fsRowBuffer) snapshot() []report.FSDigestRow {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]report.FSDigestRow, len(b.rows))
	copy(cp, b.rows)
	return cp
}

type forkEdgeBuffer struct {
	mu        sync.Mutex
	max       int
	totalAdds int
	edges     []proctree.Edge
}

func newForkEdgeBuffer(max int) *forkEdgeBuffer {
	return &forkEdgeBuffer{max: max}
}

func (b *forkEdgeBuffer) add(e proctree.Edge) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.totalAdds++
	b.edges = append(b.edges, e)
	_ = trimRing(&b.edges, b.max) // overflow surfaced via forkEdgeBuffer.snapshot() truncation flag.
}

func (b *forkEdgeBuffer) snapshot() ([]proctree.Edge, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.edges), b.max > 0 && b.totalAdds > b.max
}

type networkSectionState struct {
	mu sync.Mutex

	tcpReadErrors    int
	tcpDecodeErrors  int
	udpReadErrors    int
	udpDecodeErrors  int
	httpReadErrors   int
	httpDecodeErrors int
	tlsReadErrors    int
	tlsDecodeErrors  int
}

type networkSectionSnapshot struct {
	tcpReadErrors    int
	tcpDecodeErrors  int
	udpReadErrors    int
	udpDecodeErrors  int
	httpReadErrors   int
	httpDecodeErrors int
	tlsReadErrors    int
	tlsDecodeErrors  int
}

const (
	denyProtoTCP                = 1
	denyProtoUDP                = 2
	denyReasonDstNotAllowlisted = 1
	linuxAFInet                 = 2

	// BPF↔Go wire-format size contract. Each constant is paired with a
	// `_Static_assert(sizeof(struct X) == N)` in the matching bpf/*.c file
	// so that any drift on either side fails compilation immediately.
	// Values were determined empirically (clang -target bpf, sizeof()).
	connectEventWireSize   = 32  // 4+4+16+4+2 fields, aligned to 4 → 32
	udpSendEventWireSize   = 36  // 4+4+16+4+2+_pad[2]+4 datagram_len → 36
	httpSniffEventWireSize = 228 // 4+4+16+4+2+_pad[2]+2+payload[192] → 228
	tlsSniffEventWireSize  = 292 // 4+4+16+4+2+_pad[2]+2+payload[256] → 292
	execEventWireSize      = 280 // 4+4+16+exe_path[256] → 280
	forkEventWireSize      = 48  // 4+4+parent_comm[16]+child_comm[16]+4(sid)+4(pidns) → 48
	fsEventWireSize        = 284 // 4+4+16+1+path[256]+_pad[3] → 284
	denyEventWireSize      = 46  // packed: 4+4+16+1+1+1+_pad+daddr[16]+dport[2] → 46
	bpfAuditEventWireSize  = 28  // 4(tgid)+4(tid)+4(cmd)+comm[16] → 28
	// trace_dns.bpf.c dns_sniff_event: __u32 len + __u8 is_tcp + __u8 _pad[3] + data[DNS_SNIFF_MAX]
	dnsSniffMaxPayload          = 4096                   // DNS_SNIFF_MAX in trace_dns.bpf.c
	dnsSniffEventWireSizeLegacy = 4 + dnsSniffMaxPayload // pre-is_tcp layout (__u32 len + data[])
	dnsSniffEventWireSize       = 4 + 1 + 3 + dnsSniffMaxPayload

	// Header-only sub-sizes used by the http/tls capture decoders to slice
	// out the payload window. Pair these with the respective WireSize above.
	httpSniffEventHeaderSize = 34 // 4+4+16+4+2+_pad[2]+2 capture_len
	tlsSniffEventHeaderSize  = 34 // same layout

	// After the first enforce deny, read additional deny ringbuf records briefly so JSONL/digest
	// capture a burst (e.g. TCP + UDP) before fail-fast shutdown.
	enforceDenyDrainMaxEvents = 32
	enforceDenyDrainDuration  = 1200 * time.Millisecond
	enforceDenyDrainReadSlice = 50 * time.Millisecond

	// Canary constants matching struct canary_event in trace_connect.bpf.c.
	canaryMagic         uint32 = 0xCA1A1210
	canaryEventWireSize        = 16 // 4 magic + 4 pad + 8 seq_nr
	canaryInterval             = 10 * time.Second
	canaryTimeout              = 30 * time.Second

	ringReadRetryBaseDelay = 5 * time.Millisecond
	ringReadRetryMaxDelay  = 200 * time.Millisecond
)

type ringReadRetryBackoff struct {
	current time.Duration
	sleepFn func(time.Duration)
}

func newRingReadRetryBackoff() *ringReadRetryBackoff {
	return &ringReadRetryBackoff{sleepFn: time.Sleep}
}

func (b *ringReadRetryBackoff) nextDelay() time.Duration {
	if b.current <= 0 {
		b.current = ringReadRetryBaseDelay
		return b.current
	}
	next := b.current * 2
	if next > ringReadRetryMaxDelay {
		next = ringReadRetryMaxDelay
	}
	b.current = next
	return b.current
}

func (b *ringReadRetryBackoff) sleep() time.Duration {
	delay := b.nextDelay()
	if delay <= 0 {
		return 0
	}
	b.sleepFn(delay)
	return delay
}

func (b *ringReadRetryBackoff) reset() {
	b.current = 0
}

// canaryState tracks telemetry integrity canaries across the BPF
// ringbuf pipeline. Userspace arms a sequence via the canary_trigger
// BPF map; the BPF program emits a canary_event into connect_events;
// the ringbuf reader calls noteReceived. If a canary doesn't arrive
// within canaryTimeout, the pipeline is considered compromised.
type canaryState struct {
	mu           sync.Mutex
	lastSent     uint64
	lastSentAt   time.Time
	lastReceived uint64
	lastRecvAt   time.Time
	failCount    int
}

func newCanaryState() *canaryState { return &canaryState{} }

func (c *canaryState) noteSent(seq uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastSent = seq
	c.lastSentAt = time.Now()
}

func (c *canaryState) noteReceived(seq uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastReceived = seq
	c.lastRecvAt = time.Now()
}

type canarySnapshot struct {
	lastSent       uint64
	lastReceived   uint64
	failCount      int
	pipelineOK     bool
	lastSentAt     time.Time
	lastReceivedAt time.Time
}

func (c *canaryState) snapshot() canarySnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	ok := true
	if c.lastSent > 0 && c.lastReceived < c.lastSent &&
		time.Since(c.lastSentAt) > canaryTimeout {
		ok = false
	}
	return canarySnapshot{
		lastSent:       c.lastSent,
		lastReceived:   c.lastReceived,
		failCount:      c.failCount,
		pipelineOK:     ok,
		lastSentAt:     c.lastSentAt,
		lastReceivedAt: c.lastRecvAt,
	}
}

func (c *canaryState) checkAndRecordFailure() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastSent > 0 && c.lastReceived < c.lastSent &&
		time.Since(c.lastSentAt) > canaryTimeout {
		c.failCount++
		return true
	}
	return false
}

type enforcementState struct {
	mu                     sync.Mutex
	mode                   string
	allowlistSize          int
	denyCountN             int
	denyReserveFailuresN   int
	mapIntegrityFailures   int
	expectedEntries        int
	expectedIgnoredEntries int
	firstDenyRowV          *report.DenyDigestRow
}

type enforcementSnapshot struct {
	mode                 string
	allowlistSize        int
	denyCount            int
	denyReserveFailures  int
	mapIntegrityFailures int
	firstDeny            *report.DenyDigestRow
}

type enforceBackendConfig struct {
	modeEnforce bool
	haveLSM     bool
}

type enforceBackendOutcome struct {
	backend string
}

const (
	enforceBackendDetect = "detect"
	enforceBackendLSM    = "lsm"
	enforceBackendCgroup = "cgroup"

	enforceModeLSM    = "enforce+lsm"
	enforceModeCgroup = "enforce+cgroup"
)

func chooseEnforceBackend(cfg enforceBackendConfig, lsmAttachErr error) enforceBackendOutcome {
	if !cfg.modeEnforce {
		return enforceBackendOutcome{backend: enforceBackendDetect}
	}
	if cfg.haveLSM && lsmAttachErr == nil {
		return enforceBackendOutcome{backend: enforceBackendLSM}
	}
	return enforceBackendOutcome{backend: enforceBackendCgroup}
}

func enforceModeForBackend(backend string) string {
	if backend == enforceBackendLSM {
		return enforceModeLSM
	}
	return enforceModeCgroup
}

type enforceDenyError struct {
	protocol string
	dst      string
	dport    uint16
	reason   string
}

func (e enforceDenyError) Error() string {
	return fmt.Sprintf("enforce deny: protocol=%s dst=%s dport=%d reason=%s", e.protocol, e.dst, e.dport, e.reason)
}

func newEnforceDenyError(ev telemetry.DenyEvent) error {
	return enforceDenyError{
		protocol: ev.Protocol,
		dst:      ev.Dst,
		dport:    ev.Dport,
		reason:   ev.Reason,
	}
}

func isEnforceDenyError(err error) bool {
	var e enforceDenyError
	return errors.As(err, &e)
}

func newEnforcementState() *enforcementState {
	return &enforcementState{}
}

func (s *enforcementState) setModeAndAllowlist(mode string, allowlistSize, ignoredSize int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
	s.allowlistSize = allowlistSize
	s.expectedEntries = allowlistSize
	s.expectedIgnoredEntries = ignoredSize
}

func (s *enforcementState) addMapIntegrityFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mapIntegrityFailures++
}

func (s *enforcementState) mapIntegrityFailureCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mapIntegrityFailures
}

func (s *enforcementState) noteDeny(row report.DenyDigestRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denyCountN++
	if s.firstDenyRowV == nil {
		cp := row
		s.firstDenyRowV = &cp
	}
}

func (s *enforcementState) denyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.denyCountN
}

func (s *enforcementState) firstDeny() *report.DenyDigestRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.firstDenyRowV == nil {
		return nil
	}
	cp := *s.firstDenyRowV
	return &cp
}

func (s *enforcementState) snapshot() enforcementSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := enforcementSnapshot{
		mode:                 s.mode,
		allowlistSize:        s.allowlistSize,
		denyCount:            s.denyCountN,
		denyReserveFailures:  s.denyReserveFailuresN,
		mapIntegrityFailures: s.mapIntegrityFailures,
	}
	if s.firstDenyRowV != nil {
		cp := *s.firstDenyRowV
		out.firstDeny = &cp
	}
	return out
}

func (s *enforcementState) setDenyReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denyReserveFailuresN = n
}

func newNetworkSectionState() *networkSectionState {
	return &networkSectionState{}
}

func (s *networkSectionState) addTCPReaderError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpReadErrors++
}

func (s *networkSectionState) addTCPDecodeError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpDecodeErrors++
}

func (s *networkSectionState) addUDPReaderError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpReadErrors++
}

func (s *networkSectionState) addUDPDecodeError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpDecodeErrors++
}

func (s *networkSectionState) addHTTPReaderError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.httpReadErrors++
}

func (s *networkSectionState) addHTTPDecodeError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.httpDecodeErrors++
}

func (s *networkSectionState) addTLSReaderError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsReadErrors++
}

func (s *networkSectionState) addTLSDecodeError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsDecodeErrors++
}

func (s *networkSectionState) snapshot() networkSectionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return networkSectionSnapshot{
		tcpReadErrors:    s.tcpReadErrors,
		tcpDecodeErrors:  s.tcpDecodeErrors,
		udpReadErrors:    s.udpReadErrors,
		udpDecodeErrors:  s.udpDecodeErrors,
		httpReadErrors:   s.httpReadErrors,
		httpDecodeErrors: s.httpDecodeErrors,
		tlsReadErrors:    s.tlsReadErrors,
		tlsDecodeErrors:  s.tlsDecodeErrors,
	}
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

func (s *runStats) setUnobservedEgressSyscalls(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unobservedEgressSyscallsN = n
}

func (s *runStats) unobservedEgressSyscalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unobservedEgressSyscallsN
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
		TLSWritevMultiIovecObserved:    s.tlsWritevMultiIovecObservedN,
		UnobservedEgressSyscalls:       s.unobservedEgressSyscallsN,
		IoUringSetupObserved:           s.ioUringSetupObservedN,
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
