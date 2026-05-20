//go:build linux

package agent

import (
	"slices"
	"sync"
	"time"

	"github.com/coldstep-io/coldstep/internal/proctree"
	"github.com/coldstep-io/coldstep/internal/report"
)

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

	tcpReadErrors        int
	tcpDecodeErrors      int
	udpReadErrors        int
	udpDecodeErrors      int
	httpReadErrors       int
	httpDecodeErrors     int
	tlsReadErrors        int
	tlsDecodeErrors      int
	tcpStateReadErrors   int
	tcpStateDecodeErrors int
}

type networkSectionSnapshot struct {
	tcpReadErrors        int
	tcpDecodeErrors      int
	udpReadErrors        int
	udpDecodeErrors      int
	httpReadErrors       int
	httpDecodeErrors     int
	tlsReadErrors        int
	tlsDecodeErrors      int
	tcpStateReadErrors   int
	tcpStateDecodeErrors int
}

const (
	denyProtoTCP                = 1
	denyProtoUDP                = 2
	denyReasonDstNotAllowlisted = 1
	linuxAFInet                 = 2
	linuxAFInet6                = 10

	// BPF↔Go wire-format size contract. Each constant is paired with a
	// `_Static_assert(sizeof(struct X) == N)` in the matching bpf/*.c file
	// so that any drift on either side fails compilation immediately.
	// Values were determined empirically (clang -target bpf, sizeof()).
	connectEventWireSize   = 32  // 4+4+16+4+2 fields, aligned to 4 → 32
	udpSendEventWireSize   = 36  // 4+4+16+4+2+_pad[2]+4 datagram_len → 36
	httpSniffEventWireSize = 228 // 4+4+16+4+2+_pad[2]+2+payload[192] → 228
	// tlsSniffEventWireSize: legacy v4 header(34) + payload[256] + ipv6 trailer(20) → 312.
	// IPv6 trailer = daddr6[16] + is_ipv6(1) + _pad_v6[3]. Layout chosen so the
	// IPv4 bytes (offsets 0..289) stay byte-identical to the pre-P5 wire format.
	tlsSniffEventWireSize = 312
	execEventWireSize     = 280 // 4+4+16+exe_path[256] → 280
	forkEventWireSize     = 48  // 4+4+parent_comm[16]+child_comm[16]+4(sid)+4(pidns) → 48
	fsEventWireSize       = 284 // 4+4+16+1+path[256]+_pad[3] → 284
	denyEventWireSize     = 46  // packed: 4+4+16+1+1+1+_pad+daddr[16]+dport[2] → 46
	bpfAuditEventWireSize = 28  // 4(tgid)+4(tid)+4(cmd)+comm[16] → 28
	ktlsEventWireSize     = 32  // 4(tgid)+4(tid)+comm[16]+4(fd)+1(direction)+_pad[3] → 32
	// tcp_state_event (P3-2b): 8(timestamp_ns)+4(pid)+4(saddr)+4(daddr)+2(sport)+2(dport)+4(old_state)+4(new_state)+16(comm) → 48
	tcpStateEventWireSize = 48
	// trace_dns.bpf.c dns_sniff_event: __u32 len + __u8 is_tcp + __u8 _pad[3] + data[DNS_SNIFF_MAX]
	dnsSniffMaxPayload          = 4096                   // DNS_SNIFF_MAX in trace_dns.bpf.c
	dnsSniffEventWireSizeLegacy = 4 + dnsSniffMaxPayload // pre-is_tcp layout (__u32 len + data[])
	dnsSniffEventWireSize       = 4 + 1 + 3 + dnsSniffMaxPayload

	// Header-only sub-sizes used by the http/tls capture decoders to slice
	// out the payload window. Pair these with the respective WireSize above.
	httpSniffEventHeaderSize = 34 // 4+4+16+4+2+_pad[2]+2 capture_len
	tlsSniffEventHeaderSize  = 34 // same layout
	// Offset of the IPv6 trailer (daddr6[16] + is_ipv6 + _pad_v6[3]) inside a
	// tls_sniff_event. Equals tlsSniffEventHeaderSize + tlsPayloadMax.
	tlsSniffEventIPv6Offset = tlsSniffEventHeaderSize + tlsPayloadMax

	// After the first defend deny, read additional deny ringbuf records briefly so JSONL/digest
	// capture a burst (e.g. TCP + UDP) before fail-fast shutdown.
	defendDenyDrainMaxEvents = 32
	defendDenyDrainDuration  = 1200 * time.Millisecond
	defendDenyDrainReadSlice = 50 * time.Millisecond

	// Canary constants matching struct canary_event in trace_connect.bpf.c.
	canaryMagic         uint32 = 0xCA1A1210
	canaryEventWireSize        = 16 // 4 magic + 4 pad + 8 seq_nr
	canaryInterval             = 10 * time.Second
	canaryTimeout              = 30 * time.Second

	// P3-2: connect_result_event constants matching struct connect_result_event
	// in bpf/trace_tcp_connect_kprobe.inc. Sharing the connect_events ringbuf
	// with connect_event; magic at offset 0 distinguishes the two. Real PIDs
	// are bounded by PID_MAX_LIMIT (4194304) so the magic cannot collide with
	// a connect_event's leading tgid field. Both constants carry explicit
	// types so staticcheck SA9004 sees a consistent typing pattern.
	connectResultMagic         uint32 = 0xC0EE0001
	connectResultEventWireSize int    = 32 // 4 magic + 4 result + 4 tgid + 4 tid + comm[16]

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

func (s *networkSectionState) addTCPStateReaderError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpStateReadErrors++
}

func (s *networkSectionState) addTCPStateDecodeError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpStateDecodeErrors++
}

func (s *networkSectionState) snapshot() networkSectionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return networkSectionSnapshot{
		tcpReadErrors:        s.tcpReadErrors,
		tcpDecodeErrors:      s.tcpDecodeErrors,
		udpReadErrors:        s.udpReadErrors,
		udpDecodeErrors:      s.udpDecodeErrors,
		httpReadErrors:       s.httpReadErrors,
		httpDecodeErrors:     s.httpDecodeErrors,
		tlsReadErrors:        s.tlsReadErrors,
		tlsDecodeErrors:      s.tlsDecodeErrors,
		tcpStateReadErrors:   s.tcpStateReadErrors,
		tcpStateDecodeErrors: s.tcpStateDecodeErrors,
	}
}
