//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/coldstep-io/coldstep/internal/bpf/traceconnect"
	"github.com/coldstep-io/coldstep/internal/bpf/tracedns"
	"github.com/coldstep-io/coldstep/internal/bpf/traceenforce"
	"github.com/coldstep-io/coldstep/internal/bpf/traceexec"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefork"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefs"
	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/proctree"
	"github.com/coldstep-io/coldstep/internal/report"
	"github.com/coldstep-io/coldstep/internal/telemetry"
	"golang.org/x/sys/unix"
)

type execEvent struct {
	TGID    uint32
	TID     uint32
	Comm    [16]byte
	ExePath [256]byte
}

type runStats struct {
	mu                           sync.Mutex
	execN                        int
	tcpN                         int
	udpN                         int
	httpN                        int
	tlsN                         int
	procForkN                    int
	fsN                          int
	connect4TupleUpdateFailuresN int
	udpRingbufReserveFailuresN   int
	dnsRingbufReserveFailuresN   int
	policyCounts                 map[string]int
	droppedCounts                map[string]int
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
	trimRing(&b.rows, b.max)
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
	trimRing(&b.edges, b.max)
}

func (b *forkEdgeBuffer) snapshot() ([]proctree.Edge, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.edges), b.max > 0 && b.totalAdds > b.max
}

type networkSectionState struct {
	mu sync.Mutex

	udpReadErrors    int
	udpDecodeErrors  int
	httpReadErrors   int
	httpDecodeErrors int
	tlsReadErrors    int
	tlsDecodeErrors  int
}

type networkSectionSnapshot struct {
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
	denyEventWireSize           = 46 // bpf deny_event packed: af + daddr[16]
	linuxAFInet                 = 2
	linuxAFInet6                = 10

	// After the first enforce deny, read additional deny ringbuf records briefly so JSONL/digest
	// capture a burst (e.g. TCP + UDP) before fail-fast shutdown.
	enforceDenyDrainMaxEvents = 32
	enforceDenyDrainDuration  = 1200 * time.Millisecond
	enforceDenyDrainReadSlice = 50 * time.Millisecond
)

type enforcementState struct {
	mu                   sync.Mutex
	mode                 string
	allowlistSize        int
	denyCountN           int
	denyReserveFailuresN int
	firstDenyRowV        *report.DenyDigestRow
}

type enforcementSnapshot struct {
	mode                string
	allowlistSize       int
	denyCount           int
	denyReserveFailures int
	firstDeny           *report.DenyDigestRow
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

func (s *enforcementState) setModeAndAllowlist(mode string, allowlistSize int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
	s.allowlistSize = allowlistSize
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

func (s *enforcementState) denyCountValue() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.denyCountN
}

func (s *enforcementState) denyCount() int {
	return s.denyCountValue()
}

func (s *enforcementState) firstDenyRow() *report.DenyDigestRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.firstDenyRowV == nil {
		return nil
	}
	cp := *s.firstDenyRowV
	return &cp
}

func (s *enforcementState) firstDeny() *report.DenyDigestRow {
	return s.firstDenyRow()
}

func (s *enforcementState) snapshot() enforcementSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := enforcementSnapshot{
		mode:                s.mode,
		allowlistSize:       s.allowlistSize,
		denyCount:           s.denyCountN,
		denyReserveFailures: s.denyReserveFailuresN,
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
	return telemetry.Summary{
		Version:                     2,
		SchemaVersion:               telemetry.SchemaVersion,
		ExecEvents:                  s.execN,
		TCPEvents:                   s.tcpN,
		UDPEvents:                   s.udpN,
		HTTPEvents:                  s.httpN,
		TLSEvents:                   s.tlsN,
		ProcForkEvents:              s.procForkN,
		Connect4TupleUpdateFailures: s.connect4TupleUpdateFailuresN,
		UDPRingbufReserveFailures:   s.udpRingbufReserveFailuresN,
		DNSRingbufReserveFailures:   s.dnsRingbufReserveFailuresN,
		DroppedCounts:               dropped,
		PolicyCounts:                pc,
		KernelRelease:               kernel,
		BPF:                         bpf,
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

func trimRing[T any](s *[]T, max int) {
	if max <= 0 || len(*s) <= max {
		return
	}
	*s = (*s)[len(*s)-max:]
}

func (b *rowBuffer) addExec(r report.ExecDigestRow) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.exec = append(b.exec, r)
	trimRing(&b.exec, b.max)
}

func (b *rowBuffer) addTCP(r report.TCPDigestRow) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tcp = append(b.tcp, r)
	trimRing(&b.tcp, b.max)
}

func (b *rowBuffer) addUDP(r report.UDPDigestRow) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.udp = append(b.udp, r)
	trimRing(&b.udp, b.max)
}

func (b *rowBuffer) addHTTP(r report.HTTPDigestRow) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.http = append(b.http, r)
	trimRing(&b.http, b.max)
}

func (b *rowBuffer) addTLS(r report.TLSDigestRow) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tls = append(b.tls, r)
	trimRing(&b.tls, b.max)
}

func (b *rowBuffer) snapshot() (exec []report.ExecDigestRow, tcp []report.TCPDigestRow, udp []report.UDPDigestRow, http []report.HTTPDigestRow, tls []report.TLSDigestRow) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.exec), slices.Clone(b.tcp), slices.Clone(b.udp), slices.Clone(b.http), slices.Clone(b.tls)
}

func setupLogging(level string) {
	lvl := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(h))
}

func writeAgentStatus(path string, ok bool) error {
	if path == "" {
		return nil
	}
	payload := map[string]any{"ok": ok, "version": 1}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func agentVersionString() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	v := strings.TrimSpace(bi.Main.Version)
	if v == "" || v == "(devel)" {
		return "devel"
	}
	return v
}

func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}

// decodeConnectEvent parses trace_connect.bpf.c connect_event (tgid, tid, comm, daddr, dport).
func decodeConnectEvent(raw []byte) (tgid, tid uint32, comm [16]byte, daddr [4]byte, dport uint16, ok bool) {
	const sample = 4 + 4 + 16 + 4 + 2
	if len(raw) < sample {
		return 0, 0, [16]byte{}, [4]byte{}, 0, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	copy(comm[:], raw[8:24])
	copy(daddr[:], raw[24:28])
	dport = binary.BigEndian.Uint16(raw[28:30])
	return tgid, tid, comm, daddr, dport, true
}

// decodeUDPSendEvent parses udp_send_event.
func decodeUDPSendEvent(raw []byte) (tgid, tid uint32, comm [16]byte, daddr [4]byte, dport uint16, dgramLen uint32, ok bool) {
	const sample = 4 + 4 + 16 + 4 + 2 + 4
	if len(raw) < sample {
		return 0, 0, [16]byte{}, [4]byte{}, 0, 0, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	copy(comm[:], raw[8:24])
	copy(daddr[:], raw[24:28])
	dport = binary.BigEndian.Uint16(raw[28:30])
	dgramLen = binary.LittleEndian.Uint32(raw[30:34])
	return tgid, tid, comm, daddr, dport, dgramLen, true
}

// decodeHTTPSniffEvent parses http_sniff_event (226 bytes with HTTP_PAYLOAD_MAX=192).
func decodeHTTPSniffEvent(raw []byte) (tgid, tid uint32, comm [16]byte, daddr [4]byte, dport uint16, payload []byte, ok bool) {
	const header = 4 + 4 + 16 + 4 + 2 + 2 + 2 // tgid, tid, comm, daddr, dport, pad, capture_len
	const expect = header + 192
	if len(raw) < expect {
		return 0, 0, [16]byte{}, [4]byte{}, 0, nil, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	copy(comm[:], raw[8:24])
	copy(daddr[:], raw[24:28])
	dport = binary.BigEndian.Uint16(raw[28:30])
	capLen := int(binary.LittleEndian.Uint16(raw[32:34]))
	if capLen < 0 || capLen > 192 {
		return 0, 0, [16]byte{}, [4]byte{}, 0, nil, false
	}
	payload = make([]byte, capLen)
	copy(payload, raw[34:34+capLen])
	return tgid, tid, comm, daddr, dport, payload, true
}

const tlsPayloadMax = 256

// decodeTLSSniffEvent parses tls_sniff_event (same wire layout as http_sniff_event with TLS_PAYLOAD_MAX).
func decodeTLSSniffEvent(raw []byte) (tgid, tid uint32, comm [16]byte, daddr [4]byte, dport uint16, payload []byte, ok bool) {
	const header = 4 + 4 + 16 + 4 + 2 + 2 + 2
	const expect = header + tlsPayloadMax
	if len(raw) < expect {
		return 0, 0, [16]byte{}, [4]byte{}, 0, nil, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	copy(comm[:], raw[8:24])
	copy(daddr[:], raw[24:28])
	dport = binary.BigEndian.Uint16(raw[28:30])
	capLen := int(binary.LittleEndian.Uint16(raw[32:34]))
	if capLen < 0 || capLen > tlsPayloadMax {
		return 0, 0, [16]byte{}, [4]byte{}, 0, nil, false
	}
	payload = make([]byte, capLen)
	copy(payload, raw[34:34+capLen])
	return tgid, tid, comm, daddr, dport, payload, true
}

// decodeDNSSniffSample parses trace_dns.bpf.c ringbuf payload (__u32 len + data[len]).
func decodeDNSSniffSample(raw []byte) ([]byte, bool) {
	if len(raw) < 4 {
		return nil, false
	}
	n := binary.LittleEndian.Uint32(raw[0:4])
	if n > 4096 || int(n)+4 > len(raw) {
		return nil, false
	}
	return raw[4 : 4+int(n)], true
}

func decodeDenyEvent(raw []byte) (tgid, tid uint32, comm [16]byte, protocol uint8, reason uint8, af uint8,
	daddr16 [16]byte, dport uint16, ok bool) {
	if len(raw) < denyEventWireSize {
		return 0, 0, [16]byte{}, 0, 0, 0, [16]byte{}, 0, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	copy(comm[:], raw[8:24])
	protocol = raw[24]
	reason = raw[25]
	af = raw[26]
	copy(daddr16[:], raw[28:44])
	dport = binary.BigEndian.Uint16(raw[44:46])
	return tgid, tid, comm, protocol, reason, af, daddr16, dport, true
}

func denyProtocolLabel(protocol uint8) string {
	switch protocol {
	case denyProtoTCP:
		return "tcp"
	case denyProtoUDP:
		return "udp"
	default:
		return "unknown"
	}
}

func denyReasonLabel(reason uint8) string {
	switch reason {
	case denyReasonDstNotAllowlisted:
		return "dst_not_allowlisted"
	default:
		return "unknown"
	}
}

func denyDigestRowFromEvent(ev telemetry.DenyEvent) report.DenyDigestRow {
	return report.DenyDigestRow{
		TS:       ev.TS,
		PID:      ev.PID,
		Comm:     ev.Comm,
		Protocol: ev.Protocol,
		Dst:      ev.Dst,
		Dport:    ev.Dport,
		Reason:   ev.Reason,
	}
}

// startSyscallTrace loads observability-only BPF (TCP connect + UDP sendto + HTTP sniff + TLS write sniff; single raw_tp attach).
// cgroup enforcement loads separately (traceenforce) when mode is enforce.
// When enableTLSSNI is true, sets tls_agent_cfg map so BPF emits TLS ClientHello captures.
// tlsAgentCfgFailed is set when the map update fails (SNI path stays off in BPF) so callers can mark the hook degraded.
func startSyscallTrace(enableTLSSNI bool) (connRd, udpRd, httpRd, tlsRd *ringbuf.Reader, objs *traceconnect.TraceconnectObjects, lnk link.Link, tlsAgentCfgFailed bool, err error) {
	objs = new(traceconnect.TraceconnectObjects)
	traceLoadOpts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch | ebpf.LogLevelInstruction,
			LogSizeStart: 512 * 1024,
		},
	}
	if err = traceconnect.LoadTraceconnectObjects(objs, traceLoadOpts); err != nil {
		return nil, nil, nil, nil, nil, nil, false, err
	}

	lnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.HandleRawSysEnter,
	})
	if err != nil {
		objs.Close()
		return nil, nil, nil, nil, nil, nil, false, err
	}

	connRd, err = ringbuf.NewReader(objs.ConnectEvents)
	if err != nil {
		lnk.Close()
		objs.Close()
		return nil, nil, nil, nil, nil, nil, false, err
	}
	udpRd, err = ringbuf.NewReader(objs.UdpEvents)
	if err != nil {
		connRd.Close()
		lnk.Close()
		objs.Close()
		return nil, nil, nil, nil, nil, nil, false, err
	}
	httpRd, err = ringbuf.NewReader(objs.HttpEvents)
	if err != nil {
		udpRd.Close()
		connRd.Close()
		lnk.Close()
		objs.Close()
		return nil, nil, nil, nil, nil, nil, false, err
	}
	tlsRd, err = ringbuf.NewReader(objs.TlsEvents)
	if err != nil {
		httpRd.Close()
		udpRd.Close()
		connRd.Close()
		lnk.Close()
		objs.Close()
		return nil, nil, nil, nil, nil, nil, false, err
	}

	if enableTLSSNI {
		if uerr := objs.TlsAgentCfg.Update(uint32(0), uint8(1), ebpf.UpdateAny); uerr != nil {
			tlsAgentCfgFailed = true
			slog.Warn("tls_sni bpf cfg", "err", uerr)
		}
	}

	return connRd, udpRd, httpRd, tlsRd, objs, lnk, tlsAgentCfgFailed, nil
}

func startDNSTrace() (*ringbuf.Reader, *tracedns.TracednsObjects, link.Link, link.Link, error) {
	objs := new(tracedns.TracednsObjects)
	if err := tracedns.LoadTracednsObjects(objs, nil); err != nil {
		return nil, nil, nil, nil, err
	}

	lnkEnter, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.HandleRawSysEnterDns,
	})
	if err != nil {
		objs.Close()
		return nil, nil, nil, nil, err
	}

	lnkExit, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: objs.HandleRawSysExitDns,
	})
	if err != nil {
		lnkEnter.Close()
		objs.Close()
		return nil, nil, nil, nil, err
	}

	rd, err := ringbuf.NewReader(objs.DnsEvents)
	if err != nil {
		lnkExit.Close()
		lnkEnter.Close()
		objs.Close()
		return nil, nil, nil, nil, err
	}

	return rd, objs, lnkEnter, lnkExit, nil
}

func readExecRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	rows *rowBuffer, seq *telemetry.SeqGen, jsonlMu *sync.Mutex) error {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("ringbuf read (exec)", "err", err)
			continue
		}

		var ev execEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			stats.addDropped("exec_decode")
			slog.Warn("decode exec", "err", err)
			continue
		}

		comm := string(bytes.TrimRight(ev.Comm[:], "\x00"))
		exe := string(bytes.TrimRight(ev.ExePath[:], "\x00"))
		stats.addExec()
		ts := time.Now().UTC().Format(time.RFC3339Nano)
		rows.addExec(report.ExecDigestRow{
			TS: ts, PID: ev.TGID, ThreadID: ev.TID, Comm: comm,
			Exe: report.TruncateExeForDigest(exe),
		})

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			evOut := telemetry.ExecEvent{
				Type: "exec", TS: ts, Seq: n,
				PID: ev.TGID, TGID: ev.TGID, ThreadID: ev.TID, Comm: comm,
				Exe: exe,
			}
			err := telemetry.AppendJSONL(cfg.EventsLogPath, evOut)
			jsonlMu.Unlock()
			if err != nil {
				stats.addDropped("exec_jsonl")
				slog.Warn("events jsonl", "err", err)
			}
		}
	}
}

type forkEventWire struct {
	ParentPID  uint32
	ChildPID   uint32
	ParentComm [16]byte
	ChildComm  [16]byte
}

func readForkRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	forkBuf *forkEdgeBuffer, forkState *forkSectionState, seq *telemetry.SeqGen, jsonlMu *sync.Mutex) error {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("ringbuf read (fork)", "err", err)
			continue
		}

		var ev forkEventWire
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			forkState.addReadError()
			stats.addDropped("proc_fork_decode")
			slog.Warn("decode fork", "err", err)
			continue
		}

		pcomm := string(bytes.TrimRight(ev.ParentComm[:], "\x00"))
		ccomm := string(bytes.TrimRight(ev.ChildComm[:], "\x00"))
		forkBuf.add(proctree.Edge{
			ParentTGID: ev.ParentPID,
			ChildTGID:  ev.ChildPID,
			ParentComm: pcomm,
			ChildComm:  ccomm,
		})
		stats.addProcFork()
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			evOut := telemetry.ProcForkEvent{
				Type: "proc_fork", TS: ts, Seq: n,
				ParentPID: ev.ParentPID, ChildPID: ev.ChildPID,
				ParentComm: pcomm, ChildComm: ccomm,
				Note: "best-effort pid namespace; parent/child are kernel fork trace ids",
			}
			werr := telemetry.AppendJSONL(cfg.EventsLogPath, evOut)
			jsonlMu.Unlock()
			if werr != nil {
				stats.addDropped("proc_fork_jsonl")
				slog.Warn("events jsonl", "err", werr)
			}
		}
	}
}

func nullTermStr(b []byte) string {
	return string(bytes.TrimRight(b, "\x00"))
}

// fsOpName maps BPF op byte to JSONL op string.
func fsOpName(op uint8) string {
	switch op {
	case 1:
		return "create"
	case 2:
		return "unlink"
	case 3:
		return "rename"
	case 4:
		return "chmod"
	default:
		return "unknown"
	}
}

type fsEventWire struct {
	TGID uint32
	TID  uint32
	Comm [16]byte
	Op   uint8
	Path [256]byte
	Pad  [3]byte
}

const maxFSEventsTotal = 5000

func readFSRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	fsRows *fsRowBuffer, fsState *fsSectionState, seq *telemetry.SeqGen, jsonlMu *sync.Mutex) error {
	count := 0
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			fsState.addReadError()
			slog.Warn("ringbuf read (fs)", "err", err)
			continue
		}
		var ev fsEventWire
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			fsState.addReadError()
			stats.addDropped("fs_decode")
			slog.Warn("decode fs event", "err", err)
			continue
		}

		count++
		stats.addFS() // count all events even when rate-capped
		if count > maxFSEventsTotal {
			stats.addDropped("fs_cap")
			if count == maxFSEventsTotal+1 {
				slog.Warn("fs event cap reached; further events counted but not written to JSONL or rows", "cap", maxFSEventsTotal)
			}
			continue
		}

		comm := nullTermStr(ev.Comm[:])
		path := nullTermStr(ev.Path[:])
		op := fsOpName(ev.Op)
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		fsRows.add(report.FSDigestRow{
			TS:   ts,
			PID:  ev.TGID,
			Comm: comm,
			Op:   op,
			Path: path,
		})

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			evOut := telemetry.FSEvent{
				Type: "fs_event", TS: ts, Seq: n,
				PID: ev.TGID, TGID: ev.TGID, ThreadID: ev.TID,
				Comm: comm, Op: op, Path: path,
			}
			werr := telemetry.AppendJSONL(cfg.EventsLogPath, evOut)
			jsonlMu.Unlock()
			if werr != nil {
				stats.addDropped("fs_jsonl")
				slog.Warn("events jsonl", "err", werr)
			}
		}
	}
}

func readConnectRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, dns *DNSCache,
	pol *policy.Policy, stats *runStats, rows *rowBuffer, seq *telemetry.SeqGen, jsonlMu *sync.Mutex) error {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("ringbuf read (tcp)", "err", err)
			continue
		}

		tgid, tid, commb, daddr, port, decOK := decodeConnectEvent(record.RawSample)
		if !decOK {
			stats.addDropped("tcp_decode")
			slog.Warn("decode tcp", "len", len(record.RawSample))
			continue
		}

		ip := net.IP(daddr[:]).To4()
		if ip == nil {
			continue
		}
		comm := string(bytes.TrimRight(commb[:], "\x00"))
		fqdn, fqdnProv := "", "unknown"
		if dns != nil {
			fqdn, fqdnProv = dns.LookupProvenance(ip)
		}
		cl := pol.Classify(fqdn, ip)
		stats.addTCP(cl)

		ts := time.Now().UTC().Format(time.RFC3339Nano)
		notes := "—"
		if fqdn != "" {
			notes = fmt.Sprintf("fqdn `%s` (%s)", report.SanitizeForMarkdown(fqdn), fqdnProv)
		}
		rows.addTCP(report.TCPDigestRow{
			TS: ts, PID: tgid, Comm: comm,
			Remote: fmt.Sprintf("`%s:%d`", ip.String(), port),
			Notes:  notes,
			Policy: cl.Display(),
		})

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.TCPEvent{
				Type: "tcp", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, Dst: ip.String(), Dport: port,
				FQDN: fqdn, FQDNProvenance: fqdnProv,
				Direction: "egress",
				Policy:    string(cl),
			}
			err := telemetry.AppendJSONL(cfg.EventsLogPath, ev)
			jsonlMu.Unlock()
			if err != nil {
				stats.addDropped("tcp_jsonl")
				slog.Warn("events jsonl", "err", err)
			}
		}

		slog.Debug("tcp", "tgid", tgid, "comm", comm, "dst", ip.String(), "dport", port, "policy", string(cl))
	}
}

func readTLSRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, pol *policy.Policy,
	stats *runStats, rows *rowBuffer, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, sectionState *networkSectionState) error {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if sectionState != nil {
				sectionState.addTLSReaderError()
			}
			slog.Warn("ringbuf read (tls)", "err", err)
			continue
		}

		tgid, tid, commb, daddr, port, rawPay, ok := decodeTLSSniffEvent(record.RawSample)
		if !ok {
			if sectionState != nil {
				sectionState.addTLSDecodeError()
			}
			stats.addDropped("tls_decode")
			slog.Warn("decode tls sniff", "len", len(record.RawSample))
			continue
		}
		ip := net.IP(daddr[:]).To4()
		if ip == nil {
			continue
		}
		comm := string(bytes.TrimRight(commb[:], "\x00"))
		sni, parsed := telemetry.ParseClientHelloSNI(rawPay)
		if !parsed {
			stats.addDropped("tls_sni_parse")
			continue
		}
		cl := pol.Classify(sni, ip)
		stats.addTLS(cl)

		ts := time.Now().UTC().Format(time.RFC3339Nano)
		rows.addTLS(report.TLSDigestRow{
			TS: ts, PID: tgid, Comm: comm,
			SNI:    sni,
			Remote: fmt.Sprintf("`%s:%d`", ip.String(), port),
			Policy: cl.Display(),
		})

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.TLSEvent{
				Type: "tls", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, SNI: sni,
				Dst: ip.String(), Dport: port,
				Policy: string(cl),
				Note:   "ClientHello SNI from first write(2) buffer; fragmented handshakes may be missed",
			}
			err := telemetry.AppendJSONL(cfg.EventsLogPath, ev)
			jsonlMu.Unlock()
			if err != nil {
				stats.addDropped("tls_jsonl")
				slog.Warn("events jsonl", "err", err)
			}
		}
	}
}

func readUDPRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, dns *DNSCache,
	pol *policy.Policy, stats *runStats, rows *rowBuffer, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, sectionState *networkSectionState) error {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if sectionState != nil {
				sectionState.addUDPReaderError()
			}
			slog.Warn("ringbuf read (udp)", "err", err)
			continue
		}

		tgid, tid, commb, daddr, port, dgramLen, ok := decodeUDPSendEvent(record.RawSample)
		if !ok {
			if sectionState != nil {
				sectionState.addUDPDecodeError()
			}
			stats.addDropped("udp_decode")
			slog.Warn("decode udp", "len", len(record.RawSample))
			continue
		}
		ip := net.IP(daddr[:]).To4()
		if ip == nil {
			continue
		}
		comm := string(bytes.TrimRight(commb[:], "\x00"))
		fqdn, fqdnProv := "", "unknown"
		if dns != nil {
			fqdn, fqdnProv = dns.LookupProvenance(ip)
		}
		cl := pol.Classify(fqdn, ip)
		stats.addUDP(cl)

		ts := time.Now().UTC().Format(time.RFC3339Nano)
		rows.addUDP(report.UDPDigestRow{
			TS: ts, PID: tgid, Comm: comm,
			Remote:   fmt.Sprintf("`%s:%d`", ip.String(), port),
			DgramLen: dgramLen,
			FQDN:     fqdn,
			Policy:   cl.Display(),
		})

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.UDPEvent{
				Type: "udp", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, Dst: ip.String(), Dport: port,
				DatagramLen: dgramLen, FQDN: fqdn, FQDNProvenance: fqdnProv,
				Direction: "egress",
				Policy:    string(cl),
			}
			err := telemetry.AppendJSONL(cfg.EventsLogPath, ev)
			jsonlMu.Unlock()
			if err != nil {
				stats.addDropped("udp_jsonl")
				slog.Warn("events jsonl", "err", err)
			}
		}
	}
}

func readHTTPRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, pol *policy.Policy,
	stats *runStats, rows *rowBuffer, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, sectionState *networkSectionState) error {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if sectionState != nil {
				sectionState.addHTTPReaderError()
			}
			slog.Warn("ringbuf read (http)", "err", err)
			continue
		}

		tgid, tid, commb, daddr, port, rawPay, ok := decodeHTTPSniffEvent(record.RawSample)
		if !ok {
			if sectionState != nil {
				sectionState.addHTTPDecodeError()
			}
			stats.addDropped("http_decode")
			slog.Warn("decode http sniff", "len", len(record.RawSample))
			continue
		}
		ip := net.IP(daddr[:]).To4()
		if ip == nil {
			continue
		}
		comm := string(bytes.TrimRight(commb[:], "\x00"))
		method, host, path, parsed := telemetry.ParseHTTPRequestPrefix(rawPay)
		if !parsed {
			stats.addDropped("http_prefix_parse")
			continue
		}
		cl := pol.Classify(host, ip)
		stats.addHTTP(cl)

		ts := time.Now().UTC().Format(time.RFC3339Nano)
		sumPath := telemetry.RedactPathForSummary(path)
		rows.addHTTP(report.HTTPDigestRow{
			TS: ts, PID: tgid, Comm: comm,
			Method: method, Host: host, Path: sumPath,
			Remote: fmt.Sprintf("`%s:%d`", ip.String(), port),
			Policy: cl.Display(),
		})

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.HTTPEvent{
				Type: "http", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, Method: method, Host: host, Path: sumPath,
				Dst: ip.String(), Dport: port,
				Policy: string(cl),
			}
			err := telemetry.AppendJSONL(cfg.EventsLogPath, ev)
			jsonlMu.Unlock()
			if err != nil {
				stats.addDropped("http_jsonl")
				slog.Warn("events jsonl", "err", err)
			}
		}
	}
}

func readDNSRing(ctx context.Context, rd *ringbuf.Reader, cache *DNSCache, stats *runStats) error {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("ringbuf read (dns)", "err", err)
			continue
		}
		pkt, ok := decodeDNSSniffSample(record.RawSample)
		if !ok || len(pkt) < 12 {
			stats.addDropped("dns_decode")
			continue
		}
		cache.AddFromPacket(pkt)
	}
}

func compileEnforceAllowlist(ctx context.Context, cfg config.Config, resolver policy.LookupIPFunc, maxAttempts int) (policy.CompileResult, error) {
	if cfg.Mode != config.ModeEnforce {
		return policy.CompileResult{}, nil
	}
	if len(cfg.AllowedDomains) == 0 {
		return policy.CompileResult{}, fmt.Errorf("enforce mode requires non-empty allowlist")
	}
	compiled := policy.CompileDomainAllowlist(ctx, cfg.AllowedDomains, resolver, maxAttempts)
	if len(compiled.Domains) == 0 {
		return policy.CompileResult{}, fmt.Errorf("enforce mode requires non-empty allowlist after normalization")
	}
	pol, perr := cfg.Policy()
	if perr != nil {
		return policy.CompileResult{}, perr
	}
	pol.MergeLiteralAllowedIPv4Into(&compiled.AllowedIPv4)
	if compiled.AllowedIPv4.Len() == 0 {
		msg := "enforce allowlist effective allowlist is empty (no IPv4 A-record resolutions; add literals to allowed-ips if needed)"
		if len(compiled.UnresolvedDomains) > 0 {
			msg += fmt.Sprintf(" — check DNS for: %s", strings.Join(compiled.UnresolvedDomains, ", "))
		}
		return policy.CompileResult{}, fmt.Errorf("%s", msg)
	}
	return compiled, nil
}

// loadIgnoredLPMMap programs the BPF LPM trie used to bypass denies for ignored IPv4 CIDRs.
func loadIgnoredLPMMap(m *ebpf.Map, nets []*net.IPNet) error {
	if len(nets) == 0 {
		return nil
	}
	if m == nil {
		return fmt.Errorf("ignored_ipv4_lpm map is nil with %d ignored CIDR(s)", len(nets))
	}
	if len(nets) > policy.MaxIgnoredIPv4Nets {
		return fmt.Errorf("ignored_ipv4_lpm: %d CIDRs exceeds max %d", len(nets), policy.MaxIgnoredIPv4Nets)
	}
	val := uint8(1)
	programmed := 0
	for i := 0; i < len(nets); i++ {
		n := nets[i]
		if n == nil {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits != 32 || ones < 0 || ones > 32 {
			continue
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			continue
		}
		network := ip4.Mask(n.Mask)
		if network == nil {
			continue
		}
		var key [8]byte
		binary.LittleEndian.PutUint32(key[0:4], uint32(ones))
		binary.BigEndian.PutUint32(key[4:8], binary.BigEndian.Uint32(network))
		if err := m.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("ignored_ipv4_lpm update %s: %w", n.String(), err)
		}
		programmed++
	}
	if programmed == 0 {
		return fmt.Errorf(
			"ignored_ipv4_lpm: no entries programmed from %d configured CIDR(s) (need usable IPv4 prefixes for this LPM map)",
			len(nets),
		)
	}
	return nil
}

func readDenyReserveFailureCount(objs *traceenforce.TraceenforceObjects) int {
	if objs == nil {
		return 0
	}
	var k uint32
	var v uint32
	if err := objs.DenyReserveFailures.Lookup(&k, &v); err != nil {
		return 0
	}
	return int(v)
}

func readConnect4TupleUpdateFailureCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	var k uint32
	var v uint32
	if err := objs.Connect4TupleUpdateFailures.Lookup(&k, &v); err != nil {
		return 0
	}
	return int(v)
}

func readUDPRingbufReserveFailureCount(objs *traceconnect.TraceconnectObjects) int {
	if objs == nil {
		return 0
	}
	var k uint32
	var v uint32
	if err := objs.UdpRingbufReserveFailures.Lookup(&k, &v); err != nil {
		return 0
	}
	return int(v)
}

func readDNSRingbufReserveFailureCount(objs *tracedns.TracednsObjects) int {
	if objs == nil {
		return 0
	}
	var k uint32
	var v uint32
	if err := objs.DnsRingbufReserveFailures.Lookup(&k, &v); err != nil {
		return 0
	}
	return int(v)
}

// loadEnforceMaps programs BPF allowlist maps from compiled domain resolutions + literal policy entries.
func loadEnforceMaps(objs *traceenforce.TraceenforceObjects, compiled policy.CompileResult, pol *policy.Policy) (int, error) {
	if objs == nil {
		return 0, fmt.Errorf("traceenforce objects are required for enforce mode")
	}
	keyMode := uint32(0)
	modeEnforce := uint32(1)
	if err := objs.EnforceCfg.Update(&keyMode, &modeEnforce, ebpf.UpdateAny); err != nil {
		return 0, fmt.Errorf("load enforce_cfg map: %w", err)
	}
	if pol != nil {
		if err := loadIgnoredLPMMap(objs.IgnoredIpv4Lpm, pol.IgnoredIPv4Nets()); err != nil {
			return 0, err
		}
	}

	v4keys := make(map[[4]byte]struct{}, compiled.AllowedIPv4.Len())
	compiled.AllowedIPv4.ForEach(func(k [4]byte) { v4keys[k] = struct{}{} })
	if pol != nil {
		pol.MergeLiteralAllowedIPv4Keys(v4keys)
	}
	if len(v4keys) > policy.MaxAllowedEnforceIPv4Keys {
		return 0, fmt.Errorf("allowed_ipv4: %d entries exceeds BPF max %d", len(v4keys), policy.MaxAllowedEnforceIPv4Keys)
	}

	if len(v4keys) == 0 {
		return 0, fmt.Errorf("enforce allowlist effective allowlist is empty (no map entries)")
	}

	allow := uint8(1)
	for addr := range v4keys {
		addrCopy := addr
		if err := objs.AllowedIpv4.Update(&addrCopy, &allow, ebpf.UpdateAny); err != nil {
			return 0, fmt.Errorf("load allowed_ipv4 map: %w", err)
		}
	}

	return len(v4keys), nil
}

func appendDenyFromRaw(cfg config.Config, raw []byte, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *enforcementState) (telemetry.DenyEvent, error) {
	tgid, tid, commb, protocolRaw, reasonRaw, af, daddr16, dport, ok := decodeDenyEvent(raw)
	if !ok {
		return telemetry.DenyEvent{}, fmt.Errorf("decode deny event")
	}
	protocol := denyProtocolLabel(protocolRaw)
	reason := denyReasonLabel(reasonRaw)
	var dst string
	switch af {
	case linuxAFInet:
		dst = net.IPv4(daddr16[0], daddr16[1], daddr16[2], daddr16[3]).String()
	case linuxAFInet6:
		dst = net.IP(daddr16[:]).String()
	default:
		dst = net.IP(daddr16[:]).String()
	}
	comm := string(bytes.TrimRight(commb[:], "\x00"))
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	deny := telemetry.DenyEvent{
		Type:     "deny",
		TS:       ts,
		Seq:      seq.Next(),
		PID:      tgid,
		TGID:     tgid,
		ThreadID: tid,
		Comm:     comm,
		Protocol: protocol,
		Dst:      dst,
		Dport:    dport,
		Reason:   reason,
		Mode:     "enforce",
	}
	if cfg.EventsLogPath != "" {
		jsonlMu.Lock()
		err := telemetry.AppendJSONL(cfg.EventsLogPath, deny)
		jsonlMu.Unlock()
		if err != nil {
			return telemetry.DenyEvent{}, fmt.Errorf("append deny jsonl: %w", err)
		}
	}
	if state != nil {
		state.noteDeny(denyDigestRowFromEvent(deny))
	}
	return deny, nil
}

// testAppendDenySample exercises appendDenyFromRaw JSONL emission and returns a sentinel error
// for unit tests. Production readDenyRing logs and skips decode/JSONL failures so enforcement
// keeps running; successful denies still flow through appendDenyFromRaw unchanged.
func testAppendDenySample(cfg config.Config, raw []byte, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *enforcementState) error {
	deny, err := appendDenyFromRaw(cfg, raw, seq, jsonlMu, state)
	if err != nil {
		return err
	}
	return newEnforceDenyError(deny)
}

func readDenyRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *enforcementState, cancelRun context.CancelFunc) error {
	// First deny triggers a short drain window (more JSONL rows), then we cancel the run
	// context and return a single "enforce deny" error so Run exits non-zero while BPF
	// teardown still happens via defers. Other ringbuf readers exit on ctx cancel + map close.
	for {
		rd.SetDeadline(time.Time{})
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("ringbuf read (deny)", "err", err)
			continue
		}

		firstDeny, err := appendDenyFromRaw(cfg, record.RawSample, seq, jsonlMu, state)
		if err != nil {
			if cancelRun != nil {
				cancelRun()
			}
			return err
		}

		drainUntil := time.Now().Add(enforceDenyDrainDuration)
		n := 1
		for n < enforceDenyDrainMaxEvents && time.Now().Before(drainUntil) {
			rd.SetDeadline(time.Now().Add(enforceDenyDrainReadSlice))
			rec2, err2 := rd.Read()
			if err2 != nil {
				if errors.Is(err2, ringbuf.ErrClosed) {
					break
				}
				if errors.Is(err2, os.ErrDeadlineExceeded) {
					continue
				}
				if ctx.Err() != nil {
					rd.SetDeadline(time.Time{})
					if cancelRun != nil {
						cancelRun()
					}
					return newEnforceDenyError(firstDeny)
				}
				rd.SetDeadline(time.Time{})
				slog.Warn("ringbuf read (deny drain)", "err", err2)
				continue
			}
			if _, err3 := appendDenyFromRaw(cfg, rec2.RawSample, seq, jsonlMu, state); err3 != nil {
				rd.SetDeadline(time.Time{})
				if cancelRun != nil {
					cancelRun()
				}
				return err3
			}
			n++
		}
		rd.SetDeadline(time.Time{})
		if cancelRun != nil {
			cancelRun()
		}
		return newEnforceDenyError(firstDeny)
	}
}

// processDenyRingSample handles one deny ringbuf payload. Decode or JSONL failures are logged and
// dropped so readDenyRing never returns a fatal error (enforcement stays attached).
func processDenyRingSample(cfg config.Config, raw []byte, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *enforcementState) {
	deny, err := appendDenyFromRaw(cfg, raw, seq, jsonlMu, state)
	if err != nil {
		slog.Warn("deny ring sample skipped", "err", err, "raw_len", len(raw))
		return
	}
	slog.Debug("enforce deny", "protocol", deny.Protocol, "dst", deny.Dst, "dport", deny.Dport,
		"reason", deny.Reason, "comm", deny.Comm)
}

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

func buildDigestInput(
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
) report.DigestInput {
	execN, tcpN, udpN, httpN, tlsN, fsN := stats.counts()
	rawTPName := "raw_tp/sys_enter (connect, sendto, http sniff, tls)"
	in := report.DigestInput{
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
		UDPDegradedHook:                hookDegraded(bpfSt, rawTPName),
		UDPReaderErrors:                sectionState.udpReadErrors + sectionState.udpDecodeErrors,
		HTTPDegradedHook:               hookDegraded(bpfSt, rawTPName),
		HTTPReaderErrors:               sectionState.httpReadErrors + sectionState.httpDecodeErrors,
		TLSDegradedHook:                hookDegraded(bpfSt, rawTPName),
		TLSReaderErrors:                sectionState.tlsReadErrors + sectionState.tlsDecodeErrors,
		EnforcementMode:                enforceState.mode,
		EnforcementAllowlistSize:       enforceState.allowlistSize,
		EnforcementDenyCount:           enforceState.denyCount,
		EnforcementDenyReserveFailures: enforceState.denyReserveFailures,
		EnforcementFirstDeny:           enforceState.firstDeny,
		Connect4TupleUpdateFailures:    stats.connect4TupleUpdateFailures(),
		UDPRingbufReserveFailures:      stats.udpRingbufReserveFailures(),
		DNSRingbufReserveFailures:      stats.dnsRingbufReserveFailures(),
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

// Run loads BPF, streams events until ctx is cancelled, then drains workers.
func Run(ctx context.Context, cfg config.Config) error {
	pol, err := cfg.Policy()
	if err != nil {
		return err
	}

	kernel := kernelRelease()
	stats := newRunStats()
	maxRows := report.DefaultMaxRowsPerSection
	rows := newRowBuffer(maxRows)
	sectionState := newNetworkSectionState()
	enforceState := newEnforcementState()
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	procTreeGate := config.FeatureGateEnabled(cfg.FeatureGates, "proc_tree")
	tlsSNIGate := config.FeatureGateEnabled(cfg.FeatureGates, "tls_sni")
	fsGate := config.FeatureGateEnabled(cfg.FeatureGates, "fs_events")
	var forkBuf *forkEdgeBuffer
	var forkState *forkSectionState
	var fsRowBuf *fsRowBuffer
	var fsSt *fsSectionState

	bpfSt := []telemetry.BPFStatus{
		{Name: "sched_process_exec", OK: false, Detail: "not loaded"},
		{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: false, Detail: "not loaded"},
		{Name: "dns recvfrom sniff", OK: false, Detail: "not loaded"},
	}

	detectDest := cfg.StepSummaryPath
	if cfg.DetectLogPath != "" {
		detectDest = cfg.DetectLogPath
	}

	defer func() {
		sum := stats.snapshotSummary(kernel, bpfSt)
		if err := telemetry.WriteSummary(cfg.TelemetrySummaryPath, sum); err != nil {
			slog.Warn("telemetry summary", "err", err)
		}
		if detectDest != "" {
			execRows, tcpRows, udpRows, httpRows, tlsRows := rows.snapshot()
			seqLast := seq.Last()
			var forkEdges []proctree.Edge
			forkTrunc := false
			forkSnap := forkSectionSnapshot{}
			if forkBuf != nil {
				forkEdges, forkTrunc = forkBuf.snapshot()
			}
			if forkState != nil {
				forkSnap = forkState.snapshot()
			}
			var fsDigestRows []report.FSDigestRow
			fsSnap := fsSectionSnapshot{}
			if fsRowBuf != nil {
				fsDigestRows = fsRowBuf.snapshot()
			}
			if fsSt != nil {
				fsSnap = fsSt.snapshot()
			}
			in := buildDigestInput(stats, bpfSt, execRows, tcpRows, udpRows, httpRows, tlsRows, cfg.EventsLogPath, seqLast, maxRows, sectionState.snapshot(), enforceState.snapshot(), forkEdges, forkTrunc, forkSnap, procTreeGate, tlsSNIGate, fsDigestRows, fsSnap, fsGate)
			in.PolicyCounts = sum.PolicyCounts
			if err := report.WriteDetectDigest(detectDest, in); err != nil {
				slog.Warn("detect digest", "err", err)
			}
		}
	}()

	compileCtx, compileCancel := context.WithTimeout(ctx, 120*time.Second)
	defer compileCancel()
	enforceCompiled, err := compileEnforceAllowlist(compileCtx, cfg, nil, 2)
	if err != nil {
		return err
	}

	dnsCache := NewDNSCache()

	var execObjs traceexec.TraceexecObjects
	if err := traceexec.LoadTraceexecObjects(&execObjs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer execObjs.Close()

	execLnk, err := link.Tracepoint("sched", "sched_process_exec", execObjs.HandleSchedProcessExec, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sched_process_exec: %w", err)
	}
	defer execLnk.Close()
	bpfSt[0] = telemetry.BPFStatus{Name: "sched_process_exec", OK: true}

	execRd, err := ringbuf.NewReader(execObjs.Events)
	if err != nil {
		return fmt.Errorf("ringbuf reader exec: %w", err)
	}
	// execRd is normally closed when runCtx is cancelled (see goroutine below). Any return
	// before that goroutine is registered would otherwise leak the reader (e.g. enforce mode
	// when syscall trace attach fails, or enforce BPF/map/attach errors).
	closeExecRdOnEarlyExit := true
	defer func() {
		if closeExecRdOnEarlyExit {
			_ = execRd.Close()
		}
	}()

	var connRd, udpRd, httpRd, tlsRd *ringbuf.Reader
	var denyRd *ringbuf.Reader
	var syscallObjs *traceconnect.TraceconnectObjects
	var syscallLnk link.Link
	var enforceConnectLnk link.Link
	var enforceSendmsgLnk link.Link
	if cR, uR, hR, tR, objs, lnk, tlsCfgFailed, err := startSyscallTrace(tlsSNIGate); err != nil {
		slog.Info("syscall egress tracing disabled", "err", err)
		bpfSt[1] = telemetry.BPFStatus{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: false, Detail: bpfDetail(err)}
		if cfg.Mode == config.ModeEnforce {
			return fmt.Errorf("enforce mode requires syscall trace attach: %w", err)
		}
	} else {
		connRd, udpRd, httpRd, tlsRd, syscallObjs, syscallLnk = cR, uR, hR, tR, objs, lnk
		syscallOK := true
		syscallDetail := ""
		if tlsCfgFailed {
			syscallOK = false
			syscallDetail = "tls_agent_cfg map update failed (TLS SNI sniff disabled in BPF)"
		}
		bpfSt[1] = telemetry.BPFStatus{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: syscallOK, Detail: syscallDetail}
		slog.Info("tracing connect + UDP sendto + HTTP/80 sniff + optional TLS write (raw_tp/sys_enter)")
		defer syscallLnk.Close()
		defer syscallObjs.Close()
		defer func() {
			if syscallObjs != nil {
				stats.setConnect4TupleUpdateFailures(readConnect4TupleUpdateFailureCount(syscallObjs))
				stats.setUDPRingbufReserveFailures(readUDPRingbufReserveFailureCount(syscallObjs))
			}
		}()
		defer connRd.Close()
		defer udpRd.Close()
		defer httpRd.Close()
		defer tlsRd.Close()

		if cfg.Mode == config.ModeEnforce {
			enforceObjs := new(traceenforce.TraceenforceObjects)
			if err := traceenforce.LoadTraceenforceObjects(enforceObjs, nil); err != nil {
				return fmt.Errorf("load enforce bpf objects: %w", err)
			}
			defer func() {
				enforceState.setDenyReserveFailures(readDenyReserveFailureCount(enforceObjs))
				_ = enforceObjs.Close()
			}()

			allowlistSize, loadErr := loadEnforceMaps(enforceObjs, enforceCompiled, pol)
			if loadErr != nil {
				return loadErr
			}
			enforceState.setModeAndAllowlist(string(cfg.Mode), allowlistSize)
			denyRd, err = ringbuf.NewReader(enforceObjs.DenyEvents)
			if err != nil {
				return fmt.Errorf("ringbuf reader deny: %w", err)
			}
			defer denyRd.Close()

			cgPath := cfg.CgroupAttachPath
			if cgPath == "" {
				cgPath = "/sys/fs/cgroup"
			}

			enforceConnectLnk, err = link.AttachCgroup(link.CgroupOptions{
				Path:    cgPath,
				Attach:  ebpf.AttachCGroupInet4Connect,
				Program: enforceObjs.EnforceConnect4,
			})
			if err != nil {
				return fmt.Errorf("attach enforce_connect4: %w", err)
			}
			defer enforceConnectLnk.Close()

			enforceSendmsgLnk, err = link.AttachCgroup(link.CgroupOptions{
				Path:    cgPath,
				Attach:  ebpf.AttachCGroupUDP4Sendmsg,
				Program: enforceObjs.EnforceSendmsg4,
			})
			if err != nil {
				return fmt.Errorf("attach enforce_sendmsg4: %w", err)
			}
			defer enforceSendmsgLnk.Close()
		}
	}

	var dnsRd *ringbuf.Reader
	var dnsObjs *tracedns.TracednsObjects
	var dnsLnkEnter, dnsLnkExit link.Link
	if rd, objs, le, lx, err := startDNSTrace(); err != nil {
		slog.Info("dns reply sniffing disabled", "err", err)
		bpfSt[2] = telemetry.BPFStatus{Name: "dns recvfrom sniff", OK: false, Detail: bpfDetail(err)}
	} else {
		dnsRd, dnsObjs, dnsLnkEnter, dnsLnkExit = rd, objs, le, lx
		bpfSt[2] = telemetry.BPFStatus{Name: "dns recvfrom sniff", OK: true}
		slog.Info("tracing DNS replies (recvfrom)")
		defer dnsLnkExit.Close()
		defer dnsLnkEnter.Close()
		defer dnsObjs.Close()
		defer func() {
			if dnsObjs != nil {
				stats.setDNSRingbufReserveFailures(readDNSRingbufReserveFailureCount(dnsObjs))
			}
		}()
		defer dnsRd.Close()
	}

	var forkRd *ringbuf.Reader
	var forkObjs *tracefork.TraceforkObjects
	var forkLnk link.Link
	if procTreeGate {
		forkBuf = newForkEdgeBuffer(5000)
		forkState = newForkSectionState()
		objs := new(tracefork.TraceforkObjects)
		if err := tracefork.LoadTraceforkObjects(objs, nil); err != nil {
			slog.Info("sched_process_fork tracing disabled", "err", err)
			bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: false, Detail: bpfDetail(err)})
		} else {
			forkObjs = objs
			lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
				Name:    "sched_process_fork",
				Program: objs.HandleSchedProcessFork,
			})
			if err != nil {
				slog.Info("sched_process_fork attach failed", "err", err)
				bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: false, Detail: bpfDetail(err)})
				_ = objs.Close()
				forkObjs = nil
			} else {
				forkLnk = lnk
				rd, err := ringbuf.NewReader(objs.ForkEvents)
				if err != nil {
					slog.Info("sched_process_fork ringbuf reader failed", "err", err)
					bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: false, Detail: bpfDetail(err)})
					_ = lnk.Close()
					_ = objs.Close()
					forkObjs = nil
					forkLnk = nil
				} else {
					forkRd = rd
					bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: true})
					slog.Info("tracing sched_process_fork (process tree)")
					defer func() {
						if forkRd != nil {
							_ = forkRd.Close()
						}
						if forkLnk != nil {
							_ = forkLnk.Close()
						}
						if forkObjs != nil {
							_ = forkObjs.Close()
						}
					}()
				}
			}
		}
	}

	var fsRd *ringbuf.Reader
	var fsObjs *tracefs.TracefsObjects
	var fsLnk link.Link
	if fsGate {
		fsRowBuf = newFSRowBuffer(maxRows)
		fsSt = newFSSectionState()
		objs := new(tracefs.TracefsObjects)
		if err := tracefs.LoadTracefsObjects(objs, nil); err != nil {
			slog.Info("fs tracing disabled", "err", err)
			bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
		} else {
			var fsCfgErr error
			if err := objs.FsAgentCfg.Update(uint32(0), uint8(1), ebpf.UpdateAny); err != nil {
				fsCfgErr = err
				slog.Warn("fs cfg map update", "err", err)
			}
			fsObjs = objs
			lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
				Name:    "sys_enter",
				Program: objs.HandleFsSysEnter,
			})
			if err != nil {
				slog.Info("fs sys_enter attach failed", "err", err)
				bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
				_ = objs.Close()
				fsObjs = nil
			} else {
				fsLnk = lnk
				rd, err := ringbuf.NewReader(objs.FsEvents)
				if err != nil {
					slog.Info("fs ringbuf reader failed", "err", err)
					bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
					_ = lnk.Close()
					_ = objs.Close()
					fsObjs = nil
					fsLnk = nil
				} else {
					fsRd = rd
					fsOK := true
					fsDetail := ""
					if fsCfgErr != nil {
						fsOK = false
						fsDetail = bpfDetail(fsCfgErr)
						if fsDetail == "" {
							fsDetail = "fs_agent_cfg map update failed (fs events disabled in BPF)"
						}
					}
					bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: fsOK, Detail: fsDetail})
					slog.Info("tracing fs events (openat+create, unlink, rename, chmod)")
					defer func() {
						if fsRd != nil {
							_ = fsRd.Close()
						}
						if fsLnk != nil {
							_ = fsLnk.Close()
						}
						if fsObjs != nil {
							_ = fsObjs.Close()
						}
					}()
				}
			}
		}
	}

	if err := writeAgentStatus(cfg.AgentStatusPath, true); err != nil {
		slog.Warn("agent status", "err", err)
	}

	if cfg.EventsLogPath != "" {
		meta, err := telemetry.BuildMeta(agentVersionString(), bpfSt)
		if err != nil {
			slog.Warn("build meta", "err", err)
		} else {
			if capabilityEnabled(procTreeGate, bpfSt, "sched_process_fork") {
				if meta.Capabilities == nil {
					meta.Capabilities = make(map[string]bool)
				}
				meta.Capabilities["proc_tree"] = true
			}
			if capabilityEnabled(tlsSNIGate, bpfSt, "raw_tp/sys_enter (connect, sendto, http sniff, tls)") {
				if meta.Capabilities == nil {
					meta.Capabilities = make(map[string]bool)
				}
				meta.Capabilities["tls_sni"] = true
			}
			if capabilityEnabled(fsGate, bpfSt, "raw_tp/sys_enter (fs)") {
				if meta.Capabilities == nil {
					meta.Capabilities = make(map[string]bool)
				}
				meta.Capabilities["fs_events"] = true
			}
			if err := telemetry.AppendJSONL(cfg.EventsLogPath, meta); err != nil {
				slog.Warn("meta jsonl", "err", err)
			}
		}
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	go func() {
		<-runCtx.Done()
		_ = execRd.Close()
		if connRd != nil {
			_ = connRd.Close()
		}
		if udpRd != nil {
			_ = udpRd.Close()
		}
		if httpRd != nil {
			_ = httpRd.Close()
		}
		if tlsRd != nil {
			_ = tlsRd.Close()
		}
		if denyRd != nil {
			_ = denyRd.Close()
		}
		if dnsRd != nil {
			_ = dnsRd.Close()
		}
		if forkRd != nil {
			_ = forkRd.Close()
		}
		if fsRd != nil {
			_ = fsRd.Close()
		}
	}()

	slog.Info("coldstep event readers started", "mode", string(cfg.Mode))

	// Each reader goroutine sends one error on exit; buffer must fit all sends before wg.Wait returns.
	readerCount := 1
	if forkRd != nil && forkBuf != nil && forkState != nil {
		readerCount++
	}
	if fsRd != nil && fsRowBuf != nil && fsSt != nil {
		readerCount++
	}
	if connRd != nil {
		readerCount++
	}
	if udpRd != nil {
		readerCount++
	}
	if httpRd != nil {
		readerCount++
	}
	if tlsRd != nil {
		readerCount++
	}
	if denyRd != nil {
		readerCount++
	}
	if dnsRd != nil {
		readerCount++
	}

	var wg sync.WaitGroup
	errCh := make(chan error, readerCount)

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- readExecRing(runCtx, cfg, execRd, stats, rows, &seq, &jsonlMu)
	}()

	if forkRd != nil && forkBuf != nil && forkState != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readForkRing(runCtx, cfg, forkRd, stats, forkBuf, forkState, &seq, &jsonlMu)
		}()
	}

	if fsRd != nil && fsRowBuf != nil && fsSt != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readFSRing(runCtx, cfg, fsRd, stats, fsRowBuf, fsSt, &seq, &jsonlMu)
		}()
	}

	if connRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readConnectRing(runCtx, cfg, connRd, dnsCache, pol, stats, rows, &seq, &jsonlMu)
		}()
	}
	if udpRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readUDPRing(runCtx, cfg, udpRd, dnsCache, pol, stats, rows, &seq, &jsonlMu, sectionState)
		}()
	}
	if httpRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readHTTPRing(runCtx, cfg, httpRd, pol, stats, rows, &seq, &jsonlMu, sectionState)
		}()
	}
	if tlsRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readTLSRing(runCtx, cfg, tlsRd, pol, stats, rows, &seq, &jsonlMu, sectionState)
		}()
	}
	if denyRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readDenyRing(runCtx, cfg, denyRd, &seq, &jsonlMu, enforceState, runCancel)
		}()
	}
	if dnsRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readDNSRing(runCtx, dnsRd, dnsCache, stats)
		}()
	}

	wg.Wait()
	close(errCh)

	var retErr error
	for err := range errCh {
		retErr = preferRunError(retErr, err)
	}
	closeExecRdOnEarlyExit = false
	return retErr
}

func Main() error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	setupLogging(cfg.LogLevel)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
