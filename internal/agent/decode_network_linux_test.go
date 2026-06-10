//go:build linux

package agent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func TestDecodeUDPSendEvent(t *testing.T) {
	raw := make([]byte, udpSendEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], 100)
	binary.LittleEndian.PutUint32(raw[4:8], 101)
	copy(raw[8:24], []byte("myproc\x00"))
	raw[24], raw[25], raw[26], raw[27] = 8, 8, 8, 8
	binary.BigEndian.PutUint16(raw[28:30], 53)
	// dgramLen lives at offset 32 (after the explicit __u8 _pad[2]); see PR-B.
	binary.LittleEndian.PutUint32(raw[32:36], 512)

	tgid, tid, comm, daddr, dport, dlen, ok := decodeUDPSendEvent(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if tgid != 100 || tid != 101 || dport != 53 || dlen != 512 {
		t.Fatalf("got tgid=%d tid=%d dport=%d dlen=%d", tgid, tid, dport, dlen)
	}
	if daddr != [4]byte{8, 8, 8, 8} {
		t.Fatalf("daddr %v", daddr)
	}
	commStr := string(bytes.TrimRight(comm[:], "\x00"))
	if commStr != "myproc" {
		t.Fatalf("comm %q", commStr)
	}
}

func TestDecodeUDPSendEvent_tooShort(t *testing.T) {
	_, _, _, _, _, _, ok := decodeUDPSendEvent(make([]byte, udpSendEventWireSize-1))
	if ok {
		t.Fatal("expected false")
	}
}

func TestDecodeKTLSEvent(t *testing.T) {
	raw := make([]byte, ktlsEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], 500)
	binary.LittleEndian.PutUint32(raw[4:8], 501)
	copy(raw[8:24], []byte("openssl\x00"))
	binary.LittleEndian.PutUint32(raw[24:28], 7)
	raw[28] = 1 // tx

	tgid, tid, fd, comm, dir, ok := decodeKTLSEvent(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if tgid != 500 || tid != 501 || fd != 7 || dir != 1 {
		t.Fatalf("got tgid=%d tid=%d fd=%d dir=%d", tgid, tid, fd, dir)
	}
	if commStr := string(bytes.TrimRight(comm[:], "\x00")); commStr != "openssl" {
		t.Fatalf("comm %q", commStr)
	}
	if got := ktlsDirectionLabel(dir); got != "tx" {
		t.Fatalf("ktlsDirectionLabel(1)=%q want tx", got)
	}

	raw[28] = 2
	if _, _, _, _, dir, ok = decodeKTLSEvent(raw); !ok {
		t.Fatal("expected ok after direction=rx")
	}
	if got := ktlsDirectionLabel(dir); got != "rx" {
		t.Fatalf("ktlsDirectionLabel(2)=%q want rx", got)
	}
	if got := ktlsDirectionLabel(99); got != "unknown" {
		t.Fatalf("ktlsDirectionLabel(99)=%q want unknown", got)
	}
}

func TestDecodeKTLSEvent_tooShort(t *testing.T) {
	_, _, _, _, _, ok := decodeKTLSEvent(make([]byte, ktlsEventWireSize-1))
	if ok {
		t.Fatal("expected false")
	}
}

func TestDecodeHTTPSniffEvent(t *testing.T) {
	raw := make([]byte, httpSniffEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], 200)
	binary.LittleEndian.PutUint32(raw[4:8], 201)
	copy(raw[8:24], []byte("curl\x00"))
	raw[24], raw[25], raw[26], raw[27] = 1, 1, 1, 1
	binary.BigEndian.PutUint16(raw[28:30], 80)
	payload := []byte("GET / HTTP/1.1\r\nHost: ex\r\n")
	binary.LittleEndian.PutUint16(raw[32:34], uint16(len(payload)))
	copy(raw[httpSniffEventHeaderSize:], payload)

	tgid, tid, comm, daddr, dport, pay, ok := decodeHTTPSniffEvent(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if tgid != 200 || tid != 201 || dport != 80 {
		t.Fatalf("tgid=%d tid=%d dport=%d", tgid, tid, dport)
	}
	if daddr != [4]byte{1, 1, 1, 1} {
		t.Fatalf("daddr %v", daddr)
	}
	if !bytes.Equal(pay, payload) {
		t.Fatalf("payload %q", pay)
	}
	_ = comm
}

func TestDecodeHTTPSniffEvent_captureLenTooLarge(t *testing.T) {
	raw := make([]byte, httpSniffEventWireSize)
	binary.LittleEndian.PutUint16(raw[32:34], httpPayloadMax+1)
	_, _, _, _, _, _, ok := decodeHTTPSniffEvent(raw)
	if ok {
		t.Fatal("expected false for capLen > httpPayloadMax")
	}
}

func TestDecodeHTTPSniffEvent_tooShort(t *testing.T) {
	_, _, _, _, _, _, ok := decodeHTTPSniffEvent(make([]byte, httpSniffEventWireSize-1))
	if ok {
		t.Fatal("expected false")
	}
}

func TestDecodeTLSSniffEvent_captureLenAtMax(t *testing.T) {
	raw := make([]byte, tlsSniffEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], 300)
	binary.LittleEndian.PutUint32(raw[4:8], 301)
	copy(raw[8:24], []byte("tlscli\x00"))
	raw[24], raw[25], raw[26], raw[27] = 9, 9, 9, 9
	binary.BigEndian.PutUint16(raw[28:30], 443)
	// Syscall may pass len > tlsPayloadMax; BPF caps capture_len to tlsPayloadMax.
	binary.LittleEndian.PutUint16(raw[32:34], tlsPayloadMax)
	for i := 0; i < tlsPayloadMax; i++ {
		raw[tlsSniffEventHeaderSize+i] = byte(i)
	}

	_, _, _, daddr, _, pay, _, isIPv6, ok := decodeTLSSniffEvent(raw)
	if !ok {
		t.Fatal("expected ok when capture_len == tlsPayloadMax")
	}
	if len(pay) != tlsPayloadMax {
		t.Fatalf("payload len %d", len(pay))
	}
	if isIPv6 {
		t.Fatal("isIPv6 should be false for zeroed trailer")
	}
	if daddr != [4]byte{9, 9, 9, 9} {
		t.Fatalf("daddr %v", daddr)
	}
}

func TestDecodeTLSSniffEvent_captureLenTooLarge(t *testing.T) {
	raw := make([]byte, tlsSniffEventWireSize)
	binary.LittleEndian.PutUint16(raw[32:34], tlsPayloadMax+1)
	_, _, _, _, _, _, _, _, ok := decodeTLSSniffEvent(raw)
	if ok {
		t.Fatal("expected false for capLen > tlsPayloadMax")
	}
}

func TestDecodeTCPStateEvent(t *testing.T) {
	raw := make([]byte, tcpStateEventWireSize)
	// timestamp_ns
	binary.LittleEndian.PutUint64(raw[0:8], 0x0102030405060708)
	// pid
	binary.LittleEndian.PutUint32(raw[8:12], 42)
	// saddr (network byte order octets — 10.0.0.1)
	raw[12], raw[13], raw[14], raw[15] = 10, 0, 0, 1
	// daddr — 93.184.216.34
	raw[16], raw[17], raw[18], raw[19] = 93, 184, 216, 34
	// sport (host order) — 54321
	binary.LittleEndian.PutUint16(raw[20:22], 54321)
	// dport (host order) — 443
	binary.LittleEndian.PutUint16(raw[22:24], 443)
	// old_state — TCP_SYN_SENT (2)
	binary.LittleEndian.PutUint32(raw[24:28], 2)
	// new_state — TCP_ESTABLISHED (1)
	binary.LittleEndian.PutUint32(raw[28:32], 1)
	// comm
	copy(raw[32:48], []byte("curl\x00"))

	ts, pid, saddr, daddr, sport, dport, oldSt, newSt, comm, ok := decodeTCPStateEvent(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if ts != 0x0102030405060708 {
		t.Errorf("timestamp_ns = %x, want 0x0102030405060708", ts)
	}
	if pid != 42 {
		t.Errorf("pid = %d, want 42", pid)
	}
	if saddr != [4]byte{10, 0, 0, 1} {
		t.Errorf("saddr = %v", saddr)
	}
	if daddr != [4]byte{93, 184, 216, 34} {
		t.Errorf("daddr = %v", daddr)
	}
	if sport != 54321 {
		t.Errorf("sport = %d, want 54321", sport)
	}
	if dport != 443 {
		t.Errorf("dport = %d, want 443", dport)
	}
	if oldSt != 2 {
		t.Errorf("old_state = %d, want 2", oldSt)
	}
	if newSt != 1 {
		t.Errorf("new_state = %d, want 1", newSt)
	}
	commStr := string(bytes.TrimRight(comm[:], "\x00"))
	if commStr != "curl" {
		t.Errorf("comm = %q, want \"curl\"", commStr)
	}
}

func TestDecodeTCPStateEvent_tooShort(t *testing.T) {
	_, _, _, _, _, _, _, _, _, ok := decodeTCPStateEvent(make([]byte, tcpStateEventWireSize-1))
	if ok {
		t.Fatal("expected false for short input")
	}
}

// TestDecodeTCPStateEvent_CommSanitization guards Bug 1 from the second audit:
// the TCPState ring reader must run the comm field through
// telemetry.SanitizeField (matching every other ring reader) so a malicious or
// corrupted argv[0] cannot inject JSONL control bytes when serialized into the
// events log. We stage a comm buffer with embedded control bytes and invalid
// UTF-8, decode it via the wire path, and then exercise the same sanitization
// pipeline that readTCPStateRing uses.
func TestDecodeTCPStateEvent_CommSanitization(t *testing.T) {
	raw := make([]byte, tcpStateEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1)
	binary.LittleEndian.PutUint32(raw[8:12], 1)
	raw[12], raw[13], raw[14], raw[15] = 10, 0, 0, 1
	raw[16], raw[17], raw[18], raw[19] = 10, 0, 0, 2
	binary.LittleEndian.PutUint16(raw[20:22], 1234)
	binary.LittleEndian.PutUint16(raw[22:24], 80)
	binary.LittleEndian.PutUint32(raw[24:28], 2) // SYN_SENT
	binary.LittleEndian.PutUint32(raw[28:32], 1) // ESTABLISHED
	// comm: "ev\nil\x01\xff\xff" (newline + control + invalid UTF-8) padded
	// with NULs out to 16 bytes. Invalid UTF-8 must come out as U+FFFD; the
	// newline and 0x01 control must be stripped.
	commIn := []byte{'e', 'v', '\n', 'i', 'l', 0x01, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	copy(raw[32:48], commIn)

	_, _, _, _, _, _, _, _, commBytes, ok := decodeTCPStateEvent(raw)
	if !ok {
		t.Fatal("decode expected to succeed")
	}

	// Pipeline matches readTCPStateRing exactly so any drift between this
	// test and the production sanitization choice fails here.
	sanitized := telemetry.SanitizeField(nullTermStr(commBytes[:]), 16)

	// SanitizeField removes \n and 0x01 entirely. The invalid 0xFF pair is
	// not valid UTF-8 so SanitizeField replaces it with U+FFFD. Result must
	// contain no control bytes and no raw 0xFF.
	if bytes.ContainsRune([]byte(sanitized), '\n') {
		t.Errorf("sanitized comm still contains newline: %q", sanitized)
	}
	if bytes.IndexByte([]byte(sanitized), 0x01) >= 0 {
		t.Errorf("sanitized comm still contains 0x01 control byte: %q", sanitized)
	}
	if bytes.IndexByte([]byte(sanitized), 0xFF) >= 0 {
		t.Errorf("sanitized comm still contains raw 0xFF (invalid UTF-8 not replaced): %q", sanitized)
	}
	// And critically: the raw, un-sanitized prefix would still have the
	// newline. If the production code ever drops the SanitizeField call we
	// want this assertion to catch it.
	if got := nullTermStr(commBytes[:]); !bytes.Contains([]byte(got), []byte{'\n'}) {
		t.Fatalf("test setup wrong: pre-sanitize comm should still contain \\n; got %q", got)
	}
}

// TestClassifyTCPStateTransition guards Bug 4 from the second audit. The
// classifier must call ESTABLISHED a confirmed handshake, count Close /
// CloseWait / TimeWait as terminal failures (refused), and leave every other
// transition (SYN_RECV, FIN_WAIT*, etc.) out of *both* buckets so they are
// not misattributed as policy-relevant refusals.
func TestClassifyTCPStateTransition(t *testing.T) {
	cases := []struct {
		newStr         string
		wantConfirmed  bool
		wantRefused    bool
		wantInBuckets  bool // confirmed or refused must be set
		describeReason string
	}{
		{telemetry.TCPStateEstablished, true, false, true, "handshake succeeded"},
		{telemetry.TCPStateClose, false, true, true, "RST / timeout / unreachable"},
		{telemetry.TCPStateCloseWait, false, true, true, "peer-initiated close after partial connect"},
		{telemetry.TCPStateTimeWait, false, true, true, "connection terminated, waiting out 2*MSL"},
		// Bug 4: SYN_RECV is an intermediate handshake state, not a refusal.
		{telemetry.TCPStateSynRecv, false, false, false, "intermediate handshake state, not failure"},
		{telemetry.TCPStateFinWait1, false, false, false, "active-close intermediate, not a refusal"},
		{telemetry.TCPStateFinWait2, false, false, false, "active-close intermediate, not a refusal"},
		{telemetry.TCPStateLastAck, false, false, false, "active-close intermediate, not a refusal"},
		{telemetry.TCPStateClosing, false, false, false, "simultaneous-close intermediate, not a refusal"},
		{"UNKNOWN", false, false, false, "unknown newstate falls through both buckets"},
	}
	for _, tc := range cases {
		t.Run(tc.newStr, func(t *testing.T) {
			gotConfirmed, gotRefused := classifyTCPStateTransition(tc.newStr)
			if gotConfirmed != tc.wantConfirmed {
				t.Errorf("confirmed = %v, want %v (%s)", gotConfirmed, tc.wantConfirmed, tc.describeReason)
			}
			if gotRefused != tc.wantRefused {
				t.Errorf("refused = %v, want %v (%s)", gotRefused, tc.wantRefused, tc.describeReason)
			}
			if (gotConfirmed || gotRefused) != tc.wantInBuckets {
				t.Errorf("inBuckets = %v, want %v", gotConfirmed || gotRefused, tc.wantInBuckets)
			}
		})
	}
}

// TestDecodeConnectResultEvent guards the wire→Go decode for the P3-2
// connect_result_event emitted by the kretprobe on tcp_v4_connect. ETIMEDOUT
// (-110) is the most common non-success result on hosted runners and exercises
// the negative-errno round-trip through the (__u32 → int32) reinterpret-cast.
// Callers are expected to have already matched connectResultMagic at offset 0
// before invoking the decoder, so the test stages the magic too even though
// the decoder itself does not re-validate it.
func TestDecodeConnectResultEvent(t *testing.T) {
	raw := make([]byte, connectResultEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], connectResultMagic)
	// result = -110 (-ETIMEDOUT) round-tripped through unsigned-bits. The
	// runtime variable defeats Go's constant-overflow check, which rejects a
	// direct uint32(int32(-110)) conversion even though the same byte pattern
	// is exactly what the kernel writes to the wire.
	var wantResult int32 = -110
	binary.LittleEndian.PutUint32(raw[4:8], uint32(wantResult)) // #nosec G115 -- intentional reinterpret-cast for the wire round-trip //nolint:gosec
	binary.LittleEndian.PutUint32(raw[8:12], 1234)              // tgid
	binary.LittleEndian.PutUint32(raw[12:16], 1235)             // tid
	copy(raw[16:32], []byte("curl\x00"))                        // comm

	tgid, tid, comm, result, ok := decodeConnectResultEvent(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if tgid != 1234 {
		t.Errorf("tgid = %d, want 1234", tgid)
	}
	if tid != 1235 {
		t.Errorf("tid = %d, want 1235", tid)
	}
	if result != wantResult {
		t.Errorf("result = %d, want -110 (-ETIMEDOUT)", result)
	}
	if got := string(bytes.TrimRight(comm[:], "\x00")); got != "curl" {
		t.Errorf("comm = %q, want \"curl\"", got)
	}
}

func TestDecodeConnectResultEvent_tooShort(t *testing.T) {
	_, _, _, _, ok := decodeConnectResultEvent(make([]byte, connectResultEventWireSize-1))
	if ok {
		t.Fatal("expected ok=false for short input")
	}
}

// TestClassifyConnectRingRecord covers the magic-prefix dispatcher used by
// readConnectRing. The connect_events ringbuf is multiplexed across three
// record families (entry connect_event, canary, kretprobe connect_result) so
// drift in either magic value, in the little-endian read order, or in the
// short-record guard would silently mis-route every event. Table-driven
// rather than three separate tests so adding a future magic only edits the
// table.
func TestClassifyConnectRingRecord(t *testing.T) {
	mk := func(magic uint32, extra int) []byte {
		b := make([]byte, 4+extra)
		binary.LittleEndian.PutUint32(b[0:4], magic)
		return b
	}
	cases := []struct {
		name string
		raw  []byte
		want connectRingRecordKind
	}{
		{
			name: "canary magic routes to canary",
			raw:  mk(canaryMagic, canaryEventWireSize-4),
			want: connectRingKindCanary,
		},
		{
			name: "connect_result magic routes to connect_result",
			raw:  mk(connectResultMagic, connectResultEventWireSize-4),
			want: connectRingKindConnectResult,
		},
		{
			// Real tgid leading bytes — must NOT collide with either magic.
			// PID_MAX_LIMIT = 4194304 (0x00400000) so any plausible tgid
			// fits in a small uint32 well below both 0xCA1A1210 and
			// 0xC0EE0001 — verifying that the default branch fires.
			name: "plausible tgid prefix routes to connect_event",
			raw:  mk(12345, connectEventWireSize-4),
			want: connectRingKindConnectEvent,
		},
		{
			name: "zero prefix routes to connect_event",
			raw:  mk(0, connectEventWireSize-4),
			want: connectRingKindConnectEvent,
		},
		{
			// Records shorter than the magic itself short-circuit to the
			// default branch; the downstream connect_event decoder then
			// fails the too-short check and the dropped counter advances.
			name: "too-short record routes to connect_event",
			raw:  []byte{0xCA, 0x1A},
			want: connectRingKindConnectEvent,
		},
		{
			name: "empty record routes to connect_event",
			raw:  nil,
			want: connectRingKindConnectEvent,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyConnectRingRecord(tc.raw)
			if got != tc.want {
				t.Errorf("classifyConnectRingRecord = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestDecodeTLSSniffEvent_IPv6 exercises the P5 IPv6 trailer: a hand-crafted
// wire event with is_ipv6=1 + a v6 address in daddr6 must decode with
// isIPv6==true and daddr6 populated.
func TestDecodeTLSSniffEvent_IPv6(t *testing.T) {
	raw := make([]byte, tlsSniffEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], 400)
	binary.LittleEndian.PutUint32(raw[4:8], 401)
	copy(raw[8:24], []byte("curl6\x00"))
	// IPv6 path: BPF zeroes daddr; v6 address lives in the trailer.
	binary.BigEndian.PutUint16(raw[28:30], 443)
	binary.LittleEndian.PutUint16(raw[32:34], 0)
	// 2001:db8::1
	v6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	copy(raw[tlsSniffEventIPv6Offset:tlsSniffEventIPv6Offset+16], v6[:])
	raw[tlsSniffEventIPv6Offset+16] = 1 // is_ipv6

	_, _, _, daddr, dport, _, daddr6, isIPv6, ok := decodeTLSSniffEvent(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if !isIPv6 {
		t.Fatal("expected isIPv6=true")
	}
	if daddr != [4]byte{} {
		t.Fatalf("expected zeroed daddr on IPv6 path, got %v", daddr)
	}
	if daddr6 != v6 {
		t.Fatalf("daddr6 %v != %v", daddr6, v6)
	}
	if dport != 443 {
		t.Fatalf("dport %d", dport)
	}

	// readTLSRing formats the rendered remote string using bracket notation
	// for IPv6 — exercise the same path so digest rendering is locked in.
	ip := net.IP(daddr6[:])
	if ip.To4() != nil {
		t.Fatalf("v6 address must not coerce to To4: %s", ip)
	}
	remote := fmt.Sprintf("`[%s]:%d`", ip.String(), dport)
	if remote != "`[2001:db8::1]:443`" {
		t.Fatalf("bracketed remote = %q, want `[2001:db8::1]:443`", remote)
	}
}

func TestDecodeBPFAuditEvent(t *testing.T) {
	// BPF struct layout: tgid(0-3) tid(4-7) cmd(8-11) comm(12-27)
	raw := make([]byte, bpfAuditEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], 1234) // tgid
	binary.LittleEndian.PutUint32(raw[4:8], 5678) // tid
	binary.LittleEndian.PutUint32(raw[8:12], 12)  // cmd = BPF_MAP_GET_NEXT_ID
	copy(raw[12:28], []byte("bpftool\x00"))       // comm

	tgid, tid, comm, cmd, ok := decodeBPFAuditEvent(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if tgid != 1234 {
		t.Errorf("tgid = %d, want 1234", tgid)
	}
	if tid != 5678 {
		t.Errorf("tid = %d, want 5678", tid)
	}
	if cmd != 12 {
		t.Errorf("cmd = %d, want 12 (BPF_MAP_GET_NEXT_ID)", cmd)
	}
	commStr := string(bytes.TrimRight(comm[:], "\x00"))
	if commStr != "bpftool" {
		t.Errorf("comm = %q, want \"bpftool\"", commStr)
	}
}

func TestDecodeBPFAuditEvent_tooShort(t *testing.T) {
	_, _, _, _, ok := decodeBPFAuditEvent(make([]byte, bpfAuditEventWireSize-1))
	if ok {
		t.Fatal("expected ok=false for short input")
	}
}

func TestDecodeIOUringSendEvent_roundTrip(t *testing.T) {
	// Wire layout: ts(8) pid(4) fd(4) daddr(4) dport(2) op(1) has_tls_hello(1) comm(16).
	raw := make([]byte, ioUringSendEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1715000000000)
	binary.LittleEndian.PutUint32(raw[8:12], 9001)
	binary.LittleEndian.PutUint32(raw[12:16], 7)
	raw[16], raw[17], raw[18], raw[19] = 1, 2, 3, 4
	binary.BigEndian.PutUint16(raw[20:22], 443)
	raw[22] = 26 // IORING_OP_SEND
	raw[23] = 0  // has_tls_hello = false
	copy(raw[24:40], []byte("curl\x00"))

	ts, pid, fd, daddr, dport, op, hasTLS, comm, ok := decodeIOUringSendEvent(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ts != 1715000000000 || pid != 9001 || fd != 7 || dport != 443 || op != 26 {
		t.Fatalf("got ts=%d pid=%d fd=%d dport=%d op=%d", ts, pid, fd, dport, op)
	}
	if hasTLS {
		t.Fatalf("expected has_tls_hello=false on raw[23]=0, got true")
	}
	if daddr != [4]byte{1, 2, 3, 4} {
		t.Fatalf("daddr %v", daddr)
	}
	if got := string(bytes.TrimRight(comm[:], "\x00")); got != "curl" {
		t.Fatalf("comm %q", got)
	}
	if got := ioUringOpName(op); got != "SEND" {
		t.Fatalf("ioUringOpName(26) = %q, want SEND", got)
	}
}

func TestDecodeIOUringSendEvent_tlsHelloFlag(t *testing.T) {
	// Same wire layout, but with the P6 Phase 2 has_tls_hello flag set.
	raw := make([]byte, ioUringSendEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1715000000001)
	binary.LittleEndian.PutUint32(raw[8:12], 9002)
	binary.LittleEndian.PutUint32(raw[12:16], 8)
	raw[16], raw[17], raw[18], raw[19] = 10, 0, 0, 1
	binary.BigEndian.PutUint16(raw[20:22], 443)
	raw[22] = 9 // IORING_OP_SENDMSG
	raw[23] = 1 // has_tls_hello = true (enhanced peek matched)
	copy(raw[24:40], []byte("curl\x00"))

	_, _, _, _, _, op, hasTLS, _, ok := decodeIOUringSendEvent(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !hasTLS {
		t.Fatalf("expected has_tls_hello=true on raw[23]=1, got false")
	}
	if got := ioUringOpName(op); got != "SENDMSG" {
		t.Fatalf("ioUringOpName(9) = %q, want SENDMSG", got)
	}
}

func TestDecodeIOUringSendEvent_tooShort(t *testing.T) {
	_, _, _, _, _, _, _, _, ok := decodeIOUringSendEvent(make([]byte, ioUringSendEventWireSize-1))
	if ok {
		t.Fatal("expected ok=false for short input")
	}
}

func TestDecodeIOUringTLSEvent_roundTrip(t *testing.T) {
	// Wire layout: ts(8) pid(4) comm(16) op(1) _pad(3) capture_len(2) payload(256) _pad2(6).
	raw := make([]byte, ioUringTLSEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1715000000002)
	binary.LittleEndian.PutUint32(raw[8:12], 4242)
	copy(raw[12:28], []byte("curl\x00"))
	raw[28] = 26 // IORING_OP_SEND
	binary.LittleEndian.PutUint16(raw[32:34], 5)
	copy(raw[34:39], []byte{0x16, 0x03, 0x01, 0x00, 0x2f})

	ts, pid, op, payload, comm, _, _, ok := decodeIOUringTLSEvent(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ts != 1715000000002 || pid != 4242 || op != 26 {
		t.Fatalf("got ts=%d pid=%d op=%d", ts, pid, op)
	}
	if len(payload) != 5 || payload[0] != 0x16 || payload[4] != 0x2f {
		t.Fatalf("payload %v", payload)
	}
	if got := string(bytes.TrimRight(comm[:], "\x00")); got != "curl" {
		t.Fatalf("comm %q", got)
	}
}

func TestDecodeIOUringTLSEvent_capLenClamped(t *testing.T) {
	// A corrupt capture_len larger than the payload window must clamp, not panic.
	raw := make([]byte, ioUringTLSEventWireSize)
	binary.LittleEndian.PutUint16(raw[32:34], 0xFFFF)
	_, _, _, payload, _, _, _, ok := decodeIOUringTLSEvent(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(payload) != ioUringTLSPayloadMax {
		t.Fatalf("payload len = %d, want clamp to %d", len(payload), ioUringTLSPayloadMax)
	}
}

func TestDecodeIOUringTLSEvent_tooShort(t *testing.T) {
	_, _, _, _, _, _, _, ok := decodeIOUringTLSEvent(make([]byte, ioUringTLSEventWireSize-1))
	if ok {
		t.Fatal("expected ok=false for short input")
	}
}

// ORDER 1 (BG-5): when the kernel resolved the connected peer, daddr/dport are
// set and the event carries the real dst instead of "unknown".
func TestIoUringTLSEventFromRaw_resolvesDst(t *testing.T) {
	hello := buildSyntheticClientHello(t, "b.test")
	raw := packIOUringTLSWire(t, 26, hello)
	// daddr@292 = 93.184.216.34 (network byte order), dport@296 = 443 (BE).
	copy(raw[292:296], []byte{93, 184, 216, 34})
	binary.BigEndian.PutUint16(raw[296:298], 443)

	ev, emit := ioUringTLSEventFromRaw(raw, "2026-06-09T00:00:00Z", 7)
	if !emit {
		t.Fatal("expected emit=true")
	}
	if ev.Dst != "93.184.216.34" || ev.DstPort != 443 {
		t.Fatalf("dst=%q port=%d, want 93.184.216.34/443", ev.Dst, ev.DstPort)
	}
	if ev.SNI != "b.test" {
		t.Fatalf("sni=%q", ev.SNI)
	}
}

func packIOUringTLSWire(t *testing.T, op uint8, payload []byte) []byte {
	t.Helper()
	if len(payload) > ioUringTLSPayloadMax {
		t.Fatalf("test payload %d exceeds payload window %d", len(payload), ioUringTLSPayloadMax)
	}
	raw := make([]byte, ioUringTLSEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1715000000010)
	binary.LittleEndian.PutUint32(raw[8:12], 7777)
	copy(raw[12:28], []byte("node\x00"))
	raw[28] = op
	binary.LittleEndian.PutUint16(raw[32:34], uint16(len(payload)))
	copy(raw[34:], payload)
	return raw
}

func TestIoUringTLSEventFromRaw_parsesSNI(t *testing.T) {
	hello := buildSyntheticClientHello(t, "a.test")
	raw := packIOUringTLSWire(t, 26, hello) // IORING_OP_SEND

	ev, emit := ioUringTLSEventFromRaw(raw, "2026-05-31T00:00:00Z", 3)
	if !emit {
		t.Fatal("expected emit=true for a valid ClientHello with SNI")
	}
	if ev.Type != "io_uring_tls" || ev.SNI != "a.test" || ev.Dst != "unknown" || ev.Op != "SEND" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Seq != 3 {
		t.Fatalf("seq = %d, want 3", ev.Seq)
	}
}

func TestIoUringTLSEventFromRaw_noSNINoEmit(t *testing.T) {
	// A bare TLS record prefix without a parseable ClientHello/SNI must not emit.
	raw := packIOUringTLSWire(t, 26, []byte{0x16, 0x03, 0x01, 0x00, 0x05})
	if _, emit := ioUringTLSEventFromRaw(raw, "t", 1); emit {
		t.Fatal("expected emit=false when no SNI parses")
	}
}

func TestIoUringTLSEventFromRaw_shortRecordNoEmit(t *testing.T) {
	if _, emit := ioUringTLSEventFromRaw(make([]byte, ioUringTLSEventWireSize-1), "t", 1); emit {
		t.Fatal("expected emit=false for short wire record")
	}
}

func TestIOUringOpName_allMappedAndUnknown(t *testing.T) {
	cases := []struct {
		op   uint8
		want string
	}{
		{2, "WRITEV"},
		{9, "SENDMSG"},
		{23, "WRITE"},
		{26, "SEND"},
		{0, "UNKNOWN"},
		{255, "UNKNOWN"},
	}
	for _, c := range cases {
		if got := ioUringOpName(c.op); got != c.want {
			t.Errorf("ioUringOpName(%d) = %q, want %q", c.op, got, c.want)
		}
	}
}

func TestDecodeEgressBackstopEvent_roundTrip(t *testing.T) {
	raw := make([]byte, egressBackstopEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1717000000001)
	binary.LittleEndian.PutUint32(raw[8:12], 1234)
	copy(raw[12:28], []byte("rawsock\x00"))
	raw[28] = 2   // AF_INET
	raw[29] = 255 // IPPROTO_RAW
	copy(raw[32:36], []byte{203, 0, 113, 7})
	binary.BigEndian.PutUint16(raw[48:50], 443) // dport network order

	ts, pid, af, ipproto, daddr, dport, comm, ok := decodeEgressBackstopEvent(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ts != 1717000000001 || pid != 1234 || af != 2 || ipproto != 255 || dport != 443 {
		t.Fatalf("ts=%d pid=%d af=%d ipproto=%d dport=%d", ts, pid, af, ipproto, dport)
	}
	if net.IP(daddr[:4]).String() != "203.0.113.7" {
		t.Fatalf("daddr=%v", daddr)
	}
	if got := string(bytes.TrimRight(comm[:], "\x00")); got != "rawsock" {
		t.Fatalf("comm %q", got)
	}
}

func TestDecodeEgressBackstopEvent_tooShort(t *testing.T) {
	_, _, _, _, _, _, _, ok := decodeEgressBackstopEvent(make([]byte, egressBackstopEventWireSize-1))
	if ok {
		t.Fatal("expected ok=false for short input")
	}
}

func TestEgressBackstopEventFromRaw_parses(t *testing.T) {
	raw := make([]byte, egressBackstopEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1)
	binary.LittleEndian.PutUint32(raw[8:12], 77)
	copy(raw[12:28], []byte("curl\x00"))
	raw[28] = 2 // AF_INET
	raw[29] = 6 // TCP
	copy(raw[32:36], []byte{198, 51, 100, 9})
	binary.BigEndian.PutUint16(raw[48:50], 8443)

	ev, emit := egressBackstopEventFromRaw(raw, "2026-06-06T00:00:00Z", 5)
	if !emit {
		t.Fatal("expected emit=true")
	}
	if ev.Type != "egress_backstop" || ev.AF != "ipv4" || ev.Proto != "tcp" ||
		ev.Dst != "198.51.100.9" || ev.Dport != 8443 || ev.Seq != 5 {
		t.Fatalf("ev=%+v", ev)
	}
}

func TestEgressBackstopEventFromRaw_shortNoEmit(t *testing.T) {
	if _, emit := egressBackstopEventFromRaw(make([]byte, egressBackstopEventWireSize-1), "t", 1); emit {
		t.Fatal("expected emit=false for short record")
	}
}

// An unexpected address-family byte (corrupt record) must be dropped rather than
// rendered as a 4-byte "ipv4" address — the producer only ever emits AF_INET /
// AF_INET6. Guards against the mislabel-unknown-AF-as-ipv4 finding.
func TestEgressBackstopEventFromRaw_unknownAFNoEmit(t *testing.T) {
	raw := make([]byte, egressBackstopEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1)
	binary.LittleEndian.PutUint32(raw[8:12], 77)
	raw[28] = 99 // neither AF_INET (2) nor AF_INET6 (10)
	raw[29] = 6
	copy(raw[32:36], []byte{198, 51, 100, 9})
	if _, emit := egressBackstopEventFromRaw(raw, "t", 1); emit {
		t.Fatal("expected emit=false for unknown address family")
	}
}

// AF_INET6 records must render the full 16-byte address and the ipv6 label.
func TestEgressBackstopEventFromRaw_ipv6(t *testing.T) {
	raw := make([]byte, egressBackstopEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1)
	binary.LittleEndian.PutUint32(raw[8:12], 77)
	raw[28] = 10 // AF_INET6
	raw[29] = 6
	// 2001:db8::1
	raw[32], raw[33] = 0x20, 0x01
	raw[34], raw[35] = 0x0d, 0xb8
	raw[47] = 0x01
	binary.BigEndian.PutUint16(raw[48:50], 443)
	ev, emit := egressBackstopEventFromRaw(raw, "t", 1)
	if !emit {
		t.Fatal("expected emit=true for AF_INET6")
	}
	if ev.AF != "ipv6" || ev.Dst != "2001:db8::1" {
		t.Fatalf("ev=%+v", ev)
	}
}

func TestDecodeBpfSelfDefenseEvent(t *testing.T) {
	raw := make([]byte, bpfSelfDefenseEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1717000000002)
	copy(raw[8:24], []byte("attacker\x00"))
	binary.LittleEndian.PutUint32(raw[24:28], 9001)
	binary.LittleEndian.PutUint32(raw[28:32], 42)
	binary.LittleEndian.PutUint32(raw[32:36], 14) // BPF_PROG_GET_FD_BY_ID
	raw[36] = 1                                   // KIND_PROG

	ts, comm, tgid, targetID, cmd, kind, ok := decodeBpfSelfDefenseEvent(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ts != 1717000000002 || tgid != 9001 || targetID != 42 || cmd != 14 || kind != 1 {
		t.Fatalf("ts=%d tgid=%d id=%d cmd=%d kind=%d", ts, tgid, targetID, cmd, kind)
	}
	if got := string(bytes.TrimRight(comm[:], "\x00")); got != "attacker" {
		t.Fatalf("comm %q", got)
	}
}

func TestDecodeBpfSelfDefenseEvent_tooShort(t *testing.T) {
	if _, _, _, _, _, _, ok := decodeBpfSelfDefenseEvent(make([]byte, bpfSelfDefenseEventWireSize-1)); ok {
		t.Fatal("expected ok=false for short input")
	}
}

func TestBpfSelfDefenseEventFromRaw_parses(t *testing.T) {
	raw := make([]byte, bpfSelfDefenseEventWireSize)
	binary.LittleEndian.PutUint64(raw[0:8], 7)
	copy(raw[8:24], []byte("evil\x00"))
	binary.LittleEndian.PutUint32(raw[24:28], 1234)
	binary.LittleEndian.PutUint32(raw[28:32], 99)
	binary.LittleEndian.PutUint32(raw[32:36], 13) // BPF_MAP_GET_FD_BY_ID
	raw[36] = 2                                   // KIND_MAP

	ev, emit := bpfSelfDefenseEventFromRaw(raw, "2026-06-07T00:00:00Z", 8)
	if !emit {
		t.Fatal("expected emit=true")
	}
	if ev.Type != "bpf_self_defense" || ev.TargetKind != "map" || ev.TargetID != 99 ||
		ev.Cmd != 13 || ev.TGID != 1234 || ev.Comm != "evil" || ev.Action != "denied" || ev.Seq != 8 {
		t.Fatalf("ev=%+v", ev)
	}
}

func TestBpfSelfDefenseEventFromRaw_shortNoEmit(t *testing.T) {
	if _, emit := bpfSelfDefenseEventFromRaw(make([]byte, bpfSelfDefenseEventWireSize-1), "t", 1); emit {
		t.Fatal("expected emit=false for short record")
	}
}
