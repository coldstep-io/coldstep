//go:build linux

package agent

import (
	"bytes"
	"encoding/binary"
	"testing"
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

	_, _, _, _, _, pay, ok := decodeTLSSniffEvent(raw)
	if !ok {
		t.Fatal("expected ok when capture_len == tlsPayloadMax")
	}
	if len(pay) != tlsPayloadMax {
		t.Fatalf("payload len %d", len(pay))
	}
}

func TestDecodeTLSSniffEvent_captureLenTooLarge(t *testing.T) {
	raw := make([]byte, tlsSniffEventWireSize)
	binary.LittleEndian.PutUint16(raw[32:34], tlsPayloadMax+1)
	_, _, _, _, _, _, ok := decodeTLSSniffEvent(raw)
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
	// result = -110 (-ETIMEDOUT) round-tripped through unsigned-bits.
	binary.LittleEndian.PutUint32(raw[4:8], uint32(int32(-110))) // #nosec G115 -- intentional reinterpret-cast for the wire round-trip //nolint:gosec
	binary.LittleEndian.PutUint32(raw[8:12], 1234)               // tgid
	binary.LittleEndian.PutUint32(raw[12:16], 1235)              // tid
	copy(raw[16:32], []byte("curl\x00"))                         // comm

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
	if result != -110 {
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
