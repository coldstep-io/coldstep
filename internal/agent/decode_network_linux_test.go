//go:build linux

package agent

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDecodeUDPSendEvent(t *testing.T) {
	raw := make([]byte, 34)
	binary.LittleEndian.PutUint32(raw[0:4], 100)
	binary.LittleEndian.PutUint32(raw[4:8], 101)
	copy(raw[8:24], []byte("myproc\x00"))
	raw[24], raw[25], raw[26], raw[27] = 8, 8, 8, 8
	binary.BigEndian.PutUint16(raw[28:30], 53)
	binary.LittleEndian.PutUint32(raw[30:34], 512)

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
	_, _, _, _, _, _, ok := decodeUDPSendEvent(make([]byte, 33))
	if ok {
		t.Fatal("expected false")
	}
}

func TestDecodeHTTPSniffEvent(t *testing.T) {
	raw := make([]byte, 226)
	binary.LittleEndian.PutUint32(raw[0:4], 200)
	binary.LittleEndian.PutUint32(raw[4:8], 201)
	copy(raw[8:24], []byte("curl\x00"))
	raw[24], raw[25], raw[26], raw[27] = 1, 1, 1, 1
	binary.BigEndian.PutUint16(raw[28:30], 80)
	payload := []byte("GET / HTTP/1.1\r\nHost: ex\r\n")
	binary.LittleEndian.PutUint16(raw[32:34], uint16(len(payload)))
	copy(raw[34:], payload)

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
	raw := make([]byte, 226)
	binary.LittleEndian.PutUint16(raw[32:34], 193)
	_, _, _, _, _, _, ok := decodeHTTPSniffEvent(raw)
	if ok {
		t.Fatal("expected false for capLen > 192")
	}
}

func TestDecodeHTTPSniffEvent_tooShort(t *testing.T) {
	_, _, _, _, _, _, ok := decodeHTTPSniffEvent(make([]byte, 100))
	if ok {
		t.Fatal("expected false")
	}
}

func TestDecodeTLSSniffEvent_captureLenAtMax(t *testing.T) {
	const header = 4 + 4 + 16 + 4 + 2 + 2 + 2
	const expect = header + tlsPayloadMax
	raw := make([]byte, expect)
	binary.LittleEndian.PutUint32(raw[0:4], 300)
	binary.LittleEndian.PutUint32(raw[4:8], 301)
	copy(raw[8:24], []byte("tlscli\x00"))
	raw[24], raw[25], raw[26], raw[27] = 9, 9, 9, 9
	binary.BigEndian.PutUint16(raw[28:30], 443)
	// Syscall may pass len > tlsPayloadMax; BPF caps capture_len to tlsPayloadMax.
	binary.LittleEndian.PutUint16(raw[32:34], tlsPayloadMax)
	for i := 0; i < tlsPayloadMax; i++ {
		raw[34+i] = byte(i)
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
	const header = 4 + 4 + 16 + 4 + 2 + 2 + 2
	raw := make([]byte, header+tlsPayloadMax)
	binary.LittleEndian.PutUint16(raw[32:34], tlsPayloadMax+1)
	_, _, _, _, _, _, ok := decodeTLSSniffEvent(raw)
	if ok {
		t.Fatal("expected false for capLen > tlsPayloadMax")
	}
}
