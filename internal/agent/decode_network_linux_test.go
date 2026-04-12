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
