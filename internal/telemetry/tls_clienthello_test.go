package telemetry

import (
	"encoding/binary"
	"testing"
)

func buildSyntheticClientHelloWithSNI(host string) []byte {
	hb := []byte(host)
	if len(hb) == 0 || len(hb) > 200 {
		return nil
	}
	listLen := 1 + 2 + len(hb)
	extVal := make([]byte, 2+listLen)
	binary.BigEndian.PutUint16(extVal[0:2], uint16(listLen))
	extVal[2] = 0
	binary.BigEndian.PutUint16(extVal[3:5], uint16(len(hb)))
	copy(extVal[5:], hb)
	extBlock := make([]byte, 4+len(extVal))
	binary.BigEndian.PutUint16(extBlock[0:2], 0)
	binary.BigEndian.PutUint16(extBlock[2:4], uint16(len(extVal)))
	copy(extBlock[4:], extVal)

	ch := make([]byte, 0, 256)
	ch = append(ch, 0x03, 0x03)
	ch = append(ch, make([]byte, 32)...)
	ch = append(ch, 0)
	ch = append(ch, 0x00, 0x02, 0x13, 0x01)
	ch = append(ch, 0x01, 0x00)
	extLen := uint16(len(extBlock))
	ch = append(ch, byte(extLen>>8), byte(extLen))
	ch = append(ch, extBlock...)

	chLen := len(ch)
	hs := make([]byte, 0, 4+chLen)
	hs = append(hs, 0x01)
	hs = append(hs, byte(chLen>>16), byte(chLen>>8), byte(chLen))
	hs = append(hs, ch...)

	recBody := hs
	recLen := len(recBody)
	out := make([]byte, 0, 5+recLen)
	out = append(out, 0x16, 0x03, 0x01, byte(recLen>>8), byte(recLen))
	out = append(out, recBody...)
	return out
}

func TestIsTLSClientHelloMagic(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"empty buffer", []byte{}, false},
		{"too short — 5 bytes can't include offset 5", []byte{0x16, 0x03, 0x01, 0x00, 0x00}, false},
		{
			"valid TLS 1.0 ClientHello prefix",
			[]byte{0x16, 0x03, 0x01, 0x00, 0xff, 0x01},
			true,
		},
		{
			"valid TLS 1.3 record-version with ClientHello",
			[]byte{0x16, 0x03, 0x03, 0x01, 0x00, 0x01},
			true,
		},
		{
			"wrong ContentType — application data not handshake",
			[]byte{0x17, 0x03, 0x01, 0x00, 0xff, 0x01},
			false,
		},
		{
			"wrong record-version major byte (0x02, not 0x03)",
			[]byte{0x16, 0x02, 0x01, 0x00, 0xff, 0x01},
			false,
		},
		{
			"handshake but ServerHello not ClientHello",
			[]byte{0x16, 0x03, 0x01, 0x00, 0xff, 0x02},
			false,
		},
		{
			"trailing bytes after magic are ignored",
			append([]byte{0x16, 0x03, 0x03, 0x00, 0xff, 0x01}, make([]byte, 100)...),
			true,
		},
		{
			"synthetic ClientHello buildSyntheticClientHelloWithSNI parses as magic",
			buildSyntheticClientHelloWithSNI("example.com"),
			true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := IsTLSClientHelloMagic(tc.in)
			if got != tc.want {
				t.Fatalf("IsTLSClientHelloMagic(%v bytes) = %v, want %v", len(tc.in), got, tc.want)
			}
		})
	}
}

func TestParseClientHelloSNI_Minimal(t *testing.T) {
	ch := buildSyntheticClientHelloWithSNI("ex.example")
	if ch == nil {
		t.Fatal("nil hello")
	}
	sni, ok := ParseClientHelloSNI(ch)
	if !ok {
		t.Fatal("expected ok")
	}
	if sni != "ex.example" {
		t.Fatalf("sni=%q", sni)
	}
}

func TestParseClientHelloSNI_TruncatedRecord(t *testing.T) {
	// A full TLS 1.3 ClientHello from curl is typically 280-400 bytes; BPF captures only
	// the first 256 bytes. Verify that SNI is still extracted from a truncated buffer.
	full := buildSyntheticClientHelloWithSNI("truncated.example")
	if full == nil {
		t.Fatal("nil hello")
	}
	// Pad the synthetic hello to simulate a real larger hello that exceeds the 256-byte cap.
	// Extend by appending fake extension bytes so recLen reports a larger value.
	// Need full+pad > 256 to actually exercise the truncation path.
	extPad := make([]byte, 200)
	for i := range extPad {
		extPad[i] = 0xab
	}
	// Rewrite the record: increase record length header, append padding, then truncate to 256.
	raw := make([]byte, len(full)+len(extPad))
	copy(raw, full)
	copy(raw[len(full):], extPad)
	newRecLen := int(binary.BigEndian.Uint16(raw[3:5])) + len(extPad)
	binary.BigEndian.PutUint16(raw[3:5], uint16(newRecLen))
	truncated := raw
	if len(truncated) > 256 {
		truncated = raw[:256]
	}
	sni, ok := ParseClientHelloSNI(truncated)
	if !ok {
		t.Fatalf("expected SNI to be parsed from truncated record (len=%d, recLen=%d)", len(truncated), newRecLen)
	}
	if sni != "truncated.example" {
		t.Fatalf("sni=%q, want truncated.example", sni)
	}
}

func TestParseClientHelloSNI_RejectsApplicationDataRecord(t *testing.T) {
	// TLS application data record (type 0x17), long enough to pass initial length gates
	// but handshake type is not ClientHello.
	payload := make([]byte, 40)
	for i := range payload {
		payload[i] = 0xab
	}
	buf := []byte{0x17, 0x03, 0x03, 0x00, byte(len(payload))}
	buf = append(buf, payload...)
	if len(buf) < 43 {
		t.Fatalf("buffer too short: %d", len(buf))
	}
	if _, ok := ParseClientHelloSNI(buf); ok {
		t.Fatal("expected false for non-handshake record")
	}
}
