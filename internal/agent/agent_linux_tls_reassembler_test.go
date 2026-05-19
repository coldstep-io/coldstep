//go:build linux

package agent

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildSyntheticClientHello mirrors internal/telemetry's helper of the same
// shape — kept private so test code in the agent package does not need a build
// dependency on telemetry's _test.go (Go does not export test helpers across
// packages).
func buildSyntheticClientHello(t *testing.T, host string) []byte {
	t.Helper()
	hb := []byte(host)
	if len(hb) == 0 || len(hb) > 200 {
		t.Fatalf("bad host %q", host)
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

func TestTLSReassembler_SingleBufferSuccess(t *testing.T) {
	r := newTLSReassembler()
	hello := buildSyntheticClientHello(t, "single.example")

	res := r.appendAndParse(tlsReassemblyKey{PID: 100, Dst: [4]byte{1, 2, 3, 4}, Dport: 443}, hello)
	if !res.parsed {
		t.Fatal("expected parsed=true on first buffer")
	}
	if res.sni != "single.example" {
		t.Fatalf("sni=%q", res.sni)
	}
	if res.reassembly {
		t.Fatal("expected reassembly=false on single-buffer success")
	}
	if got := r.len(); got != 0 {
		t.Fatalf("expected store to evict after parse; got %d entries", got)
	}
}

func TestTLSReassembler_SplitBufferReassembles(t *testing.T) {
	r := newTLSReassembler()
	hello := buildSyntheticClientHello(t, "split.example")
	if len(hello) < 6 {
		t.Fatalf("hello too short: %d", len(hello))
	}
	// Split the buffer such that the first write contains only the 5-byte TLS
	// record header (the Go crypto/tls / rustls path). The second write carries
	// the handshake body.
	first := hello[:5]
	second := hello[5:]
	key := tlsReassemblyKey{PID: 200, Dst: [4]byte{10, 0, 0, 1}, Dport: 443}

	if res := r.appendAndParse(key, first); res.parsed {
		t.Fatal("first 5 bytes must not be enough to recover SNI")
	}
	if r.len() != 1 {
		t.Fatalf("expected 1 buffered entry after header write; got %d", r.len())
	}

	res := r.appendAndParse(key, second)
	if !res.parsed {
		t.Fatal("expected reassembly to recover SNI after second write")
	}
	if res.sni != "split.example" {
		t.Fatalf("sni=%q", res.sni)
	}
	if !res.reassembly {
		t.Fatal("expected reassembly=true on multi-write success")
	}
	if r.len() != 0 {
		t.Fatalf("expected store to evict on success; got %d", r.len())
	}
}

func TestTLSReassembler_SplitAcrossThreeWrites(t *testing.T) {
	r := newTLSReassembler()
	hello := buildSyntheticClientHello(t, "three.example")
	if len(hello) < 9 {
		t.Fatalf("hello too short: %d", len(hello))
	}
	parts := [][]byte{hello[:3], hello[3:8], hello[8:]}
	key := tlsReassemblyKey{PID: 300, Dst: [4]byte{172, 16, 0, 5}, Dport: 8443}

	for i, p := range parts[:2] {
		res := r.appendAndParse(key, p)
		if res.parsed {
			t.Fatalf("part %d should not yet recover SNI", i)
		}
	}
	res := r.appendAndParse(key, parts[2])
	if !res.parsed || !res.reassembly || res.sni != "three.example" {
		t.Fatalf("final part: parsed=%v reassembly=%v sni=%q", res.parsed, res.reassembly, res.sni)
	}
}

func TestTLSReassembler_TimeoutEvictsStaleEntries(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	r := newTLSReassemblerWithClock(clock, 30*time.Second, 16, tlsReassemblyBufferCap)

	key := tlsReassemblyKey{PID: 400, Dst: [4]byte{8, 8, 8, 8}, Dport: 443}
	hello := buildSyntheticClientHello(t, "expire.example")
	if res := r.appendAndParse(key, hello[:5]); res.parsed {
		t.Fatal("header alone must not parse")
	}
	if r.len() != 1 {
		t.Fatalf("expected 1 entry, got %d", r.len())
	}

	now = now.Add(31 * time.Second)
	if got := r.sweep(); got != 1 {
		t.Fatalf("sweep evicted %d entries; want 1", got)
	}
	if r.len() != 0 {
		t.Fatalf("expected store empty after sweep; got %d", r.len())
	}

	// A late-arriving body for the now-evicted entry must be treated as a
	// fresh insertion: parsing the body alone fails, but we also must not
	// claim reassembly success on what is essentially a brand-new key.
	res := r.appendAndParse(key, hello[5:])
	if res.parsed {
		t.Fatal("body alone after eviction must not parse")
	}
	if res.reassembly {
		t.Fatal("reassembly flag must be false for the first write of a fresh key")
	}
}

func TestTLSReassembler_DropsNonHandshakeRecord(t *testing.T) {
	r := newTLSReassembler()
	key := tlsReassemblyKey{PID: 500, Dst: [4]byte{1, 1, 1, 1}, Dport: 443}

	// 0x17 = TLS application_data. The reassembler should not hold state for
	// this — it isn't a ClientHello and never will be.
	appData := []byte{0x17, 0x03, 0x03, 0x00, 0x20}
	for i := 0; i < 32; i++ {
		appData = append(appData, byte(i))
	}
	res := r.appendAndParse(key, appData)
	if res.parsed {
		t.Fatal("application_data must not parse as ClientHello")
	}
	if r.len() != 0 {
		t.Fatalf("expected non-handshake bytes to drop entry; got %d", r.len())
	}
}

func TestTLSReassembler_BufferCapBoundsMemory(t *testing.T) {
	r := newTLSReassemblerWithClock(time.Now, 30*time.Second, 16, 64)
	key := tlsReassemblyKey{PID: 600, Dst: [4]byte{4, 4, 4, 4}, Dport: 443}

	// Feed 256 bytes of valid-but-truncated handshake prefix in 32-byte chunks;
	// only the first 64 should be retained, after which appendAndParse stops
	// growing the buffer.
	chunk := make([]byte, 32)
	chunk[0] = 0x16
	chunk[1] = 0x03
	chunk[2] = 0x03
	chunk[3] = 0xff
	chunk[4] = 0xff
	for i := 0; i < 8; i++ {
		res := r.appendAndParse(key, chunk)
		if res.parsed {
			t.Fatalf("chunk %d unexpectedly parsed", i)
		}
		if res.bufferLen > 64 {
			t.Fatalf("buffer grew past cap: %d", res.bufferLen)
		}
	}
}
