package agent

import (
	"net"
	"testing"
	"time"
)

// minimalResponseWWWExample builds a valid DNS reply: 1x Q www.example.com A, 1x A 93.184.216.34 TTL 300.
func minimalResponseWWWExample() []byte {
	return []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		// question www.example.com IN A
		0x03, 'w', 'w', 'w',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, 0x00, 0x01,
		// answer: ptr to question name, A, IN, TTL=300, rdlen=4
		0xc0, 0x0c,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x2c,
		0x00, 0x04,
		93, 184, 216, 34,
	}
}

func TestParseDNSResponseIPv4_exampleA(t *testing.T) {
	pkt := minimalResponseWWWExample()
	got := parseDNSResponseIPv4(pkt)
	var wantIP [4]byte
	copy(wantIP[:], net.IPv4(93, 184, 216, 34).To4())
	ans, ok := got[wantIP]
	if !ok {
		t.Fatalf("missing A for 93.184.216.34, got %#v", got)
	}
	if ans.name != "www.example.com" {
		t.Fatalf("name: got %q want www.example.com", ans.name)
	}
	if ans.ttl != 300 {
		t.Fatalf("ttl: got %d want 300", ans.ttl)
	}
}

func TestParseDNSResponseIPv4_notQueryResponse(t *testing.T) {
	pkt := minimalResponseWWWExample()
	pkt[2] &^= 0x80 // clear QR
	if len(parseDNSResponseIPv4(pkt)) != 0 {
		t.Fatal("expected empty map when QR=0")
	}
}

func TestParseDNSResponseIPv4_tooShort(t *testing.T) {
	if len(parseDNSResponseIPv4([]byte{1, 2, 3})) != 0 {
		t.Fatal("expected empty for short packet")
	}
}

func TestParseDNSResponseIPv4_noAnswers(t *testing.T) {
	pkt := []byte{
		0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'f', 'o', 'o', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	if len(parseDNSResponseIPv4(pkt)) != 0 {
		t.Fatal("expected empty when ANCOUNT=0")
	}
}

func TestParseDNSResponseIPv4_twoAsSameIPKeepsShorterName(t *testing.T) {
	// Two A RRs for 9.9.9.9: first owner aaaa.example.com, then b.example.com — shorter name wins.
	b := []byte{
		0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x01, 'z', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	// aaaa.example.com
	b = append(b, 0x04, 'a', 'a', 'a', 'a', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00)
	b = append(b, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 9, 9, 9, 9)
	// b.example.com
	b = append(b, 0x01, 'b', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00)
	b = append(b, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 9, 9, 9, 9)

	got := parseDNSResponseIPv4(b)
	var ip [4]byte
	copy(ip[:], net.IPv4(9, 9, 9, 9).To4())
	ans := got[ip]
	if ans.name != "b.example.com" {
		t.Fatalf("want shorter owner b.example.com, got %q", ans.name)
	}
}

func TestReadDNSName_compression(t *testing.T) {
	pkt := minimalResponseWWWExample()
	name, _, ok := readDNSName(pkt, 0x0c)
	if !ok || name != "www.example.com" {
		t.Fatalf("readDNSName: ok=%v name=%q", ok, name)
	}
}

func TestReadDNSName_PointerLoopReturnsFalse(t *testing.T) {
	packet := make([]byte, 32)
	packet[12] = 0xC0
	packet[13] = 0x0C // 14-bit pointer to offset 12 (self-loop)
	name, _, ok := readDNSName(packet, 12)
	if ok {
		t.Fatalf("expected failure for pointer loop, got %q", name)
	}
}

func TestReadDNSName_DeepPointerChainFailsBudget(t *testing.T) {
	packet := make([]byte, 256)
	for off := 12; off < 100; off += 2 {
		packet[off] = 0xC0
		packet[off+1] = byte(off + 2)
	}
	packet[100] = 0xC0
	packet[101] = 102
	packet[102] = 0
	name, _, ok := readDNSName(packet, 12)
	if ok {
		t.Fatalf("expected failure for deep pointer chain, got %q", name)
	}
}

func TestJoinDNSLabels(t *testing.T) {
	if got := joinDNSLabels([]string{"a", "b"}); got != "a.b" {
		t.Fatal(got)
	}
	if joinDNSLabels(nil) != "" {
		t.Fatal("empty")
	}
}

// TestParseDNSResponseIPv4_hugeCountsBoundedByPacketSize pins M-11: a tiny
// packet advertising a uint16-max QD/AN count must short-circuit before
// running the full parse loop. We assert (a) the result is empty (parser
// rejects the packet) and (b) the total work fits well under what an
// unbounded ancount=65535 loop with full readDNSName/bounds checks would
// have done — measured by walltime ceiling.
func TestParseDNSResponseIPv4_hugeCountsBoundedByPacketSize(t *testing.T) {
	pkt := []byte{
		0x00, 0x01, 0x81, 0x80,
		0xff, 0xff, // QDCOUNT = 65535
		0xff, 0xff, // ANCOUNT = 65535
		0x00, 0x00, 0x00, 0x00,
	}
	deadline := time.Now().Add(250 * time.Millisecond)
	out := parseDNSResponseIPv4(pkt)
	if len(out) != 0 {
		t.Fatalf("malicious huge-count packet should yield empty map, got %#v", out)
	}
	if time.Now().After(deadline) {
		t.Fatal("parser exceeded 250ms budget on malicious packet — bound is not effective")
	}
}

// TestParseDNSResponseIPv4_anCountFitsInPacketStillParses ensures the cap
// only rejects physically-impossible counts; legitimate small responses
// where ancount < len(packet)/dnsMinRRSize still parse normally.
func TestParseDNSResponseIPv4_anCountFitsInPacketStillParses(t *testing.T) {
	pkt := minimalResponseWWWExample()
	got := parseDNSResponseIPv4(pkt)
	if len(got) != 1 {
		t.Fatalf("expected one A record, got %d", len(got))
	}
}

func TestParseDNSResponseIPv4_typeAAAAIgnored(t *testing.T) {
	onlyAAAA := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c,
		0x00, 0x1c, 0x00, 0x01, // type AAAA
		0x00, 0x00, 0x01, 0x2c,
		0x00, 0x10,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	}
	if len(parseDNSResponseIPv4(onlyAAAA)) != 0 {
		t.Fatal("AAAA-only should yield no IPv4 map entries")
	}
}
