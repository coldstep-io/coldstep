package agent

import (
	"net"
	"testing"
	"time"
)

func TestTTLToExpiry_clamps(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	if ttlToExpiry(0, now) != now.Add(300*time.Second).Unix() {
		t.Fatal("zero ttl should use default")
	}
	if ttlToExpiry(999_999, now) != now.Add(3600*time.Second).Unix() {
		t.Fatal("huge ttl should clamp to 3600s")
	}
}

func TestDNSCache_expires(t *testing.T) {
	orig := dnsNow
	defer func() { dnsNow = orig }()
	t0 := time.Unix(10_000, 0).UTC()
	dnsNow = func() time.Time { return t0 }

	c := NewDNSCache()
	pkt := minimalResponseWWWExample()
	c.AddFromPacket(pkt)
	ip := net.IPv4(93, 184, 216, 34)
	if c.Lookup(ip) != "www.example.com" {
		t.Fatalf("lookup: %q", c.Lookup(ip))
	}

	dnsNow = func() time.Time { return t0.Add(400 * time.Second) }
	if c.Lookup(ip) != "" {
		t.Fatal("expected expired")
	}
}

func TestDNSCache_maxEntriesEviction(t *testing.T) {
	orig := dnsNow
	defer func() { dnsNow = orig }()
	t0 := time.Unix(20_000, 0).UTC()
	dnsNow = func() time.Time { return t0 }

	c := NewDNSCache()
	c.maxEntries = 3
	// Three distinct IPs, TTL 3600 so they stay valid
	for i, ipb := range [][4]byte{{1, 1, 1, 1}, {2, 2, 2, 2}, {3, 3, 3, 3}} {
		pkt := dnsReplySingleA(ipb, byte('a'+i), 3600)
		c.AddFromPacket(pkt)
	}
	if len(c.entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(c.entries))
	}
	// Fourth forces eviction (one dropped)
	pkt4 := dnsReplySingleA([4]byte{4, 4, 4, 4}, 'z', 3600)
	c.AddFromPacket(pkt4)
	if len(c.entries) != 3 {
		t.Fatalf("want cap 3, got %d", len(c.entries))
	}
}

// dnsReplySingleA builds minimal response: Q foo., one A RR ip with owner "x" + single label from byte.
func dnsReplySingleA(ip [4]byte, label byte, ttl uint32) []byte {
	b := []byte{
		0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x03, 'f', 'o', 'o', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	b = append(b, 0x01, label, 0x00)
	b = append(b, 0x00, 0x01, 0x00, 0x01,
		byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
		0x00, 0x04)
	b = append(b, ip[:]...)
	return b
}
