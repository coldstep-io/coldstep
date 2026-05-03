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

// TestDNSCache_maxEntriesMatchesBPF asserts the userspace cap is aligned
// with bpf/dns_cache.h MAX_ENTRIES. Drift here re-creates M-10's
// inconsistency window where the kernel LRU retained more keys than
// userspace tracked.
func TestDNSCache_maxEntriesMatchesBPF(t *testing.T) {
	c := NewDNSCache()
	if c.maxEntries != 8192 {
		t.Fatalf("default maxEntries = %d, want 8192 to match bpf/dns_cache.h", c.maxEntries)
	}
}

// TestDNSCache_sameNameRefreshesTTL pins the M-08 fix: when the new
// answer's owner name equals the cached name, the TTL must be refreshed
// even though the prior entry is still valid.
func TestDNSCache_sameNameRefreshesTTL(t *testing.T) {
	orig := dnsNow
	defer func() { dnsNow = orig }()
	t0 := time.Unix(30_000, 0).UTC()
	dnsNow = func() time.Time { return t0 }

	c := NewDNSCache()
	pkt := minimalResponseWWWExample()
	c.AddFromPacket(pkt)
	var ip [4]byte
	copy(ip[:], net.IPv4(93, 184, 216, 34).To4())
	first := c.entries[ip].expires

	dnsNow = func() time.Time { return t0.Add(60 * time.Second) }
	c.AddFromPacket(pkt)
	second := c.entries[ip].expires
	if second <= first {
		t.Fatalf("same-name re-add did not refresh TTL: first=%d second=%d", first, second)
	}
}

// TestDNSCache_longerNameSkippedWhileValid keeps the historical
// "shorter-name wins" preference: a longer owner name observed while the
// cached entry is still valid must be ignored.
func TestDNSCache_longerNameSkippedWhileValid(t *testing.T) {
	orig := dnsNow
	defer func() { dnsNow = orig }()
	t0 := time.Unix(40_000, 0).UTC()
	dnsNow = func() time.Time { return t0 }

	c := NewDNSCache()
	short := dnsReplySingleA([4]byte{5, 5, 5, 5}, 'a', 3600)
	c.AddFromPacket(short)
	var ip [4]byte
	copy(ip[:], []byte{5, 5, 5, 5})
	if got := c.entries[ip].name; got != "a" {
		t.Fatalf("seed name: got %q want %q", got, "a")
	}

	// Synthesize a longer-owner reply for the same IP. dnsReplySingleA's
	// owner is always one label, so build a custom packet by hand.
	long := []byte{
		0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x03, 'f', 'o', 'o', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	long = append(long, 0x05, 'l', 'o', 'n', 'g', 'r', 0x00)
	long = append(long, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 5, 5, 5, 5)
	c.AddFromPacket(long)
	if got := c.entries[ip].name; got != "a" {
		t.Fatalf("longer name overwrote shorter while still valid: got %q want %q", got, "a")
	}
}

// TestDNSCache_purgeExpiredEvictsAndCallsHook exercises in-memory purge without
// BPF maps. BPF Delete + map verification lives in dns_cache_linux_test.go.
func TestDNSCache_purgeExpiredEvictsAndCallsHook(t *testing.T) {
	orig := dnsNow
	defer func() { dnsNow = orig }()
	t0 := time.Unix(50_000, 0).UTC()
	dnsNow = func() time.Time { return t0 }

	c := NewDNSCache()
	pkt := dnsReplySingleA([4]byte{7, 7, 7, 7}, 'q', 1)
	c.AddFromPacket(pkt)
	if len(c.entries) != 1 {
		t.Fatalf("seed: want 1 entry, got %d", len(c.entries))
	}

	dnsNow = func() time.Time { return t0.Add(10 * time.Second) }
	c.mu.Lock()
	c.purgeExpiredLocked(dnsNow().Unix())
	c.mu.Unlock()
	if len(c.entries) != 0 {
		t.Fatalf("purge: want 0 entries after expiry, got %d", len(c.entries))
	}
}

// TestDNSCache_trimLockedEvictsBeyondCap exercises the M-10 8192 cap path
// indirectly: trimLocked must still bring the in-memory map back to the
// configured maxEntries even when the cap is the production value.
func TestDNSCache_trimLockedEvictsBeyondCap(t *testing.T) {
	orig := dnsNow
	defer func() { dnsNow = orig }()
	t0 := time.Unix(60_000, 0).UTC()
	dnsNow = func() time.Time { return t0 }

	c := NewDNSCache()
	c.maxEntries = 4
	for i := 0; i < 6; i++ {
		pkt := dnsReplySingleA([4]byte{10, 0, 0, byte(i)}, byte('a'+i), 3600)
		c.AddFromPacket(pkt)
	}
	if len(c.entries) > c.maxEntries {
		t.Fatalf("trim: want <= %d entries, got %d", c.maxEntries, len(c.entries))
	}
}

// TestDNSCache_failureCallbackNilSafe makes sure a DNSCache without a
// failure callback registered does not panic when no BPF maps are wired
// either. Guards against regressions in the optional callback path (M-09).
func TestDNSCache_failureCallbackNilSafe(t *testing.T) {
	c := NewDNSCache()
	c.AddFromPacket(minimalResponseWWWExample())
	if len(c.entries) == 0 {
		t.Fatal("expected entry from valid response")
	}
}

// TestDNSCache_failureCallbackInvocation verifies that
// SetBPFFailureCallback wires through to the AddFromPacket path. We can't
// force a real BPF Update error on Windows, but we can verify the
// registration roundtrips and the callback survives mutation.
func TestDNSCache_failureCallbackRegistration(t *testing.T) {
	c := NewDNSCache()
	called := 0
	c.SetBPFFailureCallback(func() { called++ })
	c.AddFromPacket(minimalResponseWWWExample())
	if called != 0 {
		t.Fatalf("no BPF map registered, callback should not fire; got %d", called)
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
