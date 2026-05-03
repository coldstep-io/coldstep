//go:build linux

package agent

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// TestDNSCache_purgeExpiredDeletesBPFKey verifies H-03: expiring a cache entry
// propagates Delete to wired BPF dns_cache maps (LRU_HASH IPv4 key).
func TestDNSCache_purgeExpiredDeletesBPFKey(t *testing.T) {
	spec := &ebpf.MapSpec{
		Name:       "coldstep_test_dns_cache",
		Type:       ebpf.LRUHash,
		KeySize:    4,
		ValueSize:  256,
		MaxEntries: 16,
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("ebpf map unavailable: %v", err)
	}
	defer m.Close()

	orig := dnsNow
	defer func() { dnsNow = orig }()
	t0 := time.Unix(50_000, 0).UTC()
	dnsNow = func() time.Time { return t0 }

	c := NewDNSCache()
	c.SetBPFMaps([]*ebpf.Map{m})
	pkt := dnsReplySingleA([4]byte{7, 7, 7, 7}, 'q', 1)
	c.AddFromPacket(pkt)

	var k [4]byte
	copy(k[:], net.IPv4(7, 7, 7, 7).To4())
	var v [256]byte
	if err := m.Lookup(&k, &v); err != nil {
		t.Fatalf("expected key in map after add: %v", err)
	}

	dnsNow = func() time.Time { return t0.Add(10 * time.Second) }
	c.mu.Lock()
	c.purgeExpiredLocked(dnsNow().Unix())
	c.mu.Unlock()

	if err := m.Lookup(&k, &v); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("expected key deleted from bpf map, got err=%v", err)
	}
}
