package agent

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// dnsNow is wall clock for TTL expiry (tests may replace).
var dnsNow = time.Now

const (
	// dnsMaxEntries matches MAX_ENTRIES in bpf/dns_cache.h so userspace
	// eviction is sized identically to the kernel-side LRU map. See M-10.
	dnsMaxEntries = 8192
	dnsMaxTTLSec  = 3600
	dnsDefaultTTL = 300
	dnsMinTTLSec  = 1
)

type dnsEntry struct {
	name    string
	expires int64 // unix seconds
}

// DNSCache maps resolved IPv4 addresses to a DNS owner name from sniffed responses,
// with TTL-based expiry and a hard entry cap.
type DNSCache struct {
	mu         sync.RWMutex
	entries    map[[4]byte]dnsEntry
	maxEntries int
	bpfMaps    []*ebpf.Map
	// onBPFFailure is bumped on every BPF map Update or Delete that returns
	// a non-ignored error; agents wire this to a stats counter so partial
	// sync between userspace and kernel is observable in digests.
	onBPFFailure func()
}

func NewDNSCache() *DNSCache {
	return &DNSCache{
		entries:    make(map[[4]byte]dnsEntry),
		maxEntries: dnsMaxEntries,
	}
}

func (c *DNSCache) SetBPFMaps(maps []*ebpf.Map) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bpfMaps = maps
}

// SetBPFFailureCallback registers a callback invoked once per failed BPF
// dns_cache map mutation (Update or non-ErrKeyNotExist Delete). Pass nil to
// clear. Safe to call before or after SetBPFMaps.
func (c *DNSCache) SetBPFFailureCallback(cb func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onBPFFailure = cb
}

func ttlToExpiry(ttl uint32, now time.Time) int64 {
	sec := ttl
	if sec == 0 {
		sec = dnsDefaultTTL
	}
	if sec > dnsMaxTTLSec {
		sec = dnsMaxTTLSec
	}
	if sec < dnsMinTTLSec {
		sec = dnsMinTTLSec
	}
	return now.Add(time.Duration(sec) * time.Second).Unix()
}

func (c *DNSCache) purgeExpiredLocked(nowUnix int64) {
	for k, e := range c.entries {
		if e.expires <= nowUnix {
			delete(c.entries, k)
			c.deleteBPFMapsLocked(k)
		}
	}
}

func (c *DNSCache) trimLocked(now time.Time) {
	for len(c.entries) > c.maxEntries {
		c.purgeExpiredLocked(now.Unix())
		if len(c.entries) <= c.maxEntries {
			break
		}
		for k := range c.entries {
			delete(c.entries, k)
			c.deleteBPFMapsLocked(k)
			break
		}
	}
}

// deleteBPFMapsLocked removes ip from every registered BPF dns_cache map.
// Mirrors the bpfKey shape used by AddFromPacket so userspace and kernel
// stay in sync on eviction (H-03). Tolerates ErrKeyNotExist silently; other
// failures are logged with structured context and fed to the failure
// callback (M-09).
func (c *DNSCache) deleteBPFMapsLocked(ip [4]byte) {
	if len(c.bpfMaps) == 0 {
		return
	}
	var bpfKey [4]byte
	copy(bpfKey[:], ip[:])
	for i, bpfMap := range c.bpfMaps {
		if bpfMap == nil {
			continue
		}
		if err := bpfMap.Delete(&bpfKey); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			ipString := net.IP(ip[:]).String()
			slog.Warn("dns cache BPF map delete failed",
				"map_index", i, "ip", ipString, "err", err)
			if c.onBPFFailure != nil {
				c.onBPFFailure()
			}
		}
	}
}

func (c *DNSCache) AddFromPacket(packet []byte) {
	m := parseDNSResponseIPv4(packet)
	if len(m) == 0 {
		return
	}
	now := dnsNow()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeExpiredLocked(now.Unix())
	for ip, ans := range m {
		exp := ttlToExpiry(ans.ttl, now)
		prev, ok := c.entries[ip]
		if ok && now.Unix() < prev.expires {
			switch {
			case ans.name == prev.name:
				// Same owner — refresh TTL only, skip BPF Update churn (M-08).
				c.entries[ip] = dnsEntry{name: ans.name, expires: exp}
				continue
			case len(ans.name) > len(prev.name):
				// Existing entry still valid and shorter; preserve it (M-08).
				continue
			}
		}
		c.entries[ip] = dnsEntry{name: ans.name, expires: exp}

		// Update BPF maps for in-kernel enrichment/enforcement.
		if len(c.bpfMaps) > 0 {
			var bpfKey [4]byte
			copy(bpfKey[:], ip[:])
			var bpfVal [256]byte
			copy(bpfVal[:], ans.name)
			for i, bpfMap := range c.bpfMaps {
				if bpfMap == nil {
					continue
				}
				if err := bpfMap.Update(&bpfKey, &bpfVal, ebpf.UpdateAny); err != nil {
					ipString := net.IP(ip[:]).String()
					slog.Warn("dns cache BPF map update failed",
						"map_index", i, "ip", ipString, "err", err)
					if c.onBPFFailure != nil {
						c.onBPFFailure()
					}
				}
			}
		}
	}
	c.trimLocked(now)
}

func (c *DNSCache) Lookup(ip net.IP) string {
	name, _ := c.LookupProvenance(ip)
	return name
}

// LookupProvenance returns a cached owner name from observed DNS replies and how it was obtained.
func (c *DNSCache) LookupProvenance(ip net.IP) (fqdn string, provenance string) {
	v4 := ip.To4()
	if v4 == nil {
		return "", "unknown"
	}
	var k [4]byte
	copy(k[:], v4)
	c.mu.RLock()
	e, ok := c.entries[k]
	c.mu.RUnlock()
	if !ok || dnsNow().Unix() >= e.expires {
		return "", "unknown"
	}
	return e.name, "dns_observed"
}
