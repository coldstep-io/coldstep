package agent

import (
	"net"
	"sync"
	"time"
)

// dnsNow is wall clock for TTL expiry (tests may replace).
var dnsNow = time.Now

const (
	dnsMaxEntries = 4096
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
}

func NewDNSCache() *DNSCache {
	return &DNSCache{
		entries:    make(map[[4]byte]dnsEntry),
		maxEntries: dnsMaxEntries,
	}
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
			break
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
		if ok && now.Unix() < prev.expires && len(ans.name) >= len(prev.name) {
			continue
		}
		c.entries[ip] = dnsEntry{name: ans.name, expires: exp}
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
