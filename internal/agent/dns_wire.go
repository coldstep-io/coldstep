package agent

import (
	"encoding/binary"
)

const (
	dnsNameMaxPointerDepth = 32
	dnsNameMaxLabelSteps   = 128
	// dnsMinRRSize is a conservative lower bound for the wire size of a
	// single resource record. The smallest plausible RR encoding is a
	// 1-byte name terminator (root) followed by 10 bytes of fixed RR
	// header (type, class, ttl, rdlength), so any RR consumes at least
	// 11 bytes. Using 4 here as a safety floor under-counts so the bound
	// stays generous; the real per-iteration parser still rejects shorter
	// records via existing bounds checks.
	dnsMinRRSize = 4
)

// ipv4DNSAnswer is one A record worth of metadata from a DNS response.
type ipv4DNSAnswer struct {
	name string
	ttl  uint32 // seconds from the RR (may be clamped when applied to wall clock)
}

// parseDNSResponseIPv4 maps IPv4 addresses to owner names and TTLs from DNS response A records.
func parseDNSResponseIPv4(packet []byte) map[[4]byte]ipv4DNSAnswer {
	out := make(map[[4]byte]ipv4DNSAnswer)
	if len(packet) < 12 {
		return out
	}
	if packet[2]&0x80 == 0 {
		return out
	}
	qdcount := int(binary.BigEndian.Uint16(packet[4:6]))
	ancount := int(binary.BigEndian.Uint16(packet[6:8]))
	if ancount == 0 {
		return out
	}
	// Guard against malicious tiny packets advertising huge QD/AN counts:
	// no individual RR can be smaller than dnsMinRRSize, so any count that
	// could not physically fit in the remaining bytes is rejected up front
	// rather than letting the parse loop walk to its full uint16 bound (M-11).
	maxRR := len(packet) / dnsMinRRSize
	if qdcount > maxRR || ancount > maxRR {
		return out
	}

	pos := 12
	for i := 0; i < qdcount; i++ {
		_, next, ok := readDNSName(packet, pos)
		if !ok {
			return out
		}
		pos = next + 4
		if pos > len(packet) {
			return out
		}
	}

	for i := 0; i < ancount; i++ {
		name, next, ok := readDNSName(packet, pos)
		if !ok {
			break
		}
		pos = next
		if pos+10 > len(packet) {
			break
		}
		typ := binary.BigEndian.Uint16(packet[pos : pos+2])
		ttl := binary.BigEndian.Uint32(packet[pos+4 : pos+8])
		rdlength := int(binary.BigEndian.Uint16(packet[pos+8 : pos+10]))
		pos += 10
		if pos+rdlength > len(packet) {
			break
		}
		if typ == 1 && rdlength == 4 {
			var ip [4]byte
			copy(ip[:], packet[pos:pos+4])
			if prev, ok := out[ip]; !ok || len(name) < len(prev.name) {
				out[ip] = ipv4DNSAnswer{name: name, ttl: ttl}
			}
		}
		pos += rdlength
	}
	return out
}

func readDNSName(packet []byte, offset int) (string, int, bool) {
	return readDNSNameSafe(packet, offset, make(map[int]struct{}), 0)
}

func readDNSNameSafe(packet []byte, offset int, visited map[int]struct{}, depth int) (string, int, bool) {
	if depth > dnsNameMaxPointerDepth {
		return "", 0, false
	}
	var labels []string
	for step := 0; step < dnsNameMaxLabelSteps; step++ {
		if offset >= len(packet) {
			return "", 0, false
		}
		b := int(packet[offset])
		offset++
		if b == 0 {
			return joinDNSLabels(labels), offset, true
		}
		if b&0xC0 == 0xC0 {
			if offset >= len(packet) {
				return "", 0, false
			}
			ptr := (b&0x3F)<<8 | int(packet[offset])
			offset++
			if ptr >= len(packet) {
				return "", 0, false
			}
			if _, dup := visited[ptr]; dup {
				return "", 0, false
			}
			visited[ptr] = struct{}{}
			suffix, _, ok := readDNSNameSafe(packet, ptr, visited, depth+1)
			if !ok {
				return "", 0, false
			}
			if len(labels) == 0 {
				return suffix, offset, true
			}
			return joinDNSLabels(labels) + "." + suffix, offset, true
		}
		if b > 63 || offset+b > len(packet) {
			return "", 0, false
		}
		labels = append(labels, string(packet[offset:offset+b]))
		offset += b
	}
	return "", 0, false
}

func joinDNSLabels(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	s := labels[0]
	for i := 1; i < len(labels); i++ {
		s += "." + labels[i]
	}
	return s
}
