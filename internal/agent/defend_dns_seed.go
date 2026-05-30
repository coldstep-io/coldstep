package agent

import (
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
)

// ownerBPFValue renders a trusted owner name into the 256-byte dns_cache value
// buffer consulted by defend_policy.inc:dst_is_allowlisted. The owner string is
// looked up verbatim as an allowed_domains key, so it must byte-match the
// normalized domain programmed into allowed_domains. Returns the buffer and
// whether the name was truncated (names longer than dnsBPFNameMax bytes), which
// mirrors dnsNameForBPF's contract on the sniffed path.
func ownerBPFValue(name string) ([256]byte, bool) {
	var buf [256]byte
	truncated := false
	if len(name) > dnsBPFNameMax {
		name = name[:dnsBPFNameMax]
		truncated = true
	}
	copy(buf[:], name)
	return buf, truncated
}

// ownerMapWriter is the subset of *ebpf.Map that seedDefendOwners needs. An
// interface keeps the seeding logic unit-testable on non-Linux hosts where a
// real BPF map cannot be created. *ebpf.Map satisfies it.
type ownerMapWriter interface {
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
}

// seedDefendOwners writes trusted ip->owner entries into the defend dns_cache
// BPF map consulted by dst_is_allowlisted's late-binding fallback.
//
// SECURITY (dns-cache-trust): owners MUST come from policy.ResolveOwners — the
// agent's own resolver — never from sniffed DNS replies. The sniffed DNSCache
// (DNSCache.AddFromPacket) feeds only the detection-side enrichment map; routing
// it into the enforcement map would let a hostile build step forge a DNS reply
// mapping an allowlisted FQDN to an attacker IP and egress to that IP. Seeding
// from the trusted resolver raises the runtime fallback trust to match the
// startup allowlist-compile trust.
//
// Returns the number of entries programmed. onFailure (nil-ok) is invoked once
// per failed Update so partial userspace<->kernel sync is observable in the
// digest, matching DNSCache's onBPFFailure semantics.
func seedDefendOwners(m ownerMapWriter, owners map[[4]byte]string, onFailure func()) int {
	if m == nil || len(owners) == 0 {
		return 0
	}
	programmed := 0
	for ip, name := range owners {
		if name == "" {
			continue
		}
		key := ip
		val, truncated := ownerBPFValue(name)
		if truncated {
			slog.Warn("defend owner seed: owner truncated for BPF map value",
				"ip", net.IP(ip[:]).String(), "name_len", len(name), "max_len", dnsBPFNameMax)
		}
		if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
			slog.Warn("defend owner seed: BPF map update failed",
				"ip", net.IP(ip[:]).String(), "err", err)
			if onFailure != nil {
				onFailure()
			}
			continue
		}
		programmed++
	}
	return programmed
}
