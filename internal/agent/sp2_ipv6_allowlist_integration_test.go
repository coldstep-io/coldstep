//go:build integration && linux && !windows

// SP-2 integration: literal IPv6 allowlist entries (a /128 literal and an IPv6
// CIDR) are programmed into the real defend `allowed_ipv6` LPM trie. Validates
// the full classifier->policy->agent->BPF path that the unit tests cover only
// up to the map boundary. Requires root + a kernel where the defend object
// loads (allowed_ipv6 is part of the cgroup defend object, not the LSM section).

package agent

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/coldstep-io/coldstep/internal/bpf/defend"
	"github.com/coldstep-io/coldstep/internal/policy"
)

func TestSP2_LiteralIPv6ProgrammedIntoAllowedTrie(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF defend objects")
	}
	objs := &defend.DefendObjects{}
	if _, err := defend.LoadDefendObjectsForKernel(objs, true, defend.HaveIOUringLSM()); err != nil {
		t.Fatalf("load defend objects: %v", err)
	}
	defer objs.Close()
	if objs.AllowedIpv6 == nil {
		t.Fatal("allowed_ipv6 map absent from loaded defend object")
	}

	// allow a /128 literal and a /32 CIDR via the policy literal path.
	pol, err := policy.Parse("", "2001:db8::1, 2606:4700::/32")
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	n, err := populateAllowedIPv6Map(objs.AllowedIpv6, policy.CompileResult{AllowedIPv6: policy.IPv6Set{}}, pol)
	if err != nil {
		t.Fatalf("populateAllowedIPv6Map: %v", err)
	}
	if n != 2 {
		t.Fatalf("programmed %d entries, want 2 (one /128 literal + one /32 CIDR)", n)
	}

	// Verify both keys are present in the trie with value 1.
	lookup := func(prefix uint32, ip string) bool {
		var key [20]byte
		binary.LittleEndian.PutUint32(key[0:4], prefix)
		copy(key[4:20], net.ParseIP(ip).To16())
		var val uint8
		return objs.AllowedIpv6.Lookup(key, &val) == nil && val == 1
	}
	if !lookup(128, "2001:db8::1") {
		t.Error("/128 literal 2001:db8::1 not found in allowed_ipv6")
	}
	if !lookup(32, "2606:4700::") {
		t.Error("/32 CIDR 2606:4700:: not found in allowed_ipv6")
	}
}
