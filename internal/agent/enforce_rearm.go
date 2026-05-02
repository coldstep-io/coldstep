//go:build linux

package agent

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/coldstep-io/coldstep/internal/policy"
)

// expectedAllowedKeys returns the LPM-trie keyset that loadAllowedLPMMap would
// program for the given snapshot. Wire format mirrors loadAllowedLPMMap:
// little-endian prefixlen at [0:4], big-endian network at [4:8].
func expectedAllowedKeys(compiled policy.CompileResult, pol *policy.Policy) map[[8]byte]struct{} {
	v4keys := make(map[[4]byte]struct{}, compiled.AllowedIPv4.Len())
	compiled.AllowedIPv4.ForEach(func(k [4]byte) { v4keys[k] = struct{}{} })
	if pol != nil {
		pol.MergeLiteralAllowedIPv4Keys(v4keys)
	}

	expected := make(map[[8]byte]struct{}, len(v4keys))
	for addr := range v4keys {
		var key [8]byte
		binary.LittleEndian.PutUint32(key[0:4], 32)
		copy(key[4:8], addr[:])
		expected[key] = struct{}{}
	}

	if pol == nil {
		return expected
	}
	for _, n := range pol.AllowedIPv4Nets() {
		if n == nil {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits != 32 || ones < 0 || ones > 32 {
			continue
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			continue
		}
		network := ip4.Mask(n.Mask)
		if network == nil {
			continue
		}
		var key [8]byte
		binary.LittleEndian.PutUint32(key[0:4], uint32(ones))
		binary.BigEndian.PutUint32(key[4:8], binary.BigEndian.Uint32(network))
		expected[key] = struct{}{}
	}
	return expected
}

// expectedIgnoredKeys returns the LPM-trie keyset that loadIgnoredLPMMap would
// program for the given policy. Wire format matches loadIgnoredLPMMap.
func expectedIgnoredKeys(pol *policy.Policy) map[[8]byte]struct{} {
	expected := make(map[[8]byte]struct{})
	if pol == nil {
		return expected
	}
	for _, n := range pol.IgnoredIPv4Nets() {
		if n == nil {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits != 32 || ones < 0 || ones > 32 {
			continue
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			continue
		}
		network := ip4.Mask(n.Mask)
		if network == nil {
			continue
		}
		var key [8]byte
		binary.LittleEndian.PutUint32(key[0:4], uint32(ones))
		binary.BigEndian.PutUint32(key[4:8], binary.BigEndian.Uint32(network))
		expected[key] = struct{}{}
	}
	return expected
}

// reconcileLPMMap brings an 8-byte-key / 1-byte-value LPM trie back in line
// with `expected`: it deletes any current key that is not in `expected` and
// (re)inserts every expected key with value 1.
//
// Iteration first collects the survey of stale keys, then deletes them in a
// second pass — cilium/ebpf documents that calling Delete during Iterate is
// unsafe (see knowledge/records/2026-05-01-cilium-ebpf-map-delete-iterate.md).
func reconcileLPMMap(m *ebpf.Map, expected map[[8]byte]struct{}) (added int, removed int, err error) {
	if m == nil {
		if len(expected) > 0 {
			return 0, 0, fmt.Errorf("map is nil with %d expected entries", len(expected))
		}
		return 0, 0, nil
	}

	iter := m.Iterate()
	var k [8]byte
	var v uint8
	var stale [][8]byte
	for iter.Next(&k, &v) {
		if _, ok := expected[k]; !ok {
			cp := k
			stale = append(stale, cp)
		}
	}
	if iterErr := iter.Err(); iterErr != nil {
		return 0, 0, fmt.Errorf("iterate map: %w", iterErr)
	}

	for i := range stale {
		dk := stale[i]
		if delErr := m.Delete(&dk); delErr != nil {
			if errors.Is(delErr, ebpf.ErrKeyNotExist) {
				continue
			}
			return 0, removed, fmt.Errorf("delete map key: %w", delErr)
		}
		removed++
	}

	val := uint8(1)
	for ek := range expected {
		key := ek
		if updErr := m.Update(&key, &val, ebpf.UpdateAny); updErr != nil {
			return added, removed, fmt.Errorf("update map key: %w", updErr)
		}
		added++
	}
	return added, removed, nil
}

// rearmAllowedFromSnapshot reconciles the BPF allowed_ipv4 LPM trie with the
// compiled enforce snapshot (and any literal CIDRs from policy).
func rearmAllowedFromSnapshot(allowedMap *ebpf.Map, compiled policy.CompileResult, pol *policy.Policy) (added int, removed int, err error) {
	expected := expectedAllowedKeys(compiled, pol)
	return reconcileLPMMap(allowedMap, expected)
}

// rearmIgnoredFromPolicy reconciles the BPF ignored_ipv4_lpm trie with the
// merged DefaultIgnoredIPv4Nets + user-provided ignored CIDRs from policy.
func rearmIgnoredFromPolicy(ignoredMap *ebpf.Map, pol *policy.Policy) (added int, removed int, err error) {
	expected := expectedIgnoredKeys(pol)
	return reconcileLPMMap(ignoredMap, expected)
}
