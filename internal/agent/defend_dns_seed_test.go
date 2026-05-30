package agent

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

// fakeOwnerMap is an in-memory ownerMapWriter so seedDefendOwners is testable
// without a real BPF map (cross-platform: runs on the Windows dev host too).
type fakeOwnerMap struct {
	entries map[[4]byte][256]byte
	failOn  map[[4]byte]bool
	updates int
}

func (f *fakeOwnerMap) Update(key, value interface{}, _ ebpf.MapUpdateFlags) error {
	f.updates++
	k := *(key.(*[4]byte))
	if f.failOn[k] {
		return errors.New("simulated map update failure")
	}
	v := *(value.(*[256]byte))
	if f.entries == nil {
		f.entries = make(map[[4]byte][256]byte)
	}
	f.entries[k] = v
	return nil
}

func ownerFromVal(v [256]byte) string {
	return string(bytes.TrimRight(v[:], "\x00"))
}

func TestOwnerBPFValue(t *testing.T) {
	v, truncated := ownerBPFValue("example.com")
	if truncated {
		t.Fatalf("short name reported truncated")
	}
	if got := ownerFromVal(v); got != "example.com" {
		t.Fatalf("owner round-trip = %q, want example.com", got)
	}
	// Trailing bytes must be NUL so the BPF char* lookup terminates.
	if v[len("example.com")] != 0 {
		t.Fatalf("value not NUL-terminated after name")
	}

	long := make([]byte, dnsBPFNameMax+10)
	for i := range long {
		long[i] = 'a'
	}
	v2, truncated2 := ownerBPFValue(string(long))
	if !truncated2 {
		t.Fatalf("over-length name not reported truncated")
	}
	if got := len(ownerFromVal(v2)); got != dnsBPFNameMax {
		t.Fatalf("truncated owner len = %d, want %d", got, dnsBPFNameMax)
	}
}

func TestSeedDefendOwners_NilAndEmpty(t *testing.T) {
	if n := seedDefendOwners(nil, map[[4]byte]string{{1, 2, 3, 4}: "a.com"}, nil); n != 0 {
		t.Fatalf("nil map programmed %d entries, want 0", n)
	}
	m := &fakeOwnerMap{}
	if n := seedDefendOwners(m, nil, nil); n != 0 {
		t.Fatalf("empty owners programmed %d entries, want 0", n)
	}
	if m.updates != 0 {
		t.Fatalf("empty owners triggered %d Update calls, want 0", m.updates)
	}
}

func TestSeedDefendOwners_HappyPath(t *testing.T) {
	m := &fakeOwnerMap{}
	owners := map[[4]byte]string{
		{93, 184, 216, 34}: "example.com",
		{1, 1, 1, 1}:       "one.one.one.one",
		{10, 0, 0, 9}:      "", // empty owner: skipped, never written
	}
	n := seedDefendOwners(m, owners, nil)
	if n != 2 {
		t.Fatalf("programmed %d entries, want 2", n)
	}
	if got := ownerFromVal(m.entries[[4]byte{93, 184, 216, 34}]); got != "example.com" {
		t.Fatalf("example.com owner = %q", got)
	}
	if got := ownerFromVal(m.entries[[4]byte{1, 1, 1, 1}]); got != "one.one.one.one" {
		t.Fatalf("cloudflare owner = %q", got)
	}
	if _, ok := m.entries[[4]byte{10, 0, 0, 9}]; ok {
		t.Fatalf("empty-owner entry was written; must be skipped")
	}
}

func TestSeedDefendOwners_FailureCounted(t *testing.T) {
	failKey := [4]byte{198, 51, 100, 7}
	m := &fakeOwnerMap{failOn: map[[4]byte]bool{failKey: true}}
	owners := map[[4]byte]string{
		failKey:          "bad.example",
		{203, 0, 113, 5}: "good.example",
	}
	failures := 0
	n := seedDefendOwners(m, owners, func() { failures++ })
	if n != 1 {
		t.Fatalf("programmed %d entries, want 1 (one failed)", n)
	}
	if failures != 1 {
		t.Fatalf("onFailure called %d times, want 1", failures)
	}
	if _, ok := m.entries[failKey]; ok {
		t.Fatalf("failed key must not be recorded as written")
	}
}
