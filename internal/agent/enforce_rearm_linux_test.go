//go:build linux

package agent

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestReconcileLPMMap_AddedCountsOnlyNewKeys(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("remove memlock rlimit (needed for ebpf.NewMap in Docker/minimal env): %v", err)
	}

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  1,
		MaxEntries: 16,
		Flags:      1, // BPF_F_NO_PREALLOC (required for LPM trie on many kernels)
	})
	if err != nil {
		// Docker/default seccomp often denies BPF map create without CAP_BPF
		// (use: docker run --cap-add BPF). GitHub-hosted ubuntu-latest allows it.
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("ebpf map create not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer m.Close()

	var kExisting, kNew [8]byte
	binary.LittleEndian.PutUint32(kExisting[0:4], 32)
	copy(kExisting[4:8], net.ParseIP("1.1.1.1").To4())
	binary.LittleEndian.PutUint32(kNew[0:4], 32)
	copy(kNew[4:8], net.ParseIP("8.8.8.8").To4())

	val := uint8(1)
	if err := m.Update(kExisting, val, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	expected := map[[8]byte]struct{}{
		kExisting: {},
		kNew:      {},
	}
	added, removed, err := reconcileLPMMap(m, expected)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("removed = %d, want 0", removed)
	}
	if added != 1 {
		t.Fatalf("added = %d, want 1 (only kNew was absent)", added)
	}
}
