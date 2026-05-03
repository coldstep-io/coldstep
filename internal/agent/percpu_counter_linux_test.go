//go:build linux

package agent

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestReadUint32PerCPUArraySum(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("rlimit.RemoveMemlock: %v", err)
	}

	spec := &ebpf.MapSpec{
		Name:       "coldstep_test_percpu_u32",
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		// Docker/default seccomp and some CI sandboxes block map create without
		// CAP_SYS_ADMIN/BPF or equivalent; privileged runners pass.
		t.Skipf("creating bpf map: %v", err)
	}
	defer m.Close()

	var key uint32
	n := ebpf.MustPossibleCPU()
	vals := make([]uint32, n)
	vals[0] = 42

	if err := m.Put(key, vals); err != nil {
		t.Fatal(err)
	}

	got := readUint32PerCPUArraySum(m, "TestReadUint32PerCPUArraySum")
	if got != 42 {
		t.Fatalf("sum = %d, want 42", got)
	}
}
