// Pure spec parse via cilium/ebpf — no kernel needed.
package tracefork

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestForkRingbufReserveFailuresMapIsPerCPUArray(t *testing.T) {
	spec, err := LoadTracefork()
	if err != nil {
		t.Fatalf("LoadTracefork: %v", err)
	}
	ms, ok := spec.Maps["fork_ringbuf_reserve_failures"]
	if !ok {
		t.Fatal(`map "fork_ringbuf_reserve_failures" missing`)
	}
	if ms.Type != ebpf.PerCPUArray {
		t.Fatalf("type = %v, want ebpf.PerCPUArray", ms.Type)
	}
	if ms.MaxEntries != 1 || ms.KeySize != 4 || ms.ValueSize != 4 {
		t.Fatalf("unexpected shape %+v", ms)
	}
}
