// Pure spec parse via cilium/ebpf — no kernel needed.
package tracefs

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestFSRingbufReserveFailuresMapIsPerCPUArray(t *testing.T) {
	spec, err := LoadTracefs()
	if err != nil {
		t.Fatalf("LoadTracefs: %v", err)
	}
	ms, ok := spec.Maps["fs_ringbuf_reserve_failures"]
	if !ok {
		t.Fatal(`map "fs_ringbuf_reserve_failures" missing`)
	}
	if ms.Type != ebpf.PerCPUArray {
		t.Fatalf("type = %v, want ebpf.PerCPUArray", ms.Type)
	}
	if ms.MaxEntries != 1 || ms.KeySize != 4 || ms.ValueSize != 4 {
		t.Fatalf("unexpected shape %+v", ms)
	}
}
