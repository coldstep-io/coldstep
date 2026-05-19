// Pure spec parse via cilium/ebpf — no kernel needed.
package tracektls

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestKTLSRingbufReserveFailuresMapIsPerCPUArray(t *testing.T) {
	spec, err := LoadTracektls()
	if err != nil {
		t.Fatalf("LoadTracektls: %v", err)
	}
	ms, ok := spec.Maps["ktls_ringbuf_reserve_failures"]
	if !ok {
		t.Fatal(`map "ktls_ringbuf_reserve_failures" missing`)
	}
	if ms.Type != ebpf.PerCPUArray {
		t.Fatalf("type = %v, want ebpf.PerCPUArray", ms.Type)
	}
	if ms.MaxEntries != 1 || ms.KeySize != 4 || ms.ValueSize != 4 {
		t.Fatalf("unexpected shape %+v", ms)
	}
}

func TestKTLSEventsRingbufExists(t *testing.T) {
	spec, err := LoadTracektls()
	if err != nil {
		t.Fatalf("LoadTracektls: %v", err)
	}
	ms, ok := spec.Maps["ktls_events"]
	if !ok {
		t.Fatal(`map "ktls_events" missing`)
	}
	if ms.Type != ebpf.RingBuf {
		t.Fatalf("type = %v, want ebpf.RingBuf", ms.Type)
	}
}
