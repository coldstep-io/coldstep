// Pure spec parse via cilium/ebpf — no kernel needed.
package traceexec

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestExecRingbufReserveFailuresMapIsPerCPUArray(t *testing.T) {
	spec, err := LoadTraceexec()
	if err != nil {
		t.Fatalf("LoadTraceexec: %v", err)
	}
	ms, ok := spec.Maps["exec_ringbuf_reserve_failures"]
	if !ok {
		t.Fatal(`map "exec_ringbuf_reserve_failures" missing`)
	}
	if ms.Type != ebpf.PerCPUArray {
		t.Fatalf("type = %v, want ebpf.PerCPUArray", ms.Type)
	}
	if ms.MaxEntries != 1 || ms.KeySize != 4 || ms.ValueSize != 4 {
		t.Fatalf("unexpected shape %+v", ms)
	}
}
