// Pure spec parse via cilium/ebpf — no kernel needed.
package traceipv6

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestIPv6ObsRingbufMap(t *testing.T) {
	spec, err := LoadTraceipv6()
	if err != nil {
		t.Fatalf("LoadTraceipv6: %v", err)
	}
	ms, ok := spec.Maps["ipv6_obs_events"]
	if !ok {
		t.Fatal(`map "ipv6_obs_events" missing`)
	}
	if ms.Type != ebpf.RingBuf {
		t.Fatalf("type = %v, want ebpf.RingBuf", ms.Type)
	}
	if ms.MaxEntries != 1<<20 {
		t.Fatalf("max_entries = %d, want %d", ms.MaxEntries, 1<<20)
	}
}

func TestIPv6ObsRingbufReserveFailuresMapIsPerCPUArray(t *testing.T) {
	spec, err := LoadTraceipv6()
	if err != nil {
		t.Fatalf("LoadTraceipv6: %v", err)
	}
	ms, ok := spec.Maps["ipv6_obs_ringbuf_reserve_failures"]
	if !ok {
		t.Fatal(`map "ipv6_obs_ringbuf_reserve_failures" missing`)
	}
	if ms.Type != ebpf.PerCPUArray {
		t.Fatalf("type = %v, want ebpf.PerCPUArray", ms.Type)
	}
	if ms.MaxEntries != 1 || ms.KeySize != 4 || ms.ValueSize != 4 {
		t.Fatalf("unexpected shape %+v", ms)
	}
}

func TestIPv6ObsProgramsPresent(t *testing.T) {
	spec, err := LoadTraceipv6()
	if err != nil {
		t.Fatalf("LoadTraceipv6: %v", err)
	}
	for _, name := range []string{"ipv6_obs_connect6", "ipv6_obs_sendmsg6"} {
		if _, ok := spec.Programs[name]; !ok {
			t.Fatalf("program %q missing from spec", name)
		}
	}
}
