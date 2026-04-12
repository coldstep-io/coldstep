//go:build linux

package agent

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestExecEventWireLayout(t *testing.T) {
	var ev execEvent
	ev.TGID = 7
	ev.TID = 8
	copy(ev.Comm[:], "sh\x00")
	copy(ev.ExePath[:], "/bin/sh\x00")

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, &ev); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if len(raw) != 280 {
		t.Fatalf("wire size %d want 280 (4+4+16+256)", len(raw))
	}
	var out execEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &out); err != nil {
		t.Fatal(err)
	}
	if out.TGID != 7 || out.TID != 8 {
		t.Fatalf("ids %+v", out)
	}
}
