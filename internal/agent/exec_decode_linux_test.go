//go:build linux

package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestExecEventWireLayout(t *testing.T) {
	var ev execEvent
	ev.TGID = 7
	ev.TID = 8
	copy(ev.Comm[:], "sh\x00")
	copy(ev.ExePath[:], "/bin/sh\x00")
	ev.ExeIno = 0xdeadbeef
	ev.ExeDev = 0x0801

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, &ev); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if len(raw) != 296 {
		t.Fatalf("wire size %d want 296 (4+4+16+256+8+4+4)", len(raw))
	}
	var out execEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &out); err != nil {
		t.Fatal(err)
	}
	if out.TGID != 7 || out.TID != 8 {
		t.Fatalf("ids %+v", out)
	}
	if out.ExeIno != 0xdeadbeef || out.ExeDev != 0x0801 {
		t.Fatalf("identity round-trip: ino=%#x dev=%#x", out.ExeIno, out.ExeDev)
	}
}

func TestBestEffortExeSHA256(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	content := []byte("#!/bin/sh\necho v1\n")
	if err := os.WriteFile(p, content, 0o755); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(content)
	if got := bestEffortExeSHA256(p); got != hex.EncodeToString(want[:]) {
		t.Fatalf("hash = %q, want %q", got, hex.EncodeToString(want[:]))
	}

	// Replacing the file content at the same path yields a different hash —
	// the tamper signal Sub-project C surfaces alongside the stable exe_ino.
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho v2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := bestEffortExeSHA256(p); got == hex.EncodeToString(want[:]) {
		t.Fatal("hash did not change after content replacement")
	}

	// Guards: relative path, missing file, and a non-absolute name all yield "".
	if got := bestEffortExeSHA256("bin"); got != "" {
		t.Fatalf("relative path should hash to empty, got %q", got)
	}
	if got := bestEffortExeSHA256(filepath.Join(dir, "nope")); got != "" {
		t.Fatalf("missing file should hash to empty, got %q", got)
	}
}
