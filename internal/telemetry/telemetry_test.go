//go:build !windows

// Windows is not a supported platform for running this repo's Go tests (CI: ubuntu-latest — see README.md).

package telemetry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendJSONL(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "e.jsonl")
	ev := TCPEvent{
		Type: "tcp", TS: "2026-04-09T12:00:00Z", Seq: 1,
		PID: 3, TGID: 3, ThreadID: 3, Comm: "curl",
		Dst: "1.1.1.1", Dport: 443, Direction: "egress", Policy: "unknown",
	}
	if err := AppendJSONL(p, ev); err != nil {
		t.Fatal(err)
	}
	if err := AppendJSONL(p, ev); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if c := bytesCountNewlines(b); c != 2 {
		t.Fatalf("lines: got %d want 2, body=%s", c, string(b))
	}
}

func bytesCountNewlines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}

func TestWriteSummary(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.json")
	s := Summary{
		Version: 2, SchemaVersion: SchemaVersion,
		ExecEvents: 1, TCPEvents: 2, UDPEvents: 0, HTTPEvents: 0,
		PolicyCounts: map[string]int{"monitor": 2},
	}
	if err := WriteSummary(p, s); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 20 {
		t.Fatalf("short file: %s", string(b))
	}
}
