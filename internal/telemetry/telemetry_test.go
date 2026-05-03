//go:build !windows

// Windows is not a supported platform for running this repo's Go tests (CI: ubuntu-latest — see README.md).

package telemetry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if err := AppendJSONL(p, ev, nil); err != nil {
		t.Fatal(err)
	}
	if err := AppendJSONL(p, ev, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if c := countNewlines(b); c != 2 {
		t.Fatalf("lines: got %d want 2, body=%s", c, string(b))
	}
}

func countNewlines(b []byte) int {
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
	if err := WriteSummary(p, s, nil); err != nil {
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

func TestWriteSummaryIncludesRingbufReserveFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "telemetry.json")
	s := Summary{
		Version: 2, SchemaVersion: SchemaVersion,
		ExecEvents: 1, TCPEvents: 1, UDPEvents: 1, HTTPEvents: 1,
		UDPRingbufReserveFailures:     7,
		DNSRingbufReserveFailures:     3,
		RingbufReserveFailuresTotal:   15,
		ConnectRingbufReserveFailures: 5,
		PolicyCounts:                  map[string]int{"monitor": 1},
	}
	if err := WriteSummary(p, s, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"udp_ringbuf_reserve_failures": 7`)) {
		t.Fatalf("missing udp reserve count: %s", b)
	}
	if !bytes.Contains(b, []byte(`"dns_ringbuf_reserve_failures": 3`)) {
		t.Fatalf("missing dns reserve count: %s", b)
	}
	if !bytes.Contains(b, []byte(`"ringbuf_reserve_failures_total": 15`)) {
		t.Fatalf("missing ringbuf reserve total: %s", b)
	}
	if !bytes.Contains(b, []byte(`"connect_ringbuf_reserve_failures": 5`)) {
		t.Fatalf("missing connect reserve count: %s", b)
	}
}

func TestSumRingbufReserveFailuresDetectPath(t *testing.T) {
	t.Parallel()
	const (
		udp = 1 + iota
		dns
		connect
		http
		tlsR
		execR
		forkR
		fsR
		bpfAudit
	)
	got := SumRingbufReserveFailuresDetectPath(udp, dns, connect, http, tlsR, execR, forkR, fsR, bpfAudit)
	want := udp + dns + connect + http + tlsR + execR + forkR + fsR + bpfAudit
	if got != want {
		t.Fatalf("got %d want %d", got, want)
	}
	if got != 45 {
		t.Fatalf("expected 1..9 sum 45, got %d", got)
	}
}

func TestSigning(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "e.jsonl")
	signer, err := NewSigner("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") // 32 bytes of zeros in base64
	if err != nil {
		t.Fatal(err)
	}

	ev := ExecEvent{
		Type: "exec", TS: "2026-04-28T12:00:00Z", Seq: 1,
		PID: 100, Comm: "ls", Exe: "/bin/ls",
	}

	if err := AppendJSONL(p, ev, signer); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(b, []byte(`"sig":`)) {
		t.Fatalf("missing signature in output: %s", b)
	}

	line := strings.TrimRight(string(b), "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("unmarshal line: %v", err)
	}
	sigStr, _ := m["sig"].(string)
	if sigStr == "" {
		t.Fatal("sig field missing or empty")
	}
	delete(m, "sig")
	canonical, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(signer.PublicKeyBytes(), canonical, sigBytes) {
		t.Fatalf("signature verification failed\ncanonical: %s", canonical)
	}
}
