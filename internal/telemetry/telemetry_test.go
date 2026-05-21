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

// TestWriteSummaryIncludesTLSConfidenceCounters pins the H8 contract: the
// per-tier TLS SNI confidence counters round-trip through the public
// `.coldstep-telemetry.json` so downstream consumers (report tooling,
// dashboards) can read the confidence breakdown without reparsing JSONL. The
// `omitempty` zero-default keeps the existing telemetry footprint unchanged
// on runs that produced no TLS events.
func TestWriteSummaryIncludesTLSConfidenceCounters(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "telemetry.json")
	s := Summary{
		Version: 2, SchemaVersion: SchemaVersion,
		ExecEvents:            1,
		TLSEvents:             4,
		TLSConfidenceFull:     2,
		TLSConfidencePartial:  1,
		TLSConfidenceInferred: 0,
		TLSConfidenceUnknown:  1,
		PolicyCounts:          map[string]int{"monitor": 4},
	}
	if err := WriteSummary(p, s, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range [][]byte{
		[]byte(`"tls_confidence_full": 2`),
		[]byte(`"tls_confidence_partial": 1`),
		[]byte(`"tls_confidence_unknown": 1`),
	} {
		if !bytes.Contains(b, needle) {
			t.Fatalf("missing %q in summary:\n%s", needle, b)
		}
	}
	// Inferred is zero — omitempty must hide it so a normal SNI-only run does
	// not emit a noise field for a tier the agent does not produce today.
	if bytes.Contains(b, []byte(`"tls_confidence_inferred"`)) {
		t.Fatalf("zero-value tls_confidence_inferred should be omitted, got:\n%s", b)
	}
}

// TestWriteSummaryIncludesNewCounters pins that the recently-added
// counters (TCP state aggregates, QUIC heuristic observation total, DNS
// drift observation total) round-trip through `.coldstep-telemetry.json`.
// Without these, the digest's TCP handshake / QUIC / DNS drift cells would
// have no machine-readable twin on the summary file — downstream consumers
// would be forced to reparse JSONL to recover the same totals.
func TestWriteSummaryIncludesNewCounters(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "telemetry.json")
	s := Summary{
		Version: 2, SchemaVersion: SchemaVersion,
		ExecEvents:                     1,
		TCPStateTotal:                  9,
		TCPStateConfirmed:              7,
		TCPStateRefused:                2,
		TCPStateRingbufReserveFailures: 1,
		QuicObserved:                   4,
		DNSDriftObservations:           3,
		PolicyCounts:                   map[string]int{"monitor": 1},
	}
	if err := WriteSummary(p, s, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range [][]byte{
		[]byte(`"tcp_state_total": 9`),
		[]byte(`"tcp_state_confirmed": 7`),
		[]byte(`"tcp_state_refused": 2`),
		[]byte(`"tcp_state_ringbuf_reserve_failures": 1`),
		[]byte(`"quic_observed": 4`),
		[]byte(`"dns_drift_observations": 3`),
	} {
		if !bytes.Contains(b, needle) {
			t.Fatalf("missing %q in summary:\n%s", needle, b)
		}
	}
	// Zero-default fields must remain omitted.
	zeroDefault := Summary{
		Version: 2, SchemaVersion: SchemaVersion,
		ExecEvents:   1,
		PolicyCounts: map[string]int{"monitor": 1},
	}
	pZero := filepath.Join(dir, "zero.json")
	if err := WriteSummary(pZero, zeroDefault, nil); err != nil {
		t.Fatal(err)
	}
	bZero, err := os.ReadFile(pZero)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		`"tcp_state_total"`,
		`"tcp_state_confirmed"`,
		`"tcp_state_refused"`,
		`"tcp_state_ringbuf_reserve_failures"`,
		`"quic_observed"`,
		`"dns_drift_observations"`,
	} {
		if bytes.Contains(bZero, []byte(needle)) {
			t.Fatalf("zero-value %s should be omitted, got:\n%s", needle, bZero)
		}
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
