package telemetry

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"crypto/ed25519"
)

func TestNewSigner_empty(t *testing.T) {
	s, err := NewSigner("")
	if err != nil {
		t.Fatal(err)
	}
	if s != nil {
		t.Fatal("expected nil signer for empty key")
	}
}

func TestNewSigner_invalidBase64(t *testing.T) {
	if _, err := NewSigner("not!!!valid@@@"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestNewSigner_badLength(t *testing.T) {
	// 31 bytes — invalid length
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	if _, err := NewSigner(short); err == nil {
		t.Fatal("expected length error")
	}
}

func TestSigner_nilPublicKey(t *testing.T) {
	var s *Signer
	if got := s.PublicKey(); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := s.PublicKeyBytes(); got != nil {
		t.Fatalf("got %v", got)
	}
	if sig, err := s.Sign(map[string]string{"a": "b"}); sig != "" || err != nil {
		t.Fatalf("Sign(nil) = %q, %v want empty, nil", sig, err)
	}
}

// Signing round-trips the event through map[string]any to canonicalize key
// order. A plain json.Unmarshal decodes every number as float64, silently
// rounding any integer above 2^53 — and the signature then certified the
// rounded value. UseNumber preserves the literal.
func TestAppendJSONL_SignedPreservesLargeUint64(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := &Signer{priv: priv}

	const exact = uint64(1738368000123456789) // > 2^53, not representable as float64
	ev := TCPStateEvent{
		Type:        EventTypeTCPState,
		TS:          "2026-01-01T00:00:00Z",
		Seq:         1,
		TimestampNS: exact,
		DstIP:       "1.2.3.4",
		DstPort:     443,
	}

	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := AppendJSONL(path, ev, signer); err != nil {
		t.Fatalf("AppendJSONL: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var back TCPStateEvent
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal signed line: %v (line=%s)", err, raw)
	}
	if back.TimestampNS != exact {
		t.Errorf("timestamp_ns=%d want %d (signed round-trip rounded it)", back.TimestampNS, exact)
	}
	if back.Sig == "" {
		t.Error("signed line carries no sig field")
	}
}
