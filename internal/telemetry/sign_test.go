package telemetry

import (
	"encoding/base64"
	"testing"
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
