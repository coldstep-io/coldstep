package telemetry

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Signer wraps an Ed25519 private key to sign telemetry events.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewSigner creates a signer from a base64-encoded seed or private key.
func NewSigner(b64 string) (*Signer, error) {
	if b64 == "" {
		return nil, nil
	}
	seed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	var priv ed25519.PrivateKey
	if len(seed) == 32 {
		priv = ed25519.NewKeyFromSeed(seed)
	} else if len(seed) == 64 {
		priv = ed25519.PrivateKey(seed)
	} else {
		return nil, fmt.Errorf("invalid signing key length: %d (want 32 or 64)", len(seed))
	}
	return &Signer{
		priv: priv,
		pub:  priv.Public().(ed25519.PublicKey),
	}, nil
}

// PublicKey returns the base64-encoded public key.
func (s *Signer) PublicKey() string {
	if s == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(s.pub)
}

// PublicKeyBytes returns the raw Ed25519 public key for signature verification.
func (s *Signer) PublicKeyBytes() ed25519.PublicKey {
	if s == nil {
		return nil
	}
	return s.pub
}

// Sign marshals v, signs the JSON, and returns the base64 signature.
// v must NOT already contain a "sig" field or it will be included in the signed payload.
func (s *Signer) Sign(v any) (string, error) {
	if s == nil {
		return "", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(s.priv, b)
	return base64.StdEncoding.EncodeToString(sig), nil
}
