package model

import (
	"bytes"
	"encoding/json"
)

// MarshalCanonical produces stable, 2-space indented JSON. Map keys are
// sorted by the encoding/json default; struct field order follows declaration.
func MarshalCanonical(r *Report) ([]byte, error) {
	return MarshalCanonicalValue(r)
}

// MarshalCanonicalValue is the shape-agnostic form of MarshalCanonical: it
// applies the same encoder settings (2-space indent, no HTML escaping, no
// trailing newline) to any JSON-encodable value, so map[string]any payloads
// written by post-build enrichment subcommands stay byte-identical to the
// build-model output for hashing / attestation.
func MarshalCanonicalValue(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	// json.Encoder appends a trailing newline; strip it for byte-stability.
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return bytes.Clone(out), nil
}
