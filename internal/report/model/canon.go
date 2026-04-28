package model

import (
	"bytes"
	"encoding/json"
)

// MarshalCanonical produces stable, 2-space indented JSON. Map keys are
// sorted by the encoding/json default; struct field order follows declaration.
func MarshalCanonical(r *Report) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	// json.Encoder appends a trailing newline; strip it for byte-stability.
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return bytes.Clone(out), nil
}
