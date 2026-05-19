package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzSanitizeField(f *testing.F) {
	f.Add("normal.domain.com", 253)
	f.Add("evil\ninjection", 253)
	f.Add("bad\x00byte", 16)
	f.Add(strings.Repeat("a", 10000), 253)
	f.Add("café", 4)
	f.Add("\xff\xfe\xfd", 16)
	f.Add("", 16)
	f.Fuzz(func(t *testing.T, s string, maxLen int) {
		if maxLen <= 0 || maxLen > 8192 {
			return
		}
		result := SanitizeField(s, maxLen)
		// Property 1: must be JSON-marshalable as a string value.
		b, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("SanitizeField(%q, %d) = %q: not JSON-marshalable: %v", s, maxLen, result, err)
		}
		// Property 2: no raw newline / carriage return survives — these are
		// the only characters that could break JSONL record framing.
		if strings.ContainsAny(result, "\n\r") {
			t.Fatalf("SanitizeField(%q, %d) = %q: contains raw newline", s, maxLen, result)
		}
		// Property 3: byte-length budget honored.
		if len(result) > maxLen {
			t.Fatalf("SanitizeField(%q, %d) = %q: len=%d exceeds maxLen", s, maxLen, result, len(result))
		}
		// Property 4: output is valid UTF-8 (truncation must not split a rune).
		if !utf8.ValidString(result) {
			t.Fatalf("SanitizeField(%q, %d) = %q: not valid UTF-8", s, maxLen, result)
		}
		// Property 5: no C0 or C1 control bytes (excluding DEL) survive.
		for _, r := range result {
			if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
				t.Fatalf("SanitizeField(%q, %d) = %q: control char U+%04X survived", s, maxLen, result, r)
			}
		}
		_ = b
	})
}
