package telemetry

import (
	"strings"
	"unicode/utf8"
)

// SanitizeField removes control characters (including \n \r \t and other
// C0/C1 controls) and truncates to maxLen bytes. It replaces any invalid
// UTF-8 sequences with the Unicode replacement character (U+FFFD). The
// result is safe to embed as a JSON string value in an append-only JSONL
// stream — no caller-controlled bytes can introduce a record boundary or
// terminate the surrounding JSON string.
//
// Field-size budgets at the call sites (P1-5):
//   - Comm           16   bytes (TASK_COMM_LEN)
//   - Exe            4096 bytes (PATH_MAX)
//   - SNI/Host/FQDN  253  bytes (RFC 1035 max FQDN)
//   - Path           4096 bytes (PATH_MAX)
//   - Cmdline        4096 bytes
//
// maxLen is a byte budget, not a rune budget; truncation walks back to a
// valid UTF-8 rune boundary so the output stays a valid UTF-8 string.
func SanitizeField(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		// Strip C0 (U+0000–U+001F), DEL (U+007F), and C1 (U+0080–U+009F)
		// control characters. Everything else (including all printable
		// Unicode, including non-ASCII) passes through unchanged.
		if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > maxLen {
		cut := maxLen
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:cut]
	}
	return out
}
