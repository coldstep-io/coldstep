package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeField_NormalASCIIPassThrough(t *testing.T) {
	in := "curl"
	got := SanitizeField(in, 16)
	if got != in {
		t.Fatalf("normal ASCII mutated: got %q want %q", got, in)
	}
}

func TestSanitizeField_StripsNewlineAndCarriageReturn(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"lf", "evil\ninjection", "evilinjection"},
		{"cr", "evil\rinjection", "evilinjection"},
		{"crlf", "evil\r\ninjection", "evilinjection"},
		{"tab", "evil\tinjection", "evilinjection"},
		{"forged_record", "bash\n{\"type\":\"meta\",\"forged\":true}", "bash{\"type\":\"meta\",\"forged\":true}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeField(tc.in, 4096)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			if strings.ContainsAny(got, "\n\r\t") {
				t.Fatalf("control chars survived: %q", got)
			}
		})
	}
}

func TestSanitizeField_StripsNULByte(t *testing.T) {
	got := SanitizeField("bad\x00byte", 16)
	if got != "badbyte" {
		t.Fatalf("got %q want %q", got, "badbyte")
	}
	if strings.ContainsRune(got, 0x00) {
		t.Fatalf("NUL survived: %q", got)
	}
}

func TestSanitizeField_StripsC0AndC1Controls(t *testing.T) {
	// Build a string containing every C0 and C1 control byte plus DEL,
	// interleaved with printable ASCII so we can verify only the controls
	// are removed.
	var raw strings.Builder
	for r := rune(0); r < 0x20; r++ {
		raw.WriteRune(r)
		raw.WriteRune('x')
	}
	raw.WriteRune(0x7F)
	raw.WriteRune('x')
	for r := rune(0x80); r <= 0x9F; r++ {
		raw.WriteRune(r)
		raw.WriteRune('x')
	}
	got := SanitizeField(raw.String(), 4096)
	want := strings.Repeat("x", 0x20+1+(0x9F-0x80+1))
	if got != want {
		t.Fatalf("control-strip mismatch: got %q want %q", got, want)
	}
}

func TestSanitizeField_TruncatesAtMaxLenBytes(t *testing.T) {
	in := strings.Repeat("a", 100)
	got := SanitizeField(in, 16)
	if len(got) != 16 {
		t.Fatalf("len=%d want 16", len(got))
	}
	if got != strings.Repeat("a", 16) {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeField_TruncateWalksBackToRuneBoundary(t *testing.T) {
	// "é" is 2 bytes (0xC3 0xA9). With maxLen=3 over "aéé", the naive cut
	// at byte 3 would split the second "é" in half; truncation must walk
	// back to a valid rune start, leaving "aé" (3 bytes total... actually
	// "aé" is 1+2=3 bytes, no walk-back needed; with maxLen=4 over "aéé"
	// the cut at byte 4 is the middle of "é" and must walk back to 3).
	in := "aéé" // a é é, total 5 bytes
	got := SanitizeField(in, 4)
	if got != "aé" {
		t.Fatalf("rune-boundary truncation failed: got %q (% x) want %q", got, got, "aé")
	}
	if len(got) > 4 {
		t.Fatalf("exceeded maxLen: len=%d", len(got))
	}
}

func TestSanitizeField_InvalidUTF8ReplacedWithU_FFFD(t *testing.T) {
	// 0xFF is not a valid UTF-8 start byte.
	in := "ok\xffend"
	got := SanitizeField(in, 16)
	if !strings.Contains(got, "�") {
		t.Fatalf("expected replacement char in %q", got)
	}
	// Must remain valid JSON when serialized.
	if _, err := json.Marshal(got); err != nil {
		t.Fatalf("not JSON-marshalable: %v", err)
	}
}

func TestSanitizeField_EmptyString(t *testing.T) {
	if got := SanitizeField("", 16); got != "" {
		t.Fatalf("empty in -> %q", got)
	}
}

func TestSanitizeField_ZeroOrNegativeMaxLenReturnsEmpty(t *testing.T) {
	if got := SanitizeField("anything", 0); got != "" {
		t.Fatalf("maxLen=0 -> %q want \"\"", got)
	}
	if got := SanitizeField("anything", -1); got != "" {
		t.Fatalf("maxLen=-1 -> %q want \"\"", got)
	}
}

func TestSanitizeField_NonASCIIPrintablePassesThrough(t *testing.T) {
	// Printable non-ASCII (CJK, accented Latin) must survive.
	cases := []string{
		"café",             // café
		"中文",               // 中文
		"\U0001F600 emoji", // grinning face
		"naïve résumé",     //nolint:gosmopolitan // intentional UTF-8 test fixture
	}
	for _, in := range cases {
		got := SanitizeField(in, 4096)
		if got != in {
			t.Fatalf("printable non-ASCII mutated: in=%q got=%q", in, got)
		}
	}
}

// Demonstrates the security property: a sanitized value, embedded as a JSON
// string in a JSONL line, can never close the surrounding string or insert
// a new record.
func TestSanitizeField_OutputIsJSONLSafe(t *testing.T) {
	in := "bash\n{\"type\":\"meta\",\"forged\":true}\nmore"
	cleaned := SanitizeField(in, 4096)
	if strings.ContainsAny(cleaned, "\n\r") {
		t.Fatalf("newline survived: %q", cleaned)
	}
	line, err := json.Marshal(struct {
		Comm string `json:"comm"`
	}{Comm: cleaned})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Count(string(line), "\n") != 0 {
		t.Fatalf("JSONL line contains raw newline: %q", line)
	}
}
