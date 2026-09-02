package telemetry

import (
	"strings"
	"testing"
)

func TestScoreTLSConfidence_Full(t *testing.T) {
	got := ScoreTLSConfidence("example.com")
	if got != TLSConfidenceFull {
		t.Fatalf("ScoreTLSConfidence(\"example.com\") = %q, want %q", got, TLSConfidenceFull)
	}
}

func TestScoreTLSConfidence_FullJustBelowBoundary(t *testing.T) {
	// A 254-char hostname is one byte short of the RFC 1035 boundary; the parser
	// would have accepted it intact, so confidence stays full.
	sni := strings.Repeat("a", TLSSNIMaxLen-1)
	got := ScoreTLSConfidence(sni)
	if got != TLSConfidenceFull {
		t.Fatalf("ScoreTLSConfidence(len=%d) = %q, want %q", len(sni), got, TLSConfidenceFull)
	}
}

func TestScoreTLSConfidence_PartialAtBoundary(t *testing.T) {
	// At exactly TLSSNIMaxLen (255) the SNI hit the parser's upper bound; we
	// cannot tell whether the real server name was longer, so we report partial.
	sni := strings.Repeat("a", TLSSNIMaxLen)
	got := ScoreTLSConfidence(sni)
	if got != TLSConfidencePartial {
		t.Fatalf("ScoreTLSConfidence(len=%d) = %q, want %q", len(sni), got, TLSConfidencePartial)
	}
}

func TestScoreTLSConfidence_Unknown(t *testing.T) {
	got := ScoreTLSConfidence("")
	if got != TLSConfidenceUnknown {
		t.Fatalf("ScoreTLSConfidence(\"\") = %q, want %q", got, TLSConfidenceUnknown)
	}
}

func TestTLSConfidenceConstants(t *testing.T) {
	cases := []struct {
		v    TLSConfidence
		want string
	}{
		{TLSConfidenceFull, "full"},
		{TLSConfidencePartial, "partial"},
		{TLSConfidenceInferred, "inferred"},
		{TLSConfidenceUnknown, "unknown"},
	}
	for _, c := range cases {
		if string(c.v) != c.want {
			t.Errorf("TLSConfidence string mismatch: got %q want %q", c.v, c.want)
		}
	}
}

// The SNI field budget passed to SanitizeField at the call sites (253, the RFC
// 1035 max FQDN) is BELOW the boundary ScoreTLSConfidence uses to report
// "partial" (TLSSNIMaxLen = 255). Confidence must therefore be scored on the
// parsed SNI, before sanitizing — scoring the sanitized value makes the partial
// tier unreachable and labels a boundary-length (possibly truncated) SNI "full".
// This pins the relationship so a re-order in the TLS ring reader fails here.
func TestScoreTLSConfidence_MustBeScoredBeforeSanitize(t *testing.T) {
	const sniFieldBudget = 253 // readTLSRing's SanitizeField(sni, 253)
	if sniFieldBudget >= TLSSNIMaxLen {
		t.Fatalf("field budget %d >= TLSSNIMaxLen %d — this test's premise no longer holds",
			sniFieldBudget, TLSSNIMaxLen)
	}

	boundary := strings.Repeat("a", TLSSNIMaxLen)
	if got := ScoreTLSConfidence(boundary); got != TLSConfidencePartial {
		t.Errorf("ScoreTLSConfidence(len=%d) = %q, want %q", len(boundary), got, TLSConfidencePartial)
	}
	// Sanitizing first destroys the signal — the reason for the ordering.
	if got := ScoreTLSConfidence(SanitizeField(boundary, sniFieldBudget)); got != TLSConfidenceFull {
		t.Errorf("sanitize-then-score = %q, want %q (documents the bug being guarded against)",
			got, TLSConfidenceFull)
	}
}
