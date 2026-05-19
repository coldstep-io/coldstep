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
