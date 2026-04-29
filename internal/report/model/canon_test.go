package model

import (
	"strings"
	"testing"
)

func TestCanonicalJSONIsDeterministic(t *testing.T) {
	r := Report{
		SchemaVersion: SchemaVersion,
		ProducedBy:    "coldstep-report-go@test",
		GeneratedAt:   "2026-04-28T22:00:00Z",
	}
	b1, err := MarshalCanonical(&r)
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}
	b2, err := MarshalCanonical(&r)
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}
	if string(b1) != string(b2) {
		t.Errorf("canonical output not deterministic")
	}
	if !strings.HasPrefix(string(b1), "{\n  \"schema_version\":") {
		snippet := string(b1)
		if len(snippet) > 50 {
			snippet = snippet[:50]
		}
		t.Errorf("canonical output should be 2-space indented; got: %s", snippet)
	}
}

func TestCanonicalNoTrailingNewline(t *testing.T) {
	r := Report{
		SchemaVersion: SchemaVersion,
		ProducedBy:    "coldstep-report-go@test",
		GeneratedAt:   "2026-04-28T22:00:00Z",
	}
	b, err := MarshalCanonical(&r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("marshal returned empty output")
	}
	if b[len(b)-1] == '\n' {
		t.Fatalf("canonical output should not end with newline")
	}
}

func TestCanonicalMapKeysSorted(t *testing.T) {
	r := Report{
		SchemaVersion: SchemaVersion,
		ProducedBy:    "coldstep-report-go@test",
		GeneratedAt:   "2026-04-28T22:00:00Z",
		CapabilityEval: CapabilityEval{
			Weights: map[string]float64{
				"z": 1,
				"a": 2,
				"m": 3,
			},
		},
	}
	b, err := MarshalCanonical(&r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	aIdx := strings.Index(s, "\"a\":")
	mIdx := strings.Index(s, "\"m\":")
	zIdx := strings.Index(s, "\"z\":")
	if aIdx == -1 || mIdx == -1 || zIdx == -1 {
		t.Fatalf("expected keys a, m, z in output; got: %s", s)
	}
	if !(aIdx < mIdx && mIdx < zIdx) {
		t.Fatalf("expected map keys sorted as a,m,z; got output: %s", s)
	}
}
