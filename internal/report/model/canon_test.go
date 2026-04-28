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
		t.Errorf("canonical output should be 2-space indented; got: %s", string(b1)[:50])
	}
}
