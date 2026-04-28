package model

import (
	"encoding/json"
	"testing"
)

func TestSchemaVersionConstant(t *testing.T) {
	if SchemaVersion != "3.0" {
		t.Errorf("SchemaVersion = %q; want 3.0", SchemaVersion)
	}
}

func TestEmptyReportMarshalsAllRequiredKeys(t *testing.T) {
	r := Report{
		SchemaVersion: SchemaVersion,
		ProducedBy:    "coldstep-report-go@test",
		GeneratedAt:   "2026-04-28T22:00:00Z",
	}
	raw, err := json.Marshal(&r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	asMap := map[string]any{}
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	required := []string{
		"schema_version", "produced_by", "generated_at",
		"run", "capability_matrix", "events_by_type",
		"timeline", "egress_sankey", "diff",
		"ip_classification", "capability_eval", "otx", "rdns",
	}
	for _, k := range required {
		if _, ok := asMap[k]; !ok {
			t.Errorf("missing required key in marshalled report: %q", k)
		}
	}
}
