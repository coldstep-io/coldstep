package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildModelEmitsSchemaV30AndAllRequiredKeys(t *testing.T) {
	tmp := t.TempDir()
	jsonl := filepath.Join(tmp, "events.jsonl")
	if err := os.WriteFile(jsonl, []byte(`{"type":"meta"}
{"type":"exec","comm":"bash"}
{"type":"tcp","dst":"1.1.1.1"}
`), 0o644); err != nil {
		t.Fatalf("setup jsonl: %v", err)
	}
	out := filepath.Join(tmp, "model.json")
	if err := buildModel([]string{"--current=" + jsonl, "--out=" + out}); err != nil {
		t.Fatalf("buildModel: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["schema_version"] != "3.0" {
		t.Errorf("schema_version = %v; want 3.0", m["schema_version"])
	}
	if _, ok := m["capability_eval"]; !ok {
		t.Error("missing capability_eval")
	}
	if _, ok := m["capability_matrix"]; !ok {
		t.Error("missing capability_matrix")
	}
}
