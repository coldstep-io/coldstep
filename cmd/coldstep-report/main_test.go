package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestBuildModelWithUnreadableBaselineDoesNotFail(t *testing.T) {
	tmp := t.TempDir()
	current := filepath.Join(tmp, "events.jsonl")
	baseline := filepath.Join(tmp, "missing-baseline.jsonl")
	out := filepath.Join(tmp, "model.json")
	if err := os.WriteFile(current, []byte("{\"type\":\"meta\"}\n{\"type\":\"exec\"}\n{\"type\":\"tcp\"}\n"), 0o644); err != nil {
		t.Fatalf("setup current: %v", err)
	}
	if err := buildModel([]string{"--current=" + current, "--baseline=" + baseline, "--out=" + out}); err != nil {
		t.Fatalf("buildModel with missing baseline: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	diff, ok := m["diff"].(map[string]any)
	if !ok {
		t.Fatalf("diff section missing or wrong type: %#v", m["diff"])
	}
	if got, want := diff["status"], "unavailable"; got != want {
		t.Errorf("diff.status = %v; want %s", got, want)
	}
}

func TestAssertIntegrityPassExitsZero(t *testing.T) {
	in := writeModelFixture(t, `{"schema_version":"3.0","capability_eval":{"verdict":"pass","score":95,"reasons":[]}}`)
	if err := assertIntegrity([]string{"--in=" + in}); err != nil {
		t.Errorf("assertIntegrity(pass) = %v; want nil", err)
	}
}

func TestAssertIntegrityWarnExitsZero(t *testing.T) {
	in := writeModelFixture(t, `{"schema_version":"3.0","capability_eval":{"verdict":"warn","score":75,"reasons":[{"code":"CANARY_MISSING","rule":"canary_tls_egress","severity":"warn"}]}}`)
	if err := assertIntegrity([]string{"--in=" + in}); err != nil {
		t.Errorf("assertIntegrity(warn) = %v; want nil", err)
	}
}

func TestAssertIntegrityFailReturnsError(t *testing.T) {
	in := writeModelFixture(t, `{"schema_version":"3.0","capability_eval":{"verdict":"fail","score":40,"reasons":[{"code":"REQUIRED_TYPE_MISSING","type":"tcp","severity":"fail"}]}}`)
	err := assertIntegrity([]string{"--in=" + in})
	if err == nil {
		t.Fatal("assertIntegrity(fail) = nil; want non-nil")
	}
	if !strings.Contains(err.Error(), "verdict=fail") {
		t.Errorf("assertIntegrity(fail) error = %q; want verdict=fail marker", err.Error())
	}
}

func TestAssertIntegrityUnknownVerdictReturnsError(t *testing.T) {
	in := writeModelFixture(t, `{"schema_version":"3.0","capability_eval":{"verdict":"","score":0,"reasons":[]}}`)
	err := assertIntegrity([]string{"--in=" + in})
	if err == nil {
		t.Fatal("assertIntegrity(empty verdict) = nil; want non-nil")
	}
	if !strings.Contains(err.Error(), "missing or unsupported") {
		t.Errorf("assertIntegrity(empty verdict) error = %q; want missing-or-unsupported marker", err.Error())
	}
}

func writeModelFixture(t *testing.T, payload string) string {
	t.Helper()
	tmp := t.TempDir()
	in := filepath.Join(tmp, "model.json")
	if err := os.WriteFile(in, []byte(payload), 0o644); err != nil {
		t.Fatalf("setup fixture: %v", err)
	}
	return in
}
