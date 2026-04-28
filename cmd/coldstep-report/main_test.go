package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempJSONL(t *testing.T, lines []string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "events*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		f.WriteString(l + "\n")
	}
	return f.Name()
}

func TestParseJSONLCounts_BasicTypes(t *testing.T) {
	path := writeTempJSONL(t, []string{
		`{"type":"exec","pid":1,"comm":"bash"}`,
		`{"type":"tcp","pid":2,"dst":"1.2.3.4"}`,
		`{"type":"tcp","pid":3,"dst":"5.6.7.8"}`,
		`{"type":"deny","pid":4}`,
		`{"type":"exec"}`,
	})
	counts, indicators, err := parseJSONLCounts(path)
	if err != nil {
		t.Fatal(err)
	}
	if counts["exec"] != 2 {
		t.Errorf("exec count=%d want 2", counts["exec"])
	}
	if counts["tcp"] != 2 {
		t.Errorf("tcp count=%d want 2", counts["tcp"])
	}
	if counts["deny"] != 1 {
		t.Errorf("deny count=%d want 1", counts["deny"])
	}
	// dst values become indicators
	found := map[string]bool{}
	for _, ind := range indicators {
		found[ind] = true
	}
	if !found["1.2.3.4"] || !found["5.6.7.8"] {
		t.Errorf("indicators missing expected IPs: %v", indicators)
	}
}

func TestParseJSONLCounts_MalformedLinesSkipped(t *testing.T) {
	path := writeTempJSONL(t, []string{
		`{"type":"exec"}`,
		`not-json`,
		``,
		`{"type":"tcp"}`,
	})
	counts, _, err := parseJSONLCounts(path)
	if err != nil {
		t.Fatal(err)
	}
	if counts["exec"] != 1 || counts["tcp"] != 1 {
		t.Errorf("unexpected counts: %v", counts)
	}
}

func TestParseJSONLCounts_EmptyFile(t *testing.T) {
	path := writeTempJSONL(t, nil)
	counts, indicators, err := parseJSONLCounts(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 0 {
		t.Errorf("expected empty counts, got %v", counts)
	}
	if len(indicators) != 0 {
		t.Errorf("expected empty indicators, got %v", indicators)
	}
}

func TestBuildModel_WritesValidJSON(t *testing.T) {
	dir := t.TempDir()
	current := writeTempJSONL(t, []string{
		`{"type":"exec"}`,
		`{"type":"tcp","dst":"1.1.1.1"}`,
	})
	out := filepath.Join(dir, "model.json")
	os.Setenv("COLDSTEP_REPORT_CURRENT_JSONL", current)
	os.Setenv("COLDSTEP_REPORT_MODEL_OUT", out)
	defer os.Unsetenv("COLDSTEP_REPORT_CURRENT_JSONL")
	defer os.Unsetenv("COLDSTEP_REPORT_MODEL_OUT")
	if err := buildModel([]string{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var m reportModel
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, raw)
	}
	if m.Counts["exec"] != 1 || m.Counts["tcp"] != 1 {
		t.Errorf("unexpected counts: %v", m.Counts)
	}
	if !strings.HasPrefix(m.SchemaVersion, "v") {
		t.Errorf("unexpected schema version: %q", m.SchemaVersion)
	}
}

func TestAssertIntegrity_PassWithEvents(t *testing.T) {
	dir := t.TempDir()
	current := writeTempJSONL(t, []string{`{"type":"exec"}`, `{"type":"tcp"}`})
	out := filepath.Join(dir, "model.json")
	os.Setenv("COLDSTEP_REPORT_CURRENT_JSONL", current)
	os.Setenv("COLDSTEP_REPORT_MODEL_OUT", out)
	defer os.Unsetenv("COLDSTEP_REPORT_CURRENT_JSONL")
	defer os.Unsetenv("COLDSTEP_REPORT_MODEL_OUT")
	if err := buildModel([]string{}); err != nil {
		t.Fatal(err)
	}
	os.Setenv("COLDSTEP_REPORT_MODEL_IN", out)
	defer os.Unsetenv("COLDSTEP_REPORT_MODEL_IN")
	if err := assertIntegrity([]string{}); err != nil {
		t.Errorf("expected integrity pass, got: %v", err)
	}
}

func TestAssertIntegrity_FailEmpty(t *testing.T) {
	dir := t.TempDir()
	current := writeTempJSONL(t, nil)
	out := filepath.Join(dir, "model.json")
	os.Setenv("COLDSTEP_REPORT_CURRENT_JSONL", current)
	os.Setenv("COLDSTEP_REPORT_MODEL_OUT", out)
	defer os.Unsetenv("COLDSTEP_REPORT_CURRENT_JSONL")
	defer os.Unsetenv("COLDSTEP_REPORT_MODEL_OUT")
	if err := buildModel([]string{}); err != nil {
		t.Fatal(err)
	}
	os.Setenv("COLDSTEP_REPORT_MODEL_IN", out)
	defer os.Unsetenv("COLDSTEP_REPORT_MODEL_IN")
	if err := assertIntegrity([]string{}); err == nil {
		t.Error("expected integrity failure on empty events, got nil")
	}
}

func TestSumMap(t *testing.T) {
	m := map[string]int{"exec": 3, "tcp": 5, "deny": 1}
	if got := sumMap(m); got != 9 {
		t.Errorf("sumMap=%d want 9", got)
	}
}

func TestSumMap_Empty(t *testing.T) {
	if got := sumMap(map[string]int{}); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestSanitize(t *testing.T) {
	if s := sanitize("foo|bar`baz"); s != "foo·bar'baz" {
		t.Errorf("unexpected: %q", s)
	}
}

func TestMapKeys_Sorted(t *testing.T) {
	m := map[string]int{"z": 1, "a": 2, "m": 3}
	keys := mapKeys(m)
	if keys[0] != "a" || keys[1] != "m" || keys[2] != "z" {
		t.Errorf("keys not sorted: %v", keys)
	}
}

func TestRenderSummary_WritesToFile(t *testing.T) {
	dir := t.TempDir()
	current := writeTempJSONL(t, []string{`{"type":"exec"}`, `{"type":"tcp","dst":"8.8.8.8"}`})
	modelOut := filepath.Join(dir, "model.json")
	summaryOut := filepath.Join(dir, "summary.md")
	os.Setenv("COLDSTEP_REPORT_CURRENT_JSONL", current)
	os.Setenv("COLDSTEP_REPORT_MODEL_OUT", modelOut)
	defer os.Unsetenv("COLDSTEP_REPORT_CURRENT_JSONL")
	defer os.Unsetenv("COLDSTEP_REPORT_MODEL_OUT")
	if err := buildModel([]string{}); err != nil {
		t.Fatal(err)
	}
	os.Setenv("COLDSTEP_REPORT_MODEL_IN", modelOut)
	os.Setenv("GITHUB_STEP_SUMMARY", summaryOut)
	defer os.Unsetenv("COLDSTEP_REPORT_MODEL_IN")
	defer os.Unsetenv("GITHUB_STEP_SUMMARY")
	if err := renderSummary([]string{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(summaryOut)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if !strings.Contains(content, "Coldstep") {
		t.Errorf("expected Coldstep heading in summary: %q", content[:200])
	}
	if !strings.Contains(content, "exec") {
		t.Errorf("expected exec row in summary: %q", content)
	}
}

func TestRenderHTML_WritesHTMLFile(t *testing.T) {
	dir := t.TempDir()
	current := writeTempJSONL(t, []string{`{"type":"exec"}`, `{"type":"deny"}`})
	modelOut := filepath.Join(dir, "model.json")
	htmlOut := filepath.Join(dir, "report.html")
	os.Setenv("COLDSTEP_REPORT_CURRENT_JSONL", current)
	os.Setenv("COLDSTEP_REPORT_MODEL_OUT", modelOut)
	defer os.Unsetenv("COLDSTEP_REPORT_CURRENT_JSONL")
	defer os.Unsetenv("COLDSTEP_REPORT_MODEL_OUT")
	if err := buildModel([]string{}); err != nil {
		t.Fatal(err)
	}
	os.Setenv("COLDSTEP_REPORT_MODEL_IN", modelOut)
	os.Setenv("COLDSTEP_REPORT_HTML_OUT", htmlOut)
	defer os.Unsetenv("COLDSTEP_REPORT_MODEL_IN")
	defer os.Unsetenv("COLDSTEP_REPORT_HTML_OUT")
	if err := renderHTML([]string{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(htmlOut)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if !strings.Contains(content, "<!doctype html>") {
		t.Error("expected HTML doctype")
	}
	if !strings.Contains(content, "exec") {
		t.Error("expected exec in HTML")
	}
}

func TestMarkSkippedEnrichment_WritesSkipField(t *testing.T) {
	dir := t.TempDir()
	current := writeTempJSONL(t, []string{`{"type":"exec"}`})
	modelOut := filepath.Join(dir, "model.json")
	os.Setenv("COLDSTEP_REPORT_CURRENT_JSONL", current)
	os.Setenv("COLDSTEP_REPORT_MODEL_OUT", modelOut)
	defer os.Unsetenv("COLDSTEP_REPORT_CURRENT_JSONL")
	defer os.Unsetenv("COLDSTEP_REPORT_MODEL_OUT")
	if err := buildModel([]string{}); err != nil {
		t.Fatal(err)
	}
	os.Setenv("COLDSTEP_REPORT_MODEL_IN", modelOut)
	defer os.Unsetenv("COLDSTEP_REPORT_MODEL_IN")
	if err := markSkippedEnrichment([]string{}, "otx", "go-otx-skip-v1"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(modelOut)
	var m reportModel
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	otx, ok := m.Extras["otx"].(map[string]any)
	if !ok {
		t.Fatalf("expected otx key in extras, got: %v", m.Extras)
	}
	if otx["skipped"] != "go-otx-skip-v1" {
		t.Errorf("unexpected skip reason: %v", otx["skipped"])
	}
}

func TestDiffSummary_WritesSummaryLine(t *testing.T) {
	dir := t.TempDir()
	current := writeTempJSONL(t, []string{`{"type":"exec"}`, `{"type":"tcp"}`})
	baseline := writeTempJSONL(t, []string{`{"type":"exec"}`})
	summaryOut := filepath.Join(dir, "summary.md")
	if err := diffSummary([]string{
		"--current", current,
		"--baseline", baseline,
		"--summary", summaryOut,
		"--marker", "coldstep-test-diff",
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(summaryOut)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "coldstep-test-diff") {
		t.Errorf("marker not in summary: %q", string(raw))
	}
}
