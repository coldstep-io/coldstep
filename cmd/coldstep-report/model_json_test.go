package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

// Bug #5: writeModelMap (used by rdns-enrich / otx-enrich) must use the same
// canonical encoder as build-model: 2-space indent, no HTML escaping, no
// trailing newline. The previous json.Marshal path silently rewrote `<`/`>`/`&`
// to their Unicode escapes (corrupting PTR records and suspicious domain
// names) and dropped the indentation, so post-enrichment hashes diverged from
// the post-build-model snapshot.
func TestWriteModelMap_CanonicalRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "model.json")

	payload := map[string]any{
		"schema_version": "v1",
		"dns_lookups": map[string]any{
			// Characters json.Marshal HTML-escapes by default.
			"1.2.3.4":  "evil<script>.example.com",
			"5.6.7.8":  "a&b.example.com",
			"9.10.0.1": "x>y.example.com",
		},
	}
	if err := writeModelMap(p, payload); err != nil {
		t.Fatalf("writeModelMap: %v", err)
	}

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(raw)

	// 1. No HTML escaping — the original characters must survive verbatim.
	for _, want := range []string{
		`evil<script>.example.com`,
		`a&b.example.com`,
		`x>y.example.com`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected literal %q in output; got:\n%s", want, got)
		}
	}
	// The default encoding/json behaviour (HTML escaping on) would rewrite
	// these characters as the unicode escape sequences below. None should
	// appear when SetEscapeHTML(false) is in effect.
	for _, banned := range []string{"\\u003c", "\\u003e", "\\u0026"} {
		if strings.Contains(got, banned) {
			t.Errorf("unexpected JSON HTML-escape sequence %q in output:\n%s", banned, got)
		}
	}

	// 2. Indentation must match build-model (`MarshalCanonical`).
	if !strings.Contains(got, "\n  \"") {
		t.Errorf("expected 2-space indented JSON; got:\n%s", got)
	}

	// 3. No trailing newline.
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		t.Errorf("expected no trailing newline; final byte is %q", raw[len(raw)-1])
	}

	// 4. Byte-identical to MarshalCanonicalValue on the same input — proves
	//    enrichment writes stay in the same hash space as build-model output.
	want, err := model.MarshalCanonicalValue(payload)
	if err != nil {
		t.Fatalf("MarshalCanonicalValue: %v", err)
	}
	if string(raw) != string(want) {
		t.Errorf("writeModelMap output diverges from canonical encoder:\n--- got ---\n%s\n--- want ---\n%s", raw, want)
	}
}

func TestWriteModelMap_RoundTripReadsBack(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "model.json")

	payload := map[string]any{"dns_lookups": map[string]any{"1.2.3.4": "a<b&c>d.example.com"}}
	if err := writeModelMap(p, payload); err != nil {
		t.Fatalf("writeModelMap: %v", err)
	}
	round, err := readModelMap(p)
	if err != nil {
		t.Fatalf("readModelMap: %v", err)
	}
	lookups, ok := round["dns_lookups"].(map[string]any)
	if !ok {
		t.Fatalf("dns_lookups missing or wrong type: %#v", round["dns_lookups"])
	}
	if got := lookups["1.2.3.4"]; got != "a<b&c>d.example.com" {
		t.Errorf("roundtrip lost characters: got %q", got)
	}
}
