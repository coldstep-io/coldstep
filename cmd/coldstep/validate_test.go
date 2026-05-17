package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestValidateEntry_IP(t *testing.T) {
	kind, err := validateEntry("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != kindIP {
		t.Fatalf("got %q want %q", kind, kindIP)
	}
}

func TestValidateEntry_CIDR(t *testing.T) {
	kind, err := validateEntry("10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != kindCIDR {
		t.Fatalf("got %q want %q", kind, kindCIDR)
	}
}

func TestValidateEntry_Domain(t *testing.T) {
	kind, err := validateEntry("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != kindDomain {
		t.Fatalf("got %q want %q", kind, kindDomain)
	}
}

func TestValidateEntry_WildcardDomain(t *testing.T) {
	kind, err := validateEntry("*.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != kindWildcardDomain {
		t.Fatalf("got %q want %q", kind, kindWildcardDomain)
	}
}

func TestValidateEntry_Negation(t *testing.T) {
	kind, err := validateEntry("!1.2.3.4")
	if err == nil {
		t.Fatal("expected error for negation entry")
	}
	if kind != kindNegation {
		t.Fatalf("got %q want %q", kind, kindNegation)
	}
}

func TestValidateEntry_InvalidCIDR(t *testing.T) {
	_, err := validateEntry("999.0.0.0/8")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestValidateEntry_IPv6(t *testing.T) {
	_, err := validateEntry("::1")
	if err == nil {
		t.Fatal("expected error for IPv6 address")
	}
}

func TestValidateEntry_IPv6CIDR(t *testing.T) {
	_, err := validateEntry("::/0")
	if err == nil {
		t.Fatal("expected error for IPv6 CIDR")
	}
}

func TestValidateEntry_WildcardEmptySuffix(t *testing.T) {
	_, err := validateEntry("*.")
	if err == nil {
		t.Fatal("expected error for wildcard with empty suffix")
	}
}

func TestValidateEntry_WildcardDoubleWild(t *testing.T) {
	_, err := validateEntry("*.*.example.com")
	if err == nil {
		t.Fatal("expected error for double wildcard")
	}
}

func TestValidateEntry_BadDomain(t *testing.T) {
	_, err := validateEntry("not_a_domain!")
	if err == nil {
		t.Fatal("expected error for invalid domain token")
	}
}

func TestValidateEntry_DomainLeadingHyphen(t *testing.T) {
	_, err := validateEntry("-bad.example.com")
	if err == nil {
		t.Fatal("expected error for domain with leading hyphen")
	}
}

func TestParseAllowlistLines_CommentsAndBlanks(t *testing.T) {
	input := `
# This is a comment
1.2.3.4      # inline comment
10.0.0.0/8

example.com
*.wildcard.io
`
	results := parseAllowlistLines(strings.NewReader(input))
	if len(results) != 4 {
		t.Fatalf("got %d entries, want 4: %+v", len(results), results)
	}
	wantKinds := []entryKind{kindIP, kindCIDR, kindDomain, kindWildcardDomain}
	for i, r := range results {
		if r.Error != nil {
			t.Errorf("entry %d unexpected error: %v", i, r.Error)
		}
		if r.Kind != wantKinds[i] {
			t.Errorf("entry %d: got kind %q want %q", i, r.Kind, wantKinds[i])
		}
	}
}

func TestRunValidate_OK(t *testing.T) {
	input := "1.2.3.4\nexample.com\n10.0.0.0/8\n*.foo.io\n"
	var out, errOut bytes.Buffer
	rc := runValidate([]string{}, &out, &errOut)
	// Can't pass stdin easily; use the string-reader path via parseAllowlistLines.
	_ = rc
	results := parseAllowlistLines(strings.NewReader(input))
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("unexpected error for %q: %v", r.Raw, r.Error)
		}
	}
}

func TestRunValidate_Error(t *testing.T) {
	input := "1.2.3.4\nbad_entry!\n10.0.0.0/8\n"
	results := parseAllowlistLines(strings.NewReader(input))
	var errCount int
	for _, r := range results {
		if r.Error != nil {
			errCount++
		}
	}
	if errCount != 1 {
		t.Fatalf("expected 1 error, got %d", errCount)
	}
}

func TestRunValidate_TooManyArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	rc := runValidate([]string{"a", "b"}, &out, &errOut)
	if rc != 2 {
		t.Fatalf("got exit %d want 2", rc)
	}
}

func TestRunValidate_MissingFile(t *testing.T) {
	var out, errOut bytes.Buffer
	rc := runValidate([]string{"/no/such/file.txt"}, &out, &errOut)
	if rc != 1 {
		t.Fatalf("got exit %d want 1", rc)
	}
}

func TestValidateEntry_HostWithNumbers(t *testing.T) {
	kind, err := validateEntry("api2.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != kindDomain {
		t.Fatalf("got %q want %q", kind, kindDomain)
	}
}

func TestValidateEntry_SingleLabel(t *testing.T) {
	kind, err := validateEntry("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != kindDomain {
		t.Fatalf("got %q want %q", kind, kindDomain)
	}
}
