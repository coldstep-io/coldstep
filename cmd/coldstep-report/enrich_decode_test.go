package main

import (
	"strings"
	"testing"
)

func TestDecodeOTXGeneralJSON_ValidSmall(t *testing.T) {
	body, err := decodeOTXGeneralJSON(strings.NewReader(`{"pulse_info":{"count":2}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if extractPulseCount(body) != 2 {
		t.Fatalf("pulse count: %#v", body)
	}
}

func TestDecodeOTXGeneralJSON_RejectsOversizedDocument(t *testing.T) {
	// Valid prefix + huge string ensures the decoder reads past otxMaxResponseJSONBytes and fails.
	payload := `{"k":"` + strings.Repeat("x", otxMaxResponseJSONBytes) + `"}`
	_, err := decodeOTXGeneralJSON(strings.NewReader(payload))
	if err == nil {
		t.Fatal("expected error for oversized JSON document")
	}
}
