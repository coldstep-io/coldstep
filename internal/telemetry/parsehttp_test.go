package telemetry

import "testing"

func TestParseHTTPRequestPrefix(t *testing.T) {
	raw := []byte("GET /foo/bar?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	m, h, p, ok := ParseHTTPRequestPrefix(raw)
	if !ok || m != "GET" || h != "example.com" || p != "/foo/bar?x=1" {
		t.Fatalf("got %q %q %q ok=%v", m, h, p, ok)
	}
}

func TestParseHTTPRequestPrefix_partial(t *testing.T) {
	raw := []byte("POST /api HTTP/1.1\r\nHo")
	m, _, p, ok := ParseHTTPRequestPrefix(raw)
	if !ok || m != "POST" || p != "/api" {
		t.Fatalf("got %q %q ok=%v", m, p, ok)
	}
}
