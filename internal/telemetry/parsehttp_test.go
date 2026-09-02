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

func TestParseHTTPRequestPrefix_hostIPv6BracketWithPort(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n")
	m, h, p, ok := ParseHTTPRequestPrefix(raw)
	if !ok || m != "GET" || h != "2001:db8::1" || p != "/" {
		t.Fatalf("got method=%q host=%q path=%q ok=%v", m, h, p, ok)
	}
}

func TestParseHTTPRequestPrefix_hostIPv6BracketNoPort(t *testing.T) {
	raw := []byte("GET /x HTTP/1.1\r\nHost: [2001:db8::2]\r\n\r\n")
	m, h, p, ok := ParseHTTPRequestPrefix(raw)
	if !ok || m != "GET" || h != "2001:db8::2" || p != "/x" {
		t.Fatalf("got method=%q host=%q path=%q ok=%v", m, h, p, ok)
	}
}

func TestParseHTTPRequestPrefix_hostMalformedIPv6Bracket(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: [::1\r\n\r\n")
	_, h, _, ok := ParseHTTPRequestPrefix(raw)
	if !ok || h != "?" {
		t.Fatalf("want placeholder host for unclosed bracket, ok=%v host=%q", ok, h)
	}
}

// TestParseHTTPRequestPrefix_hostTruncatedMidValue guards against reporting a
// shorter, wrong hostname when the capture window cuts the Host header
// mid-value with no trailing CRLF. The placeholder "?" is preferred over a
// silently-truncated value that could pass an allowlist check meant for the
// full domain.
func TestParseHTTPRequestPrefix_hostTruncatedMidValue(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: api.github")
	_, h, _, ok := ParseHTTPRequestPrefix(raw)
	if !ok || h != "?" {
		t.Fatalf("want placeholder host for truncated Host value, ok=%v host=%q", ok, h)
	}
}
