package telemetry

import (
	"bytes"
	"strings"
)

// normalizeHostHeader returns the host part of an HTTP Host header value, without a port.
// Bracketed IPv6 literals may include a port after the closing bracket (e.g. "[::1]:8080").
func normalizeHostHeader(val string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return "?"
	}
	if strings.HasPrefix(val, "[") {
		end := strings.IndexByte(val, ']')
		if end > 1 {
			return val[1:end]
		}
		return "?"
	}
	if i := strings.IndexByte(val, ':'); i >= 0 {
		return val[:i]
	}
	return val
}

// ParseHTTPRequestPrefix extracts method, host, and path from the first bytes of a cleartext HTTP/1.x request.
// Tolerates partial buffers; returns ok=false if no recognizable request line.
func ParseHTTPRequestPrefix(raw []byte) (method, host, path string, ok bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 8 {
		return "", "", "", false
	}
	lineEnd := bytes.Index(raw, []byte("\r\n"))
	if lineEnd < 0 {
		lineEnd = bytes.IndexByte(raw, '\n')
	}
	if lineEnd < 0 {
		lineEnd = len(raw)
		if lineEnd > 256 {
			lineEnd = 256
		}
	}
	reqLine := raw[:lineEnd]
	parts := bytes.Fields(reqLine)
	if len(parts) < 3 {
		return "", "", "", false
	}
	method = string(parts[0])
	path = string(parts[1])
	if path == "" || path[0] != '/' {
		return "", "", "", false
	}
	rest := raw[lineEnd:]
	rest = skipEOL(rest)
	for len(rest) > 0 {
		var line []byte
		line, rest = takeLine(rest)
		if len(line) == 0 {
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name := strings.TrimSpace(strings.ToLower(string(line[:colon])))
		val := strings.TrimSpace(string(line[colon+1:]))
		if name == "host" && val != "" {
			host = normalizeHostHeader(val)
			break
		}
	}
	if host == "" {
		host = "?"
	}
	return method, host, path, true
}

func skipEOL(b []byte) []byte {
	b = bytes.TrimPrefix(b, []byte("\r\n"))
	b = bytes.TrimPrefix(b, []byte("\n"))
	return b
}

// takeLine removes one line from the front of b (LF or CRLF) and returns the line without terminators.
func takeLine(b []byte) (line, rest []byte) {
	if len(b) == 0 {
		return nil, b
	}
	if i := bytes.Index(b, []byte("\r\n")); i >= 0 {
		return b[:i], b[i+2:]
	}
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[:i], b[i+1:]
	}
	return b, nil
}
