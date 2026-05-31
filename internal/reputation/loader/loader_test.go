package loader

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// TestVirusTotalStub_WarnsOnceWithoutIP verifies the not-implemented
// stub warning fires at most once per process and never carries an IP,
// even when Enrich is called for multiple distinct IPs.
func TestVirusTotalStub_WarnsOnceWithoutIP(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	v := &virusTotalEnricher{apiKey: "test-key"}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if _, err := v.Enrich(context.Background(), ip); err != nil {
			t.Fatalf("Enrich(%s) returned error: %v", ip, err)
		}
	}

	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		lines++
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line is not valid JSON: %q: %v", line, err)
		}
		if _, ok := entry["ip"]; ok {
			t.Errorf("warning log leaked an ip field: %q", line)
		}
	}
	if lines != 1 {
		t.Errorf("expected exactly 1 warning log entry, got %d:\n%s", lines, buf.String())
	}
}
