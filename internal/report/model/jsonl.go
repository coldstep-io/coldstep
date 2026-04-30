package model

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Event map[string]any

// Production caps for JSONL ingest (CI-generated files; hostile inputs must not OOM the runner).
const (
	maxJSONLFileBytes    int64 = 256 << 20 // refuse huge files before scanning
	maxJSONLScanLines          = 5_000_000
	maxJSONLParsedEvents       = 2_000_000
)

type loadEventsLimits struct {
	maxFileBytes int64
	maxScanLines int
	maxParsed    int
}

// LoadEvents parses JSONL with malformed-line tolerance (matches Python
// _load_jsonl behaviour). Empty lines and unparseable lines are skipped.
func LoadEvents(path string) ([]Event, error) {
	return loadEvents(path, loadEventsLimits{
		maxFileBytes: maxJSONLFileBytes,
		maxScanLines: maxJSONLScanLines,
		maxParsed:    maxJSONLParsedEvents,
	})
}

func loadEvents(path string, lim loadEventsLimits) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > lim.maxFileBytes {
		return nil, fmt.Errorf("jsonl file exceeds max size (%d bytes)", lim.maxFileBytes)
	}

	out := make([]Event, 0, 64)
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 4*1024*1024)
	scanLines := 0
	for s.Scan() {
		scanLines++
		if scanLines > lim.maxScanLines {
			return nil, fmt.Errorf("jsonl exceeds max scan line count (%d)", lim.maxScanLines)
		}
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if len(out) >= lim.maxParsed {
			return nil, fmt.Errorf("jsonl exceeds max parsed events (%d)", lim.maxParsed)
		}
		out = append(out, ev)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// AsString safely extracts a string field from an Event; returns "" if missing or wrong type.
func (e Event) AsString(key string) string {
	v, ok := e[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}
