package model

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
)

type Event map[string]any

// LoadEvents parses JSONL with malformed-line tolerance (matches Python
// _load_jsonl behaviour). Empty lines and unparseable lines are skipped.
func LoadEvents(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make([]Event, 0, 64)
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
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
