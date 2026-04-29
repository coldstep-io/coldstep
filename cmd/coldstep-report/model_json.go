package main

import (
	"encoding/json"
	"os"
)

func readModelMap(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func writeModelMap(path string, m map[string]any) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}
