package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Loose upper bound so a hostile or corrupted artifact cannot exhaust memory in-process.
const maxReportModelJSONBytes = 64 << 20

func readModelMap(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxReportModelJSONBytes {
		return nil, fmt.Errorf("report model exceeds max size (%d bytes)", maxReportModelJSONBytes)
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
	return atomicWriteBytes(path, raw, 0o644)
}

func atomicWriteBytes(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".coldstep-atomic.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	keepTmp := true
	defer func() {
		if keepTmp {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if runtime.GOOS == "windows" {
			_ = os.Remove(path)
			err = os.Rename(tmpPath, path)
		}
		if err != nil {
			return err
		}
	}
	keepTmp = false
	if perm != 0 {
		_ = os.Chmod(path, perm)
	}
	return nil
}
