package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/coldstep-io/coldstep/internal/atomicwrite"
	"github.com/coldstep-io/coldstep/internal/report/model"
)

// Loose upper bound so a hostile or corrupted artifact cannot exhaust memory in-process.
const maxReportModelJSONBytes = 64 << 20

func readModelMap(path string) (map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxReportModelJSONBytes+1))
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

// writeModelMap persists an enrichment-modified report model using the same
// canonical encoder as `build-model`: 2-space indent, no HTML escaping, no
// trailing newline. Plain json.Marshal would re-introduce HTML escaping on
// `<`/`>`/`&` (silently rewriting PTR records or suspicious domain names) and
// drop the indentation, diverging from the post-build-model snapshot so
// downstream attestation hashes stop matching.
func writeModelMap(path string, m map[string]any) error {
	raw, err := model.MarshalCanonicalValue(m)
	if err != nil {
		return err
	}
	return atomicwrite.Bytes(path, raw, 0o644)
}
