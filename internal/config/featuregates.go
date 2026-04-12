package config

import "strings"

// ParseFeatureGates parses COLDSTEP_FEATURE_GATES: comma-separated k=v pairs.
// Keys are lowercased; values preserve case (trimmed). Invalid segments are skipped.
func ParseFeatureGates(raw string) map[string]string {
	out := make(map[string]string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			continue
		}
		out[strings.ToLower(k)] = v
	}
	return out
}

// FeatureGateEnabled reports whether key is enabled (case-insensitive key).
// Truthy values: 1, true, yes, on (case-insensitive).
func FeatureGateEnabled(m map[string]string, key string) bool {
	if len(m) == 0 {
		return false
	}
	v, ok := m[strings.ToLower(strings.TrimSpace(key))]
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
