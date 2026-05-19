package report

import "testing"

func TestFormatTCPResultBreakdown(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		counts map[string]int
		want   string
	}{
		{"empty", nil, ""},
		{"all_zero", map[string]int{"established": 0, "refused": 0}, ""},
		{"only_established", map[string]int{"established": 18}, "18 established"},
		{"established_refused_timeout", map[string]int{
			"established": 18, "refused": 3, "timeout": 1,
		}, "18 established · 3 refused · 1 timeout"},
		{"ordering_matches_buckets", map[string]int{
			"timeout": 1, "established": 5, "refused": 2,
		}, "5 established · 2 refused · 1 timeout"},
		{"unknown_bucket_ignored", map[string]int{
			"established": 4, "weird_bucket": 99,
		}, "4 established"},
		{"includes_in_progress_and_denied", map[string]int{
			"established": 2, "in_progress": 1, "denied": 1,
		}, "2 established · 1 in_progress · 1 denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatTCPResultBreakdown(tc.counts); got != tc.want {
				t.Fatalf("formatTCPResultBreakdown(%v) = %q, want %q", tc.counts, got, tc.want)
			}
		})
	}
}

func TestHasTCPResultBreakdown(t *testing.T) {
	t.Parallel()
	if hasTCPResultBreakdown(nil) {
		t.Fatal("nil counts should not register a breakdown")
	}
	if hasTCPResultBreakdown(map[string]int{"established": 0, "refused": 0}) {
		t.Fatal("all-zero counts should not register a breakdown")
	}
	if !hasTCPResultBreakdown(map[string]int{"established": 1}) {
		t.Fatal("non-zero count should register a breakdown")
	}
}
