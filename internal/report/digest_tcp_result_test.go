package report

import (
	"strings"
	"testing"
)

func TestBuildDetectMarkdown_TCPConnectionsKPI(t *testing.T) {
	t.Parallel()

	t.Run("with_breakdown", func(t *testing.T) {
		md := BuildDetectMarkdown(DigestInput{
			ExecTotal: 1,
			TCPTotal:  22,
			TCPResultCounts: map[string]int{
				"established": 18, "refused": 3, "timeout": 1,
			},
			MaxRowsPerSection: 50,
		})
		want := "| **TCP connections** | 18 established · 3 refused · 1 timeout |"
		if !strings.Contains(md, want) {
			t.Fatalf("expected TCP connections KPI row %q in:\n%s", want, md)
		}
		if !strings.Contains(md, "**TCP semantics:** rows reflect `connect(2)` attempts at syscall enter; the **TCP connections** KPI splits them") {
			t.Fatalf("expected updated TCP semantics footnote when breakdown is present; got:\n%s", md)
		}
	})

	t.Run("kretprobe_attach_failed", func(t *testing.T) {
		md := BuildDetectMarkdown(DigestInput{
			ExecTotal:         1,
			TCPTotal:          5,
			TCPResultCounts:   nil,
			MaxRowsPerSection: 50,
		})
		if strings.Contains(md, "| **TCP connections** |") {
			t.Fatalf("did not expect TCP connections KPI row when counts are empty; got:\n%s", md)
		}
		if !strings.Contains(md, "kretprobe on `tcp_v4_connect` failed to attach") {
			t.Fatalf("expected fallback TCP semantics footnote referencing kretprobe attach; got:\n%s", md)
		}
	})
}

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
