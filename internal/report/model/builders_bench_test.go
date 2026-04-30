package model

import "testing"

func BenchmarkFingerprintCounts_tcpBaseline(b *testing.B) {
	ev := make([]Event, 1024)
	for i := range ev {
		ev[i] = Event{
			"type":  "tcp",
			"dst":   "203.0.113.1",
			"dport": float64(443),
			"fqdn":  "bench.example",
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fingerprintCounts(ev)
	}
}

func BenchmarkBuildDiff_identical512(b *testing.B) {
	cur := make([]Event, 512)
	base := make([]Event, 512)
	for i := range cur {
		cur[i] = Event{
			"type":  "tcp",
			"dst":   "198.51.100.1",
			"dport": float64(443),
			"fqdn":  "same.example",
		}
		base[i] = Event{
			"type":  "tcp",
			"dst":   "198.51.100.1",
			"dport": float64(443),
			"fqdn":  "same.example",
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildDiff(cur, base)
	}
}

func BenchmarkBuildDiff_divergent512(b *testing.B) {
	cur := make([]Event, 512)
	base := make([]Event, 512)
	for i := range cur {
		cur[i] = Event{
			"type":  "tcp",
			"dst":   "198.51.100.2",
			"dport": float64(443),
			"fqdn":  "cur.example",
		}
		base[i] = Event{
			"type":  "tcp",
			"dst":   "198.51.100.3",
			"dport": float64(443),
			"fqdn":  "base.example",
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildDiff(cur, base)
	}
}
