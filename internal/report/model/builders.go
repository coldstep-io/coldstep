package model

import (
	"sort"
	"strings"
	"time"
)

// requiredCapabilities mirrors REQUIRED_CAPABILITIES from
// scripts/coldstep_detect_report/build_report_model.py.
var requiredCapabilities = []struct {
	ID, Label string
}{
	{"exec", "Exec tracing"},
	{"tcp", "TCP connect telemetry"},
	{"udp", "UDP sendto telemetry"},
	{"http", "HTTP cleartext telemetry"},
	{"tls", "TLS ClientHello/SNI hint"},
	{"proc_fork", "Process tree (fork)"},
	{"fs_event", "Filesystem events"},
	{"bpf_audit", "BPF Syscall Auditing"},
}

var egressTypes = map[string]struct{}{
	"tcp": {}, "udp": {}, "http": {}, "tls": {},
}

func BuildCapabilityMatrix(events []Event) []CapabilityCell {
	counts := map[string]int{}
	for _, e := range events {
		t := e.AsString("type")
		if t != "" {
			counts[t]++
		}
	}
	out := make([]CapabilityCell, 0, len(requiredCapabilities))
	for _, c := range requiredCapabilities {
		n := counts[c.ID]
		status := "fail"
		if n > 0 {
			status = "pass"
		}
		out = append(out, CapabilityCell{
			ID:            c.ID,
			Label:         c.Label,
			Status:        status,
			EvidenceCount: n,
		})
	}
	return out
}

func BuildEventsByType(events []Event) []EventCount {
	counts := map[string]int{}
	for _, e := range events {
		t := e.AsString("type")
		if t == "" {
			t = "<missing>"
		}
		if t == "meta" {
			continue
		}
		counts[t]++
	}
	out := make([]EventCount, 0, len(counts))
	for k, v := range counts {
		out = append(out, EventCount{Type: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func BuildTimeline(events []Event) []TimelineBucket {
	type key struct{ Bucket, Type string }
	counts := map[key]int{}
	for _, e := range events {
		ts := e.AsString("ts")
		typ := e.AsString("type")
		if ts == "" {
			continue
		}
		if typ == "" {
			typ = "<missing>"
		}
		t, err := time.Parse(time.RFC3339Nano, strings.Replace(ts, "Z", "+00:00", 1))
		if err != nil {
			t, err = time.Parse(time.RFC3339, ts)
			if err != nil {
				continue
			}
		}
		bucket := t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
		counts[key{bucket, typ}]++
	}
	out := make([]TimelineBucket, 0, len(counts))
	for k, v := range counts {
		out = append(out, TimelineBucket{Bucket: k.Bucket, Type: k.Type, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bucket != out[j].Bucket {
			return out[i].Bucket < out[j].Bucket
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func BuildEgressSankey(events []Event) []SankeyEdge {
	type key struct{ Source, Target string }
	values := map[key]int{}
	indicators := map[key]map[string]struct{}{}
	for _, e := range events {
		typ := e.AsString("type")
		if _, ok := egressTypes[typ]; !ok {
			continue
		}
		host := firstNonEmpty(
			e.AsString("fqdn"),
			e.AsString("host"),
			e.AsString("sni"),
			e.AsString("dst"),
		)
		if host == "" {
			host = "unknown"
		}
		policy := e.AsString("policy")
		k := key{host, policy}
		values[k]++
		if indicators[k] == nil {
			indicators[k] = map[string]struct{}{}
		}
		for _, ind := range trafficIndicators(e) {
			indicators[k][ind] = struct{}{}
		}
	}
	out := make([]SankeyEdge, 0, len(values))
	for k, v := range values {
		inds := make([]string, 0, len(indicators[k]))
		for ind := range indicators[k] {
			inds = append(inds, ind)
		}
		sort.Strings(inds)
		out = append(out, SankeyEdge{
			Source:     k.Source,
			Target:     k.Target,
			Value:      v,
			Indicators: inds,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Target < out[j].Target
	})
	return out
}

func BuildDiff(current []Event, baseline []Event) DiffPayload {
	if baseline == nil {
		return DiffPayload{
			Status:         "unavailable",
			Reason:         "no_baseline_provided",
			TrafficNew:     []DiffEntry{},
			TrafficGone:    []DiffEntry{},
			TrafficChanged: []DiffChanged{},
		}
	}
	// Minimal diff: count events by (type,dst,sni,host,fqdn) tuple. Plan 4 may
	// extend this to match the Python ci_coldstep_jsonl_traffic_diff fingerprint.
	cur := fingerprintCounts(current)
	base := fingerprintCounts(baseline)
	fpIndicators := map[string]map[string]struct{}{}
	addFingerprintIndicators := func(events []Event) {
		for _, e := range events {
			typ := e.AsString("type")
			if _, ok := egressTypes[typ]; !ok {
				continue
			}
			host := firstNonEmpty(e.AsString("fqdn"), e.AsString("host"), e.AsString("sni"), e.AsString("dst"))
			fp := typ + "»" + host
			if fpIndicators[fp] == nil {
				fpIndicators[fp] = map[string]struct{}{}
			}
			for _, ind := range trafficIndicators(e) {
				fpIndicators[fp][ind] = struct{}{}
			}
		}
	}
	addFingerprintIndicators(current)
	addFingerprintIndicators(baseline)
	out := DiffPayload{
		Status:         "ok",
		TrafficNew:     []DiffEntry{},
		TrafficGone:    []DiffEntry{},
		TrafficChanged: []DiffChanged{},
	}
	for fp, n := range cur {
		if _, ok := base[fp]; !ok {
			out.TrafficNew = append(out.TrafficNew, DiffEntry{
				Count:       n,
				Fingerprint: fp,
				Indicators:  sortedIndicators(fpIndicators[fp]),
			})
		}
	}
	for fp, n := range base {
		if _, ok := cur[fp]; !ok {
			out.TrafficGone = append(out.TrafficGone, DiffEntry{
				Count:       n,
				Fingerprint: fp,
				Indicators:  sortedIndicators(fpIndicators[fp]),
			})
		}
	}
	for fp, n := range cur {
		if b, ok := base[fp]; ok && b != n {
			out.TrafficChanged = append(out.TrafficChanged, DiffChanged{
				Baseline:    b,
				Current:     n,
				Fingerprint: fp,
				Indicators:  sortedIndicators(fpIndicators[fp]),
			})
		}
	}
	sort.Slice(out.TrafficNew, func(i, j int) bool { return out.TrafficNew[i].Fingerprint < out.TrafficNew[j].Fingerprint })
	sort.Slice(out.TrafficGone, func(i, j int) bool { return out.TrafficGone[i].Fingerprint < out.TrafficGone[j].Fingerprint })
	sort.Slice(out.TrafficChanged, func(i, j int) bool { return out.TrafficChanged[i].Fingerprint < out.TrafficChanged[j].Fingerprint })
	return out
}

func trafficIndicators(e Event) []string {
	out := []string{}
	seen := map[string]struct{}{}
	add := func(v string) {
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	dst := e.AsString("dst")
	if dst != "" && dst != "0.0.0.0" {
		add(dst)
	}
	add(firstNonEmpty(e.AsString("fqdn"), e.AsString("sni"), e.AsString("host")))
	return out
}

func sortedIndicators(set map[string]struct{}) []string {
	if len(set) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(set))
	for ind := range set {
		out = append(out, ind)
	}
	sort.Strings(out)
	return out
}

func fingerprintCounts(events []Event) map[string]int {
	out := map[string]int{}
	for _, e := range events {
		typ := e.AsString("type")
		if _, ok := egressTypes[typ]; !ok {
			continue
		}
		host := firstNonEmpty(e.AsString("fqdn"), e.AsString("host"), e.AsString("sni"), e.AsString("dst"))
		fp := typ + "»" + host
		out[fp]++
	}
	return out
}

func firstNonEmpty(args ...string) string {
	for _, a := range args {
		if a != "" {
			return a
		}
	}
	return ""
}
