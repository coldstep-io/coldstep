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
	type key struct {
		Source, Target, Protocol string
		Port                     int
	}
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
		var protocol string
		switch typ {
		case "tcp", "tls", "udp", "http":
			protocol = typ
		case "deny":
			protocol = e.AsString("protocol")
			if protocol == "" {
				protocol = "tcp"
			}
		}
		port := int(e.AsFloat("dport"))
		if port == 0 {
			port = int(e.AsFloat("port"))
		}
		k := key{Source: host, Target: policy, Protocol: protocol, Port: port}
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
			Protocol:   k.Protocol,
			Port:       k.Port,
			Value:      v,
			Indicators: inds,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Target < out[j].Target
	})
	return out
}

func BuildDiff(current []Event, baseline []Event) DiffPayload {
	// An empty (or nil) baseline is "no comparison data," not "everything in
	// current is new" — LoadEvents returns a non-nil empty slice for an empty
	// or unparseable JSONL file, so guard on length rather than nil-ness.
	if len(baseline) == 0 {
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
	//
	// Bug #11: a destination observed once with fqdn populated and once
	// without (DNS cache miss race) would yield two distinct fingerprints —
	// `tcp»example.com` and `tcp»1.2.3.4` — and surface as a spurious
	// traffic_gone + traffic_new pair across otherwise-identical runs.
	// Build a single dst→name map across current + baseline so the dst-only
	// events resolve to the same fingerprint as their name-bearing siblings.
	nameByDst := buildDstNameMap(current, baseline)
	cur := fingerprintCounts(current, nameByDst)
	base := fingerprintCounts(baseline, nameByDst)
	fpIndicators := map[string]map[string]struct{}{}
	addFingerprintIndicators := func(events []Event) {
		for _, e := range events {
			typ := e.AsString("type")
			if _, ok := egressTypes[typ]; !ok {
				continue
			}
			fp := typ + "»" + resolveFingerprintHost(e, nameByDst)
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

func fingerprintCounts(events []Event, nameByDst map[string]string) map[string]int {
	out := map[string]int{}
	for _, e := range events {
		typ := e.AsString("type")
		if _, ok := egressTypes[typ]; !ok {
			continue
		}
		fp := typ + "»" + resolveFingerprintHost(e, nameByDst)
		out[fp]++
	}
	return out
}

// buildDstNameMap collects dst → first-observed name (fqdn / sni / host)
// across all events, so dst-only events resolve to the same fingerprint as
// their name-bearing siblings. Repeated dst with different names keeps the
// first encountered (input order). Empty dst entries are skipped.
func buildDstNameMap(eventSlices ...[]Event) map[string]string {
	out := map[string]string{}
	for _, events := range eventSlices {
		for _, e := range events {
			dst := e.AsString("dst")
			if dst == "" || dst == "0.0.0.0" {
				continue
			}
			if _, ok := out[dst]; ok {
				continue
			}
			name := firstNonEmpty(e.AsString("fqdn"), e.AsString("sni"), e.AsString("host"))
			if name == "" {
				continue
			}
			out[dst] = name
		}
	}
	return out
}

// resolveFingerprintHost picks the host portion of the fingerprint for e.
// Prefers a name on the event itself; falls back to nameByDst (resolved
// across the union of current + baseline events) so dst-only events match
// their name-bearing siblings; finally falls back to dst when no name is
// available anywhere.
func resolveFingerprintHost(e Event, nameByDst map[string]string) string {
	if name := firstNonEmpty(e.AsString("fqdn"), e.AsString("sni"), e.AsString("host")); name != "" {
		return name
	}
	if dst := e.AsString("dst"); dst != "" {
		if name, ok := nameByDst[dst]; ok && name != "" {
			return name
		}
		return dst
	}
	return ""
}

func firstNonEmpty(args ...string) string {
	for _, a := range args {
		if a != "" {
			return a
		}
	}
	return ""
}
