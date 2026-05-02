package integrity

import (
	"sort"
	"strconv"
	"strings"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

type CanaryRule struct {
	Name string
	Type string
	All  map[string]string
}

// DefaultCanaryRules matches scripts/coldstep_detect_report/build_report_model.py
// canary_rules (subset predicates matched against JSONL events).
func DefaultCanaryRules() []CanaryRule {
	return []CanaryRule{
		{Name: "canary_demo_exec", Type: "exec", All: map[string]string{"comm": "bash"}},
		{Name: "canary_dns_lookup", Type: "udp", All: map[string]string{"dst": "8.8.8.8"}},
		{Name: "canary_bpftool_audit", Type: "bpf_audit", All: map[string]string{"comm": "bpftool"}},
		{Name: "canary_fs_chmod", Type: "fs_event", All: map[string]string{"op": "chmod"}},
		{Name: "canary_tls_egress", Type: "tls", All: map[string]string{"sni": "theclouddj.com"}},
	}
}

// EvaluateCanaries returns missing-canary reasons plus sorted seen/required names.
func EvaluateCanaries(events []model.Event, rules []CanaryRule) ([]model.Reason, []string, []string) {
	seen := map[string]struct{}{}
	required := make([]string, 0, len(rules))
	for _, r := range rules {
		required = append(required, r.Name)
		for _, ev := range events {
			if !matchRule(ev, r) {
				continue
			}
			seen[r.Name] = struct{}{}
			break
		}
	}
	sort.Strings(required)
	seenList := make([]string, 0, len(seen))
	for k := range seen {
		seenList = append(seenList, k)
	}
	sort.Strings(seenList)

	var reasons []model.Reason
	for _, req := range required {
		if _, ok := seen[req]; ok {
			continue
		}
		reasons = append(reasons, model.Reason{
			Code:     model.ReasonCanaryMissing,
			Rule:     req,
			Severity: model.SeverityWarn,
		})
	}
	return reasons, seenList, required
}

func matchRule(ev model.Event, r CanaryRule) bool {
	if ev.AsString("type") != r.Type {
		return false
	}
	for k, want := range r.All {
		got := strings.TrimSpace(toString(ev[k]))
		if got != want {
			return false
		}
	}
	return true
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strings.TrimSpace(strconv.FormatFloat(x, 'f', -1, 64))
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	default:
		return ""
	}
}
