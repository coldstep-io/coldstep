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

func DefaultCanaryRules() []CanaryRule {
	return []CanaryRule{
		{Name: "tcp_to_1.1.1.1", Type: "tcp", All: map[string]string{"dst": "1.1.1.1"}},
		{Name: "udp_to_8.8.8.8", Type: "udp", All: map[string]string{"dst": "8.8.8.8"}},
		{Name: "tls_sni_theclouddj", Type: "tls", All: map[string]string{"sni": "theclouddj.com"}},
		{Name: "fs_chmod_tmp", Type: "fs_event", All: map[string]string{"op": "chmod", "path": "/tmp/x"}},
		{Name: "bpf_bpftool_cmd3", Type: "bpf_audit", All: map[string]string{"comm": "bpftool", "cmd": "3"}},
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
			Severity: model.SeverityFail,
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
