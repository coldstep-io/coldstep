package integrity

import (
	"sort"
	"strings"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

func DefaultRequiredTypes() []string {
	return []string{"meta", "exec", "tcp"}
}

// RequiredTypesForDetectProfile returns required JSONL event types for integrity scoring.
// "enhanced" expects broader egress/process/fs signals (observe-only; does not block).
func RequiredTypesForDetectProfile(profile string) []string {
	p := strings.ToLower(strings.TrimSpace(profile))
	if p != "enhanced" {
		return DefaultRequiredTypes()
	}
	return []string{"meta", "exec", "tcp", "udp", "http", "tls", "proc_fork", "fs_event"}
}

// CheckRequiredTypes returns one Reason per missing required type and the
// sorted set of observed types.
func CheckRequiredTypes(events []model.Event, required []string) ([]model.Reason, []string) {
	seen := map[string]struct{}{}
	for _, e := range events {
		t := e.AsString("type")
		if t != "" {
			seen[t] = struct{}{}
		}
	}
	var reasons []model.Reason
	for _, req := range required {
		if _, ok := seen[req]; !ok {
			reasons = append(reasons, model.Reason{
				Code:     model.ReasonRequiredTypeMissing,
				Type:     req,
				Severity: model.SeverityFail,
			})
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return reasons, out
}
