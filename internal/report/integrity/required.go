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

// CheckBPFTamper returns a hard-fail Reason when any bpf_tamper JSONL event
// is present in the input stream. The agent emits bpf_tamper events from
// watchMapIntegrity (`internal/agent/agent_linux.go`) whenever the in-kernel
// enforce_cfg / allowed_ipv4 / ignored_ipv4_lpm maps drift from the
// programmed snapshot. Surfacing the event here forces integrityScore to 0
// so a report cannot show a healthy verdict while kernel-side policy is
// eroding (M-12 anti-blindness gating).
func CheckBPFTamper(events []model.Event) []model.Reason {
	for _, e := range events {
		if e.AsString("type") == "bpf_tamper" {
			return []model.Reason{{
				Code:     model.ReasonBPFMapTamperDetected,
				Type:     "bpf_tamper",
				Severity: model.SeverityFail,
			}}
		}
	}
	return nil
}
