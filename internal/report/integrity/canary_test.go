package integrity

import (
	"testing"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

func TestEvaluateCanariesAllPresent(t *testing.T) {
	events := []model.Event{
		{"type": "exec", "comm": "bash"},
		{"type": "udp", "dst": "8.8.8.8"},
		{"type": "tls", "sni": "theclouddj.com"},
		{"type": "fs_event", "op": "chmod", "path": "/tmp/not-important"},
		{"type": "bpf_audit", "comm": "bpftool", "cmd": 3},
	}
	reasons, seen, required := EvaluateCanaries(events, DefaultCanaryRules())
	if len(reasons) != 0 {
		t.Errorf("reasons = %v; want []", reasons)
	}
	if got, want := len(seen), len(required); got != want {
		t.Errorf("seen=%d required=%d", got, want)
	}
}

func TestEvaluateCanariesMissingOne(t *testing.T) {
	events := []model.Event{
		{"type": "exec", "comm": "bash"},
		{"type": "udp", "dst": "8.8.8.8"},
		{"type": "tls", "sni": "theclouddj.com"},
		{"type": "fs_event", "op": "chmod"},
		// missing bpf_audit / bpftool
	}
	reasons, _, _ := EvaluateCanaries(events, DefaultCanaryRules())
	if len(reasons) != 1 {
		t.Fatalf("reasons=%v; want one", reasons)
	}
	if reasons[0].Code != model.ReasonCanaryMissing {
		t.Errorf("code=%q; want %q", reasons[0].Code, model.ReasonCanaryMissing)
	}
	if reasons[0].Rule != "canary_bpftool_audit" {
		t.Errorf("rule=%q; want canary_bpftool_audit", reasons[0].Rule)
	}
	if reasons[0].Severity != model.SeverityWarn {
		t.Errorf("severity=%q; want warn", reasons[0].Severity)
	}
}
