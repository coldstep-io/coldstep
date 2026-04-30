package integrity

import (
	"testing"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

func TestEvaluatePassesWhenScoresHighAndNoHardFails(t *testing.T) {
	events := []model.Event{
		{"type": "meta"},
		{"type": "exec", "comm": "bash"},
		{"type": "tcp"},
		{"type": "udp", "dst": "8.8.8.8"},
		{"type": "tls", "sni": "theclouddj.com"},
		{"type": "http"},
		{"type": "proc_fork"},
		{"type": "fs_event", "op": "chmod"},
		{"type": "bpf_audit", "comm": "bpftool"},
	}
	eval := Evaluate(events)
	if eval.Verdict != VerdictPass {
		t.Errorf("verdict=%q; want pass", eval.Verdict)
	}
	if eval.Score < DefaultPassThreshold {
		t.Errorf("score=%d; want >= %d", eval.Score, DefaultPassThreshold)
	}
	if len(eval.Reasons) != 0 {
		t.Errorf("reasons=%v; want []", eval.Reasons)
	}
}

func TestEvaluateForDetectProfileEnhancedRequiresStreams(t *testing.T) {
	events := []model.Event{{"type": "meta"}, {"type": "exec"}, {"type": "tcp"}}
	eval := EvaluateForDetectProfile(events, "enhanced")
	if eval.Verdict != VerdictFail {
		t.Fatalf("verdict=%q; want fail (missing udp/http/tls/proc_fork/fs_event)", eval.Verdict)
	}
}

func TestEvaluateFailsWhenRequiredTypeMissing(t *testing.T) {
	events := []model.Event{{"type": "meta"}, {"type": "exec"}} // missing tcp
	eval := Evaluate(events)
	if eval.Verdict != VerdictFail {
		t.Errorf("verdict=%q; want fail", eval.Verdict)
	}
	if eval.Score != 0 {
		t.Errorf("score=%d; want 0 on hard fail", eval.Score)
	}
	if len(eval.Reasons) == 0 {
		t.Fatal("expected hard-fail reasons")
	}
	hasRequiredTypeMissing := false
	for _, reason := range eval.Reasons {
		if reason.Code == model.ReasonRequiredTypeMissing {
			hasRequiredTypeMissing = true
			break
		}
	}
	if !hasRequiredTypeMissing {
		t.Errorf("reasons=%v; want at least one %q", eval.Reasons, model.ReasonRequiredTypeMissing)
	}
}

func TestEvaluateWarnsWhenScoreBetweenFailAndPass(t *testing.T) {
	events := []model.Event{
		{"type": "meta"}, {"type": "exec", "comm": "bash"}, {"type": "tcp"},
		// All canaries satisfied; omit http + proc_fork for ~78% coverage → weighted score in warn band.
		{"type": "udp", "dst": "8.8.8.8"},
		{"type": "tls", "sni": "theclouddj.com"},
		{"type": "fs_event", "op": "chmod"},
		{"type": "bpf_audit", "comm": "bpftool"},
	}
	weights := map[string]float64{"integrity": 0.05, "coverage": 0.95, "correlation": 0.0}
	eval := EvaluateWithConfig(events, Config{
		FailThreshold: DefaultFailThreshold,
		PassThreshold: DefaultPassThreshold,
		Weights:       weights,
	})
	if eval.Verdict != VerdictWarn {
		t.Errorf("verdict=%q; want warn", eval.Verdict)
	}
	if eval.Score < DefaultFailThreshold || eval.Score >= DefaultPassThreshold {
		t.Errorf("score=%d; want [%d,%d)", eval.Score, DefaultFailThreshold, DefaultPassThreshold)
	}
}

func TestEvaluateWarnsWhenCanaryMissing(t *testing.T) {
	events := []model.Event{
		{"type": "meta"},
		{"type": "exec", "comm": "bash"},
		{"type": "tcp"},
		{"type": "udp", "dst": "8.8.8.8"},
		// missing tls canary
		{"type": "fs_event", "op": "chmod"},
		{"type": "bpf_audit", "comm": "bpftool"},
	}
	eval := Evaluate(events)
	if eval.Verdict != VerdictWarn {
		t.Fatalf("verdict=%q; want warn", eval.Verdict)
	}
	hasCanaryMissing := false
	for _, r := range eval.Reasons {
		if r.Code == model.ReasonCanaryMissing {
			hasCanaryMissing = true
			if r.Severity != model.SeverityWarn {
				t.Fatalf("canary severity=%q; want warn", r.Severity)
			}
			break
		}
	}
	if !hasCanaryMissing {
		t.Fatalf("reasons=%v; want CANARY_MISSING", eval.Reasons)
	}
}
