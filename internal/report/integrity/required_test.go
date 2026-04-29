package integrity

import (
	"testing"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

func TestCheckRequiredTypesAllPresentReturnsNoReasons(t *testing.T) {
	events := []model.Event{
		{"type": "meta"},
		{"type": "exec"},
		{"type": "tcp"},
	}
	reasons, seen := CheckRequiredTypes(events, DefaultRequiredTypes())
	if len(reasons) != 0 {
		t.Errorf("reasons = %v; want []", reasons)
	}
	if len(seen) != 3 {
		t.Errorf("seen types count = %d; want 3", len(seen))
	}
}

func TestCheckRequiredTypesMissingTypeReturnsReason(t *testing.T) {
	events := []model.Event{
		{"type": "meta"},
		{"type": "exec"},
		// no tcp
	}
	reasons, _ := CheckRequiredTypes(events, DefaultRequiredTypes())
	if len(reasons) != 1 {
		t.Fatalf("reasons = %v; want exactly one", reasons)
	}
	r := reasons[0]
	if r.Code != model.ReasonRequiredTypeMissing {
		t.Errorf("reason code = %q; want %q", r.Code, model.ReasonRequiredTypeMissing)
	}
	if r.Type != "tcp" {
		t.Errorf("reason type = %q; want tcp", r.Type)
	}
	if r.Severity != model.SeverityFail {
		t.Errorf("reason severity = %q; want fail", r.Severity)
	}
}
