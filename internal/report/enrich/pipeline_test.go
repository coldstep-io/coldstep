package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

type fakeSource struct {
	name   string
	delay  time.Duration
	err    error
	rawSet json.RawMessage
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Enrich(ctx context.Context, m *model.Report) error {
	timer := time.NewTimer(f.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		setSlot(m, f.name, json.RawMessage(`{"skipped":"budget_exhausted"}`))
		return nil
	case <-timer.C:
	}
	if f.err != nil {
		return f.err
	}
	setSlot(m, f.name, f.rawSet)
	return nil
}

func TestRunInvokesEachSourceWithItsBudget(t *testing.T) {
	m := &model.Report{}
	s := &fakeSource{name: "otx", rawSet: json.RawMessage(`{"ok":true}`)}
	Run(context.Background(), m, []Source{s}, BudgetFunc(func(string) time.Duration {
		return 100 * time.Millisecond
	}))
	if !strings.Contains(string(m.OTX), `"ok":true`) {
		t.Errorf("otx slot = %s; want ok:true", m.OTX)
	}
}

func TestRunCapturesPipelineErrorAsSkipped(t *testing.T) {
	m := &model.Report{}
	s := &fakeSource{name: "otx", err: errors.New("boom")}
	Run(context.Background(), m, []Source{s}, BudgetFunc(func(string) time.Duration {
		return 100 * time.Millisecond
	}))
	if !strings.Contains(string(m.OTX), "pipeline_error") {
		t.Errorf("otx slot = %s; want pipeline_error skip marker", m.OTX)
	}
}

func TestRunHonoursBudgetTimeout(t *testing.T) {
	m := &model.Report{}
	s := &fakeSource{name: "otx", delay: 200 * time.Millisecond}
	start := time.Now()
	Run(context.Background(), m, []Source{s}, BudgetFunc(func(string) time.Duration {
		return 50 * time.Millisecond
	}))
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Errorf("Run blocked %v; want <=150ms (budget=50ms)", elapsed)
	}
	if !strings.Contains(string(m.OTX), "budget_exhausted") {
		t.Errorf("otx slot = %s; want budget_exhausted", m.OTX)
	}
}

func TestRunUnknownSourceDoesNotMutateKnownSlots(t *testing.T) {
	m := &model.Report{
		OTX:  json.RawMessage(`{"keep":"otx"}`),
		RDNS: json.RawMessage(`{"keep":"rdns"}`),
	}
	s := &fakeSource{name: "unknown", rawSet: json.RawMessage(`{"new":"value"}`)}

	Run(context.Background(), m, []Source{s}, BudgetFunc(func(string) time.Duration {
		return 100 * time.Millisecond
	}))

	if got := string(m.OTX); got != `{"keep":"otx"}` {
		t.Errorf("otx slot = %s; want unchanged", got)
	}
	if got := string(m.RDNS); got != `{"keep":"rdns"}` {
		t.Errorf("rdns slot = %s; want unchanged", got)
	}
}
