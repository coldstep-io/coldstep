package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

// BudgetFunc returns the per-source wall-clock budget keyed by name.
type BudgetFunc func(name string) time.Duration

// Run iterates sources, applies a per-source budget, and converts unrecovered
// errors into {"skipped": "pipeline_error: ..."} markers. It NEVER returns
// non-nil itself — the always-exit-0 contract is encoded here.
func Run(ctx context.Context, m *model.Report, sources []Source, budget BudgetFunc) {
	for _, s := range sources {
		runSource(ctx, m, s, budget)
	}
}

func runSource(ctx context.Context, m *model.Report, s Source, budget BudgetFunc) {
	sctx, cancel := context.WithTimeout(ctx, budget(s.Name()))
	defer cancel()

	err := s.Enrich(sctx, m)
	if err != nil {
		setSlot(m, s.Name(), json.RawMessage(fmt.Sprintf(`{"skipped":"pipeline_error: %s"}`, jsonEscape(err.Error()))))
	}
}

func setSlot(m *model.Report, name string, raw json.RawMessage) {
	switch name {
	case "otx":
		m.OTX = raw
	case "rdns":
		m.RDNS = raw
	default:
		// Unknown source names are a safe no-op for typed slots.
	}
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	if len(b) >= 2 {
		return string(b[1 : len(b)-1])
	}
	return ""
}
