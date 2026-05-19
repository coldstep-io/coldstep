package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/coldstep-io/coldstep/internal/reputation"
	"github.com/coldstep-io/coldstep/internal/reputation/loader"
)

// reputationWallBudgetEnv bounds the total wall-clock time spent on the
// new generic reputation pass. The legacy OTX path has its own budget
// (COLDSTEP_OTX_WALL_BUDGET_MS); this knob covers the registry-driven
// pass only.
const reputationWallBudgetEnv = "COLDSTEP_REPUTATION_WALL_BUDGET_MS"

// applyReputationEnrichers loads enrichers from the environment, runs
// them over every IPv4 indicator in the model, and stores the combined
// results under m["reputation_results"]. A summary block is written to
// m["reputation"].
//
// This is the new plug-in path defined in internal/reputation. It runs
// in addition to the legacy OTX-specific code in enrich.go so existing
// reports keep producing the same fields; the new shape is additive.
//
// Returns nil even on partial enricher errors — those are recorded in
// the per-IP "errors" field. A non-nil error here means we could not run
// the pass at all (e.g. corrupt model).
func applyReputationEnrichers(m map[string]any) error {
	enrichers := loader.LoadFromEnv()
	reputation.Reset()
	for _, e := range enrichers {
		reputation.Register(e)
	}

	active := make([]string, 0, len(enrichers))
	for _, e := range enrichers {
		if _, isNoOp := e.(reputation.NoOpEnricher); isNoOp {
			continue
		}
		active = append(active, e.Name())
	}

	budgetMs := parseBudgetMillis(reputationWallBudgetEnv, 30000)
	deadline := time.Now().Add(time.Duration(budgetMs) * time.Millisecond)
	indicators := gatherModelIndicators(m)

	rows := make([]map[string]any, 0)
	queried := 0
	partial := false

	for _, ind := range indicators {
		if !isIPv4(ind) {
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			partial = true
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), remaining)
		results, err := reputation.EnrichAll(ctx, ind)
		cancel()
		queried++

		row := map[string]any{"ip": ind}
		if err != nil {
			row["errors"] = err.Error()
		}
		if len(results) == 0 {
			continue
		}
		serialized := make([]map[string]any, 0, len(results))
		for _, r := range results {
			serialized = append(serialized, map[string]any{
				"ip":           r.IP,
				"enricher":     r.Enricher,
				"score":        r.Score,
				"tags":         r.Tags,
				"country_code": r.CountryCode,
				"asn":          r.ASN,
			})
		}
		row["results"] = serialized
		rows = append(rows, row)
	}

	if len(rows) > 0 {
		m["reputation_results"] = rows
	}
	m["reputation"] = map[string]any{
		"active_enrichers": active,
		"queried":          queried,
		"partial_results":  partial,
		"wall_budget_ms":   budgetMs,
		"queried_at":       time.Now().UTC().Format(time.RFC3339),
	}
	fmt.Fprintf(os.Stderr, "reputation: ran %d enricher(s) over %d indicator(s)\n", len(active), queried)
	return nil
}
