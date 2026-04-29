// Package enrich defines the Source interface every enrichment plug-in must
// implement (OTX, rDNS, future passive-DNS, GeoIP, VirusTotal). Sources MUST:
//
//   - Mutate ONLY the report slot selected by setSlot (currently m.OTX/m.RDNS).
//   - Honour ctx.Done() — cancellation is the budget-enforcement mechanism.
//   - Return nil for any recoverable failure after writing
//     {"skipped": "<reason>"} to their slot.
//
// Non-nil error means a programming error in the pipeline itself; the runner
// captures it as {"skipped": "pipeline_error: <err>"} so the binary's
// always-exit-0 contract still holds.
package enrich

import (
	"context"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

type Source interface {
	Name() string
	Enrich(ctx context.Context, m *model.Report) error
}
