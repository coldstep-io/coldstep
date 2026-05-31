// Package loader assembles reputation enrichers from environment
// variables.
//
// It lives in its own subpackage (rather than next to the interface in
// internal/reputation) so the top-level package can stay leaf-only: the
// concrete backends in internal/reputation/{otx,passivedns,...} import
// the interface, and this loader imports both — that ordering avoids an
// import cycle.
package loader

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/coldstep-io/coldstep/internal/reputation"
	"github.com/coldstep-io/coldstep/internal/reputation/otx"
	"github.com/coldstep-io/coldstep/internal/reputation/passivedns"
)

// Env var names recognized by LoadFromEnv. Centralized here so callers
// (and docs) reference a single source of truth.
const (
	EnvOTXAPIKey        = "COLDSTEP_OTX_API_KEY" // #nosec G101 -- env var name, not a credential value
	EnvVirusTotalAPIKey = "COLDSTEP_VIRUSTOTAL_API_KEY"
	EnvPassiveDNSServer = "COLDSTEP_PASSIVEDNS_SERVER"
)

// LoadFromEnv inspects the environment and returns one Enricher per
// supported backend, in deterministic order: otx, virustotal,
// passivedns.
//
// When a backend's env var is empty, LoadFromEnv returns a NoOpEnricher
// with that backend's Name(). This keeps the slice length and ordering
// stable so callers can iterate uniformly and report which backends are
// active without nil checks.
//
// LoadFromEnv does not call reputation.Register — that is the caller's
// choice. Subcommands typically Reset() then Register() the returned
// enrichers before invoking EnrichAll.
func LoadFromEnv() []reputation.Enricher {
	otxKey := strings.TrimSpace(os.Getenv(EnvOTXAPIKey))
	vtKey := strings.TrimSpace(os.Getenv(EnvVirusTotalAPIKey))
	pdnsServer := strings.TrimSpace(os.Getenv(EnvPassiveDNSServer))

	out := make([]reputation.Enricher, 0, 3)

	if otxKey != "" {
		out = append(out, otx.New(otxKey))
	} else {
		out = append(out, reputation.NewNoOp("otx"))
	}

	if vtKey != "" {
		out = append(out, &virusTotalEnricher{apiKey: vtKey})
	} else {
		out = append(out, reputation.NewNoOp("virustotal"))
	}

	if pdnsServer != "" {
		out = append(out, passivedns.New(pdnsServer))
	} else {
		out = append(out, reputation.NewNoOp("passivedns"))
	}

	return out
}

// virusTotalEnricher is an in-package stub for the VirusTotal backend.
// It lives here (rather than in its own subpackage) because the wire
// protocol is not yet implemented and a dedicated package would mostly
// be empty. Once a real client is built, move this to
// internal/reputation/virustotal/.
type virusTotalEnricher struct {
	apiKey string
}

// virusTotalStubWarnOnce guards the not-implemented warning so it fires
// at most once per process regardless of how many IPs are enriched. The
// warning carries no IP — egress IPs must not leak into logs.
var virusTotalStubWarnOnce sync.Once

func (v *virusTotalEnricher) Name() string { return "virustotal" }

func (v *virusTotalEnricher) Enrich(_ context.Context, _ string) (*reputation.Result, error) {
	// Stub: keys are accepted (so LoadFromEnv can report the backend as
	// "configured") but no HTTP call is made yet. Treat as no-data.
	virusTotalStubWarnOnce.Do(func() {
		slog.Warn("virustotal reputation backend not yet implemented; COLDSTEP_VIRUSTOTAL_API_KEY is set but no enrichment is performed")
	})
	return nil, nil
}
