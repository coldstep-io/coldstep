// Package loader assembles reputation enrichers from environment
// variables.
//
// It lives in its own subpackage (rather than next to the interface in
// internal/reputation) so the top-level package can stay leaf-only: the
// concrete backends in internal/reputation/{otx,...} import the interface,
// and this loader imports both — that ordering avoids an import cycle.
package loader

import (
	"os"
	"strings"

	"github.com/coldstep-io/coldstep/internal/reputation"
	"github.com/coldstep-io/coldstep/internal/reputation/otx"
)

// Env var names recognized by LoadFromEnv. Centralized here so callers
// (and docs) reference a single source of truth.
const (
	EnvOTXAPIKey = "COLDSTEP_OTX_API_KEY" // #nosec G101 -- env var name, not a credential value
)

// LoadFromEnv inspects the environment and returns one Enricher per
// supported backend, in deterministic order: otx.
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

	out := make([]reputation.Enricher, 0, 1)

	if otxKey != "" {
		out = append(out, otx.New(otxKey))
	} else {
		out = append(out, reputation.NewNoOp("otx"))
	}

	return out
}
