// Package reputation defines the plug-in interface for IP/indicator
// reputation enrichers (e.g. OTX, VirusTotal, PassiveDNS).
//
// Enrichment is post-processing only: callers run it after events are
// written to JSONL, never on the agent's hot path. Implementations must be
// safe for concurrent use because [EnrichAll] fans out to every registered
// enricher in parallel.
//
// The public surface (Enricher, Result, Register, Registered, EnrichAll,
// LoadFromEnv) is considered stable once shipped; external integrators may
// build their own enrichers against it without depending on internal
// coldstep details.
package reputation

import (
	"context"
	"time"
)

// Enricher enriches an IPv4 address with reputation data from a single
// backend. Implementations must be safe for concurrent use.
type Enricher interface {
	// Name returns a stable identifier for this enricher
	// (e.g. "otx", "virustotal", "passivedns"). Used as the
	// Result.Enricher field and as a deduplication key.
	Name() string

	// Enrich queries reputation data for the given IPv4 address.
	// Returning (nil, nil) means "no data available" and is not an
	// error; callers should treat that case as a clean lookup.
	Enrich(ctx context.Context, ip string) (*Result, error)
}

// Result holds reputation data for a single IP from one enricher.
//
// Score is a normalized 0–10 value where higher means more suspicious.
// Raw is a passthrough of the backend's response for callers that want to
// surface fields the normalized shape does not cover.
type Result struct {
	IP          string         `json:"ip"`
	Enricher    string         `json:"enricher"`
	Score       float64        `json:"score,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	CountryCode string         `json:"country_code,omitempty"`
	ASN         string         `json:"asn,omitempty"`
	Raw         map[string]any `json:"raw,omitempty"`
	CachedAt    *time.Time     `json:"cached_at,omitempty"`
}

// NoOpEnricher satisfies [Enricher] but always returns (nil, nil). The
// loader returns one of these for each backend that is not configured, so
// callers can iterate the registry uniformly without nil checks.
type NoOpEnricher struct{ name string }

// NewNoOp constructs a NoOpEnricher with the given Name().
func NewNoOp(name string) NoOpEnricher { return NoOpEnricher{name: name} }

// Name reports the stable identifier supplied at construction.
func (n NoOpEnricher) Name() string { return n.name }

// Enrich always returns (nil, nil) — the backend is intentionally disabled.
func (n NoOpEnricher) Enrich(_ context.Context, _ string) (*Result, error) { return nil, nil }
