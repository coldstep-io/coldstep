// Package passivedns provides a PassiveDNS backend for the reputation
// enrichment interface.
//
// The expected backend is CIRCL PassiveDNS or any compatible server
// implementing the COF (Common Output Format) protocol:
//
//	GET https://{server}/query/{ip}
//	Headers: Authorization: Bearer {token} (optional)
//	Response: newline-delimited JSON, one record per historical resolution
//
// This file ships a stub implementation: Enrich always returns (nil, nil).
// It exists so the registry surface and env loader are complete; the wire
// protocol is left to a follow-up PR (or to external integrators who
// embed coldstep and supply their own Enricher).
package passivedns

import (
	"context"
	"strings"

	"github.com/coldstep-io/coldstep/internal/reputation"
)

// Enricher implements reputation.Enricher against a CIRCL PassiveDNS
// compatible server. The Server field is the base URL of the PDNS
// service; Token is the optional bearer token.
type Enricher struct {
	Server string
	Token  string
}

// New constructs a PassiveDNS enricher pointing at server. When server is
// empty, Enrich returns (nil, nil).
func New(server string) *Enricher {
	return &Enricher{Server: strings.TrimSpace(server)}
}

// Name reports the stable identifier "passivedns".
func (e *Enricher) Name() string { return "passivedns" }

// Enrich queries the configured PassiveDNS server for the given IP.
//
// This is a stub: it validates configuration and returns (nil, nil)
// without making a network call. A real implementation would fetch
// historical A/AAAA records, derive a reputation score from age/diversity
// of resolutions, and surface the records in Result.Raw.
func (e *Enricher) Enrich(_ context.Context, _ string) (*reputation.Result, error) {
	if e == nil || e.Server == "" {
		return nil, nil
	}
	return nil, nil
}
