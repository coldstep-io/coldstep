// Package otx provides an OTX (AlienVault Open Threat Exchange) backend
// for the reputation enrichment interface.
//
// OTXEnricher implements reputation.Enricher by querying
// https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general with the
// configured API key. If no API key is supplied, Enrich is a no-op and
// returns (nil, nil).
package otx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coldstep-io/coldstep/internal/reputation"
)

// Cap decoded JSON to prevent a pathological response from allocating
// unbounded memory. Mirrors the bound used in cmd/coldstep-report.
const maxResponseJSONBytes = 4 << 20

// DefaultTimeout bounds a single OTX HTTP call. Callers can override by
// passing a tighter deadline on the ctx supplied to Enrich.
const DefaultTimeout = 10 * time.Second

// OTXEnricher implements reputation.Enricher against the OTX general
// indicators endpoint.
type OTXEnricher struct {
	APIKey  string
	Client  *http.Client // optional; defaults to a 10s-timeout client
	BaseURL string       // optional; defaults to https://otx.alienvault.com
}

// New constructs an OTXEnricher with the given API key. When apiKey is
// empty, Enrich returns (nil, nil) — useful as a placeholder in the
// registry when the user has not configured OTX.
func New(apiKey string) *OTXEnricher {
	return &OTXEnricher{
		APIKey:  strings.TrimSpace(apiKey),
		Client:  &http.Client{Timeout: DefaultTimeout},
		BaseURL: "https://otx.alienvault.com",
	}
}

// Name reports the stable identifier "otx".
func (o *OTXEnricher) Name() string { return "otx" }

// Enrich queries OTX for the given IPv4 address. Returns (nil, nil) when:
//   - the API key is not configured, or
//   - OTX has no pulse data for this indicator.
//
// HTTP and decode failures are surfaced as errors so the caller can
// distinguish "no data" from "lookup failed".
func (o *OTXEnricher) Enrich(ctx context.Context, ip string) (*reputation.Result, error) {
	if o == nil || o.APIKey == "" {
		return nil, nil
	}
	if strings.TrimSpace(ip) == "" {
		return nil, nil
	}

	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}
	base := o.BaseURL
	if base == "" {
		base = "https://otx.alienvault.com"
	}
	endpoint := fmt.Sprintf("%s/api/v1/indicators/IPv4/%s/general", strings.TrimRight(base, "/"), url.PathEscape(ip))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OTX-API-KEY", o.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseJSONBytes))
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		// Fall through to decode below.
	case http.StatusForbidden:
		return nil, fmt.Errorf("otx: invalid api key")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("otx: rate-limited")
	default:
		return nil, fmt.Errorf("otx: unexpected status %d", resp.StatusCode)
	}

	var body map[string]any
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseJSONBytes))
	if err := dec.Decode(&body); err != nil {
		return nil, fmt.Errorf("otx: decode response: %w", err)
	}

	pulseCount := extractPulseCount(body)
	if pulseCount == 0 {
		// No OTX intel on this IP — that's "no data", not an error.
		return nil, nil
	}

	now := time.Now().UTC()
	result := &reputation.Result{
		IP:       ip,
		Enricher: o.Name(),
		Score:    scoreFromPulseCount(pulseCount),
		Tags:     extractTags(body),
		CachedAt: &now,
		Raw:      body,
	}
	if cc, ok := body["country_code"].(string); ok {
		result.CountryCode = cc
	}
	if asn, ok := body["asn"].(string); ok {
		result.ASN = asn
	}
	return result, nil
}

// scoreFromPulseCount maps OTX pulse counts onto the 0–10 reputation
// scale. The mapping is intentionally simple — callers that need a
// finer-grained model should inspect Result.Raw directly.
func scoreFromPulseCount(n int) float64 {
	switch {
	case n <= 0:
		return 0
	case n >= 25:
		return 10
	default:
		return float64(n) * 10.0 / 25.0
	}
}

func extractPulseCount(body map[string]any) int {
	pulseInfo, ok := body["pulse_info"].(map[string]any)
	if !ok {
		return 0
	}
	switch v := pulseInfo["count"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	if pulses, ok := pulseInfo["pulses"].([]any); ok {
		return len(pulses)
	}
	return 0
}

func extractTags(body map[string]any) []string {
	pulseInfo, ok := body["pulse_info"].(map[string]any)
	if !ok {
		return nil
	}
	pulses, ok := pulseInfo["pulses"].([]any)
	if !ok {
		return nil
	}
	seen := map[string]struct{}{}
	var tags []string
	for _, raw := range pulses {
		pulse, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		rawTags, ok := pulse["tags"].([]any)
		if !ok {
			continue
		}
		for _, t := range rawTags {
			s, ok := t.(string)
			if !ok {
				continue
			}
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			tags = append(tags, s)
		}
	}
	return tags
}
