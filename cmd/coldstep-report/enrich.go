package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coldstep-io/coldstep/internal/safepath"
)

// Bound OTX JSON decode so a pathological HTTP body cannot allocate unbounded memory.
const otxMaxResponseJSONBytes = 4 << 20

func rdnsEnrich(args []string) error {
	fs := flag.NewFlagSet("rdns-enrich", flag.ContinueOnError)
	in := fs.String("in", envOr("COLDSTEP_REPORT_MODEL_IN", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	inPath, err := safepath.Workspace(*in, "COLDSTEP_REPORT_MODEL_IN")
	if err != nil {
		return err
	}
	m, err := readModelMap(inPath)
	if err != nil {
		return err
	}

	budgetMs := parseBudgetMillis("COLDSTEP_RDNS_WALL_BUDGET_MS", 5000)
	deadline := time.Now().Add(time.Duration(budgetMs) * time.Millisecond)
	indicators := gatherModelIndicators(m)
	lookups := map[string]string{}

	for _, indicator := range indicators {
		if !isIPv4(indicator) {
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		perLookup := remaining / 2
		if perLookup < time.Second {
			perLookup = remaining
		}
		if perLookup > 3*time.Second {
			perLookup = 3 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), perLookup)
		names, lookupErr := net.DefaultResolver.LookupAddr(ctx, indicator)
		cancel()
		if lookupErr != nil || len(names) == 0 {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
		if name != "" {
			lookups[indicator] = name
		}
	}

	m["dns_lookups"] = lookups
	if err := writeModelMap(inPath, m); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "rdns: resolved %d indicator(s)\n", len(lookups))
	return nil
}

func otxEnrich(args []string) error {
	fs := flag.NewFlagSet("otx-enrich", flag.ContinueOnError)
	in := fs.String("in", envOr("COLDSTEP_REPORT_MODEL_IN", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	inPath, err := safepath.Workspace(*in, "COLDSTEP_REPORT_MODEL_IN")
	if err != nil {
		return err
	}
	m, err := readModelMap(inPath)
	if err != nil {
		return err
	}

	apiKey := strings.TrimSpace(os.Getenv("OTX_API_KEY"))
	queriedAt := time.Now().UTC().Format(time.RFC3339)
	budgetMs := parseBudgetMillis("COLDSTEP_OTX_WALL_BUDGET_MS", 30000)
	if apiKey == "" {
		m["otx"] = map[string]any{
			"skipped":         true,
			"skipped_reason":  "no api key",
			"queried_at":      queriedAt,
			"wall_ms":         0,
			"wall_budget_ms":  budgetMs,
			"partial_results": false,
			// api_calls counts indicators processed (including failed HTTP/decode), matching summaries that say "queried N indicator(s)".
			"api_calls":    0,
			"rate_limited": 0,
			"indicators":   []any{},
			"summary": map[string]any{
				"malicious":    0,
				"clean":        0,
				"unidentified": 0,
				"total":        0,
			},
		}
		return writeModelMap(inPath, m)
	}

	start := time.Now()
	deadline := start.Add(time.Duration(budgetMs) * time.Millisecond)
	indicators := gatherModelIndicators(m)
	outRows := make([]map[string]any, 0, len(indicators))
	maliciousCount, cleanCount, unidentifiedCount := 0, 0, 0
	apiCalls := 0
	rateLimited := 0
	partial := false
	client := &http.Client{Timeout: 10 * time.Second}

	for _, indicator := range indicators {
		if time.Now().After(deadline) {
			partial = true
			break
		}

		indicatorType := "hostname"
		if isIPv4(indicator) {
			indicatorType = "IPv4"
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			partial = true
			break
		}
		verdict, note, pulseCount, callErr := queryOTXIndicator(client, apiKey, indicatorType, indicator, remaining)
		if callErr != nil {
			verdict = "unidentified"
			note = callErr.Error()
		}

		row := map[string]any{
			"indicator":   indicator,
			"type":        indicatorType,
			"verdict":     verdict,
			"pulse_count": pulseCount,
		}
		if note != "" {
			row["note"] = note
		}
		outRows = append(outRows, row)
		apiCalls++

		switch verdict {
		case "malicious":
			maliciousCount++
		case "clean":
			cleanCount++
		default:
			unidentifiedCount++
		}
		if note == "rate-limited" {
			rateLimited++
		}
	}

	m["otx"] = map[string]any{
		"skipped":         false,
		"skipped_reason":  nil,
		"queried_at":      queriedAt,
		"wall_ms":         int(time.Since(start).Milliseconds()),
		"wall_budget_ms":  budgetMs,
		"partial_results": partial,
		"api_calls":       apiCalls, // indicators attempted (each row), not only HTTP 200 successes
		"rate_limited":    rateLimited,
		"indicators":      outRows,
		"summary": map[string]any{
			"malicious":    maliciousCount,
			"clean":        cleanCount,
			"unidentified": unidentifiedCount,
			"total":        maliciousCount + cleanCount + unidentifiedCount,
		},
	}
	return writeModelMap(inPath, m)
}

func gatherModelIndicators(m map[string]any) []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(ind string) {
		ind = strings.TrimSpace(ind)
		if ind == "" {
			return
		}
		if _, ok := seen[ind]; ok {
			return
		}
		seen[ind] = struct{}{}
		out = append(out, ind)
	}

	if sankey, ok := sliceFromAny(m["egress_sankey"]); ok {
		for _, raw := range sankey {
			row, ok := mapFromAny(raw)
			if !ok {
				continue
			}
			if inds, ok := sliceFromAny(row["indicators"]); ok {
				for _, rawInd := range inds {
					if s, ok := stringFromAny(rawInd); ok {
						add(s)
					}
				}
			}
		}
	}
	if diff, ok := mapFromAny(m["diff"]); ok {
		for _, bucket := range []string{"traffic_new", "traffic_gone", "traffic_changed"} {
			rows, ok := sliceFromAny(diff[bucket])
			if !ok {
				continue
			}
			for _, raw := range rows {
				row, ok := mapFromAny(raw)
				if !ok {
					continue
				}
				if inds, ok := sliceFromAny(row["indicators"]); ok {
					for _, rawInd := range inds {
						if s, ok := stringFromAny(rawInd); ok {
							add(s)
						}
					}
				}
			}
		}
	}
	if classes, ok := sliceFromAny(m["ip_classification"]); ok {
		for _, raw := range classes {
			row, ok := mapFromAny(raw)
			if !ok {
				continue
			}
			if s, ok := stringFromAny(row["ip"]); ok {
				add(s)
			}
			if s, ok := stringFromAny(row["indicator"]); ok {
				add(s)
			}
			if s, ok := stringFromAny(row["fqdn"]); ok {
				add(s)
			}
		}
	}
	return out
}

func decodeOTXGeneralJSON(r io.Reader) (map[string]any, error) {
	dec := json.NewDecoder(io.LimitReader(r, otxMaxResponseJSONBytes))
	var body map[string]any
	if err := dec.Decode(&body); err != nil {
		return nil, err
	}
	return body, nil
}

func queryOTXIndicator(client *http.Client, apiKey, indicatorType, indicator string, remaining time.Duration) (string, string, int, error) {
	escapedIndicator := url.PathEscape(indicator)
	endpoint := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/%s/%s/general", indicatorType, escapedIndicator)
	reqTimeout := remaining
	if reqTimeout > 10*time.Second {
		reqTimeout = 10 * time.Second
	}
	if reqTimeout < 500*time.Millisecond {
		reqTimeout = 500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "unidentified", "", 0, err
	}
	req.Header.Set("X-OTX-API-KEY", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return "unidentified", "", 0, err
	}
	defer func() {
		// Drain up to cap so the shared transport can reuse keep-alive connections on non-200 responses.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, otxMaxResponseJSONBytes))
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusForbidden:
		return "unidentified", "invalid api key", 0, nil
	case http.StatusTooManyRequests:
		return "unidentified", "rate-limited", 0, nil
	case http.StatusOK:
		body, err := decodeOTXGeneralJSON(resp.Body)
		if err != nil {
			return "unidentified", "", 0, err
		}
		pulseCount := extractPulseCount(body)
		validationCount := extractValidationCount(body)
		if pulseCount > 0 {
			return "malicious", "", pulseCount, nil
		}
		if validationCount > 0 {
			return "clean", "", 0, nil
		}
		return "unidentified", "", 0, nil
	default:
		return "unidentified", fmt.Sprintf("otx status %d", resp.StatusCode), 0, nil
	}
}

func extractPulseCount(body map[string]any) int {
	pulseInfo, ok := mapFromAny(body["pulse_info"])
	if !ok {
		return 0
	}
	count := intFromAny(pulseInfo["count"])
	if count > 0 {
		return count
	}
	if pulses, ok := sliceFromAny(pulseInfo["pulses"]); ok {
		return len(pulses)
	}
	return 0
}

func extractValidationCount(body map[string]any) int {
	if validation, ok := sliceFromAny(body["validation"]); ok {
		return len(validation)
	}
	return 0
}

func parseBudgetMillis(envKey string, defaultValue int) int {
	v := strings.TrimSpace(os.Getenv(envKey))
	if v == "" {
		return defaultValue
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return defaultValue
	}
	return n
}

func isIPv4(indicator string) bool {
	ip := net.ParseIP(strings.TrimSpace(indicator))
	return ip != nil && ip.To4() != nil
}
