package main

import (
	"flag"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/coldstep-io/coldstep/internal/atomicwrite"
	"github.com/coldstep-io/coldstep/internal/safepath"
)

func renderSummary(args []string) error {
	fs := flag.NewFlagSet("render-summary", flag.ContinueOnError)
	in := fs.String("in", envOr("COLDSTEP_REPORT_MODEL_IN", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	summaryPath := fs.String("summary", envOr("GITHUB_STEP_SUMMARY", ""), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*summaryPath) == "" {
		return nil
	}

	inPath, err := safepath.Workspace(*in, "COLDSTEP_REPORT_MODEL_IN")
	if err != nil {
		return err
	}
	outPath, err := safepath.Workspace(*summaryPath, "GITHUB_STEP_SUMMARY")
	if err != nil {
		return err
	}

	m, err := readModelMap(inPath)
	if err != nil {
		return err
	}

	type egressRow struct {
		dst     string
		hits    int
		reason  string
		rawEdge map[string]any
	}
	var allowed, unidentified, blocked []egressRow

	if sankey, ok := sliceFromAny(m["egress_sankey"]); ok {
		for _, raw := range sankey {
			row, ok := mapFromAny(raw)
			if !ok {
				continue
			}
			dst, _ := stringFromAny(row["source"])
			policy, _ := stringFromAny(row["target"])
			hits := intFromAny(row["value"])
			if dst == "" {
				continue
			}
			tr := egressRow{dst: dst, hits: hits, rawEdge: row}
			switch strings.ToLower(policy) {
			case "allowed":
				allowed = append(allowed, tr)
			case "denied", "blocked", "deny":
				tr.reason = policy
				blocked = append(blocked, tr)
			default:
				unidentified = append(unidentified, tr)
			}
		}
	}

	sortRows := func(rows []egressRow) {
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].hits != rows[j].hits {
				return rows[i].hits > rows[j].hits
			}
			return rows[i].dst < rows[j].dst
		})
	}
	sortRows(allowed)
	sortRows(unidentified)
	sortRows(blocked)

	f, err := os.OpenFile(outPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	const rowCap = 40
	var sb strings.Builder

	sb.WriteString("\n## Coldstep — egress baseline\n\n")

	if len(unidentified) > 0 {
		fmt.Fprintf(&sb, "> [!WARNING]\n> %d unidentified destination(s) observed. Review before enabling defend mode.\n\n",
			len(unidentified))
	}

	// P1-2 / 4b: surface suspicious-domain heuristics. Counts come from
	// build-model (model.SuspiciousDomains). We only render the alert when
	// at least one row was flagged so a clean baseline stays terse.
	suspRows := suspiciousDomainsFromModel(m)
	if len(suspRows) > 0 {
		he, rare, port := countSuspiciousReasons(suspRows)
		fmt.Fprintf(
			&sb,
			"> [!WARNING]\n> %d suspicious domains flagged (high entropy: %d, rare: %d, port anomaly: %d). Review before promoting to `allow:` (P1-2).\n\n",
			len(suspRows), he, rare, port,
		)
	}

	// P1-2 / 4a: surface a short-observation-window warning when build-model
	// recorded one. The hard fail lives in assert-integrity; the summary
	// notice keeps eyes on the report even when integrity is disabled.
	if observationHoursFromModel(m) > 0 && shortObservationWindowFromModel(m) {
		fmt.Fprintf(
			&sb,
			"> [!WARNING]\n> Observation window only %.2fh (< %.2fh threshold). Allowlist promotion off this run is risky (P1-2).\n\n",
			observationHoursFromModel(m), minObservationHoursFromModel(m),
		)
	}

	writeSection := func(heading string, rows []egressRow, showReason bool) {
		if len(rows) == 0 {
			return
		}
		fmt.Fprintf(&sb, "### %s\n\n", heading)
		if showReason {
			sb.WriteString("| Destination | Protocol | Port | Reason |\n")
			sb.WriteString("|-------------|----------|------|--------|\n")
		} else {
			sb.WriteString("| Destination | Protocol | Port | Hits |\n")
			sb.WriteString("|-------------|----------|------|------|\n")
		}
		limit := len(rows)
		if limit > rowCap {
			limit = rowCap
		}
		for _, r := range rows[:limit] {
			proto, _ := stringFromAny(r.rawEdge["protocol"])
			if proto == "" {
				proto = "—"
			}
			port := intFromAny(r.rawEdge["port"])
			portStr := "—"
			if port > 0 {
				portStr = fmt.Sprintf("%d", port)
			}
			if showReason {
				fmt.Fprintf(&sb, "| `%s` | %s | %s | %s |\n", sanitize(r.dst), sanitize(proto), portStr, sanitize(r.reason))
			} else {
				fmt.Fprintf(&sb, "| `%s` | %s | %s | %d |\n", sanitize(r.dst), sanitize(proto), portStr, r.hits)
			}
		}
		if len(rows) > rowCap {
			fmt.Fprintf(&sb, "\n_(%d more — see artifact)_\n", len(rows)-rowCap)
		}
		sb.WriteString("\n")
	}

	writeSection("Allowed", allowed, false)
	writeSection("Unidentified", unidentified, false)
	writeSection("Blocked", blocked, true)

	sb.WriteString("_Full telemetry in attached artifact. Add unidentified destinations to `allow:` to build your allowlist._\n")

	_, err = f.WriteString(sb.String())
	return err
}

func renderIPSummary(args []string) error {
	fs := flag.NewFlagSet("render-ip-summary", flag.ContinueOnError)
	in := fs.String("in", envOr("COLDSTEP_REPORT_MODEL_IN", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	summaryPath := fs.String("summary", envOr("GITHUB_STEP_SUMMARY", ""), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*summaryPath) == "" {
		return nil
	}

	inPath, err := safepath.Workspace(*in, "COLDSTEP_REPORT_MODEL_IN")
	if err != nil {
		return err
	}
	outPath, err := safepath.Workspace(*summaryPath, "GITHUB_STEP_SUMMARY")
	if err != nil {
		return err
	}
	m, err := readModelMap(inPath)
	if err != nil {
		return err
	}

	var lines []string
	lines = append(lines, "", "## IP Classification Summary", "")
	lines = append(lines, "| Indicator | Kind | Verdict | Confidence |")
	lines = append(lines, "|:--|:--|:--|:--|")

	rowsAdded := 0
	if classRows, ok := sliceFromAny(m["ip_classification"]); ok {
		for _, raw := range classRows {
			row, ok := mapFromAny(raw)
			if !ok {
				continue
			}
			indicator, _ := stringFromAny(row["indicator"])
			if indicator == "" {
				indicator, _ = stringFromAny(row["ip"])
			}
			if indicator == "" {
				continue
			}
			kind, _ := stringFromAny(row["kind"])
			verdict, _ := stringFromAny(row["verdict"])
			conf, _ := stringFromAny(row["confidence"])
			lines = append(lines, fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` |", sanitize(indicator), sanitize(kind), sanitize(verdict), sanitize(conf)))
			rowsAdded++
			if rowsAdded >= 25 {
				break
			}
		}
	}

	if rowsAdded == 0 {
		indicators := gatherModelIndicators(m)
		for _, ind := range indicators {
			lines = append(lines, fmt.Sprintf("| `%s` | `unknown` | `unidentified` | `C` |", sanitize(ind)))
			rowsAdded++
			if rowsAdded >= 25 {
				break
			}
		}
	}
	if rowsAdded == 0 {
		lines = append(lines, "| `(none)` | `unknown` | `unidentified` | `C` |")
	}

	f, err := os.OpenFile(outPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(strings.Join(lines, "\n") + "\n")
	return err
}

func renderHTML(args []string) error {
	fs := flag.NewFlagSet("render-html", flag.ContinueOnError)
	in := fs.String("in", envOr("COLDSTEP_REPORT_MODEL_IN", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	out := fs.String("out", envOr("COLDSTEP_REPORT_HTML_OUT", filepath.Join(envOr("GITHUB_WORKSPACE", "."), "coldstep-detect-report.html")), "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	inPath, err := safepath.Workspace(*in, "COLDSTEP_REPORT_MODEL_IN")
	if err != nil {
		return err
	}
	outPath, err := safepath.Workspace(*out, "COLDSTEP_REPORT_HTML_OUT")
	if err != nil {
		return err
	}
	m, err := readModelMap(inPath)
	if err != nil {
		return err
	}

	var rows strings.Builder
	if evRows, ok := sliceFromAny(m["events_by_type"]); ok {
		for _, raw := range evRows {
			row, ok := mapFromAny(raw)
			if !ok {
				continue
			}
			typ, _ := stringFromAny(row["type"])
			cnt := intFromAny(row["count"])
			rows.WriteString(fmt.Sprintf("<tr><td><code>%s</code></td><td>%d</td></tr>\n", html.EscapeString(typ), cnt))
		}
	}

	score := 0
	verdict := "unknown"
	if ceval, ok := mapFromAny(m["capability_eval"]); ok {
		score = intFromAny(ceval["score"])
		if v, ok := stringFromAny(ceval["verdict"]); ok && v != "" {
			verdict = v
		}
	}

	profileHTML := "standard"
	if run, ok := mapFromAny(m["run"]); ok {
		if dp, ok := stringFromAny(run["detect_profile"]); ok && dp != "" {
			profileHTML = dp
		}
	}
	profilePara := "<p><strong>Detect profile:</strong> " + html.EscapeString(profileHTML) + "</p>"
	if strings.EqualFold(profileHTML, "enhanced") {
		profilePara += "<p><em>Enhanced integrity expects udp, http, tls, proc_fork, and fs_event event types in JSONL.</em></p>"
	}

	htmlBody := "<!doctype html><html><head><meta charset=\"utf-8\"><title>Coldstep Detect Report</title></head><body>" +
		"<h1>Coldstep Detect Report</h1>" +
		profilePara +
		"<p><strong>Capability score:</strong> " + html.EscapeString(fmt.Sprintf("%d (%s)", score, verdict)) + "</p>" +
		"<table border=\"1\" cellspacing=\"0\" cellpadding=\"6\"><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>" +
		rows.String() +
		"</tbody></table></body></html>"
	return atomicwrite.Bytes(outPath, []byte(htmlBody), 0o644)
}

func stringFromAny(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(s), true
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

func mapFromAny(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func sliceFromAny(v any) ([]any, bool) {
	s, ok := v.([]any)
	return s, ok
}

func floatFromAny(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}

func boolFromAny(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

// observationHoursFromModel / shortObservationWindowFromModel /
// minObservationHoursFromModel pull the P1-2 / 4a fields out of the
// generic map form used by render-summary (readModelMap unmarshals into
// map[string]any). They tolerate missing keys / wrong types because the
// build-model output evolves and old artifacts may not carry them.
func observationHoursFromModel(m map[string]any) float64 {
	return floatFromAny(m["observation_hours"])
}

func shortObservationWindowFromModel(m map[string]any) bool {
	return boolFromAny(m["short_observation_window"])
}

func minObservationHoursFromModel(m map[string]any) float64 {
	return floatFromAny(m["min_observation_hours"])
}

// suspiciousDomainsFromModel decodes Report.SuspiciousDomains from the
// generic map form. Returns an empty slice when the field is missing or
// malformed.
func suspiciousDomainsFromModel(m map[string]any) []map[string]any {
	raw, ok := sliceFromAny(m["suspicious_domains"])
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		row, ok := mapFromAny(r)
		if !ok {
			continue
		}
		out = append(out, row)
	}
	return out
}

func countSuspiciousReasons(rows []map[string]any) (highEntropy, rare, portAnomaly int) {
	for _, r := range rows {
		reasons, ok := sliceFromAny(r["reasons"])
		if !ok {
			continue
		}
		for _, raw := range reasons {
			s, ok := stringFromAny(raw)
			if !ok {
				continue
			}
			switch s {
			case "high_entropy":
				highEntropy++
			case "rare":
				rare++
			case "port_anomaly":
				portAnomaly++
			}
		}
	}
	return
}

// gatherModelIndicators collects distinct destination indicators from the
// report model (egress sankey, diff buckets, ip_classification) for the
// render-ip-summary fallback table.
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
