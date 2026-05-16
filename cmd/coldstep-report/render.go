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

	maliciousCount := 0
	if rawOTX, ok := m["otx"]; ok {
		if otx, ok := mapFromAny(rawOTX); ok {
			if summary, ok := mapFromAny(otx["summary"]); ok {
				maliciousCount = intFromAny(summary["malicious"])
			}
		}
	}

	f, err := os.OpenFile(outPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	const rowCap = 40
	var sb strings.Builder

	sb.WriteString("\n## Coldstep — egress baseline\n\n")

	if len(unidentified) > 0 || maliciousCount > 0 {
		fmt.Fprintf(&sb, "> [!WARNING]\n> %d unidentified / %d malicious destinations observed. Review before enabling defend mode.\n\n",
			len(unidentified), maliciousCount)
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

func boolFromAny(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
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

func lenSlice(v any) int {
	if s, ok := sliceFromAny(v); ok {
		return len(s)
	}
	return 0
}
