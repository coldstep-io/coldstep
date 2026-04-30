package main

import (
	"flag"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"

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
	f, err := os.OpenFile(outPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	score := 0
	verdict := "unknown"
	if ceval, ok := mapFromAny(m["capability_eval"]); ok {
		score = intFromAny(ceval["score"])
		if v, ok := stringFromAny(ceval["verdict"]); ok && v != "" {
			verdict = v
		}
	}

	passCount, warnCount, failCount := 0, 0, 0
	if cells, ok := sliceFromAny(m["capability_matrix"]); ok {
		for _, raw := range cells {
			row, ok := mapFromAny(raw)
			if !ok {
				continue
			}
			status, _ := stringFromAny(row["status"])
			switch status {
			case "pass":
				passCount++
			case "warn":
				warnCount++
			case "fail":
				failCount++
			}
		}
	}

	diffLine := "unavailable"
	if diff, ok := mapFromAny(m["diff"]); ok {
		status, _ := stringFromAny(diff["status"])
		switch status {
		case "ok":
			newN := lenSlice(diff["traffic_new"])
			goneN := lenSlice(diff["traffic_gone"])
			changedN := lenSlice(diff["traffic_changed"])
			diffLine = fmt.Sprintf("ok - new=%d gone=%d changed=%d", newN, goneN, changedN)
		default:
			reason, _ := stringFromAny(diff["reason"])
			if reason != "" {
				diffLine = fmt.Sprintf("unavailable (%s)", reason)
			}
		}
	}

	otxLine := "not present"
	if rawOTX, ok := m["otx"]; ok {
		if otx, ok := mapFromAny(rawOTX); ok {
			if skipped, ok := boolFromAny(otx["skipped"]); ok && skipped {
				reason, _ := stringFromAny(otx["skipped_reason"])
				if reason == "" {
					reason = "unknown"
				}
				otxLine = "skipped (" + reason + ")"
			} else if summary, ok := mapFromAny(otx["summary"]); ok {
				otxLine = fmt.Sprintf(
					"queried=%d malicious=%d clean=%d unidentified=%d",
					intFromAny(otx["api_calls"]),
					intFromAny(summary["malicious"]),
					intFromAny(summary["clean"]),
					intFromAny(summary["unidentified"]),
				)
			}
		}
	}

	profileLine := "standard"
	if run, ok := mapFromAny(m["run"]); ok {
		if dp, ok := stringFromAny(run["detect_profile"]); ok && dp != "" {
			profileLine = dp
		}
	}

	missingLine := ""
	if ceval, ok := mapFromAny(m["capability_eval"]); ok {
		if integ, ok := mapFromAny(ceval["integrity"]); ok {
			if det, ok := mapFromAny(integ["details"]); ok {
				if missing, ok := sliceFromAny(det["missing_types"]); ok {
					parts := make([]string, 0, len(missing))
					for _, x := range missing {
						if s, ok := x.(string); ok && s != "" {
							parts = append(parts, s)
						}
					}
					missingLine = strings.Join(parts, ", ")
				}
			}
		}
	}

	integrityNote := ""
	if strings.EqualFold(profileLine, "enhanced") {
		integrityNote = "\n- **Integrity tier:** enhanced — scoring expects **udp**, **http**, **tls**, **proc_fork**, **fs_event** rows (plus meta/exec/tcp)."
	}
	missingBullet := ""
	if missingLine != "" {
		missingBullet = "\n- **Missing required event types:** " + sanitize(missingLine)
	}

	_, err = fmt.Fprintf(
		f,
		"\n## Coldstep detect - summary\n\n- **Detect profile:** %s%s\n- **Capabilities:** pass=%d warn=%d fail=%d\n- **Capability score:** %d/100 (%s)\n- **Baseline diff:** %s\n- **Threat intel (OTX):** %s%s\n",
		sanitize(profileLine),
		integrityNote,
		passCount,
		warnCount,
		failCount,
		score,
		sanitize(verdict),
		sanitize(diffLine),
		sanitize(otxLine),
		missingBullet,
	)
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
	return os.WriteFile(outPath, []byte(htmlBody), 0o644)
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
