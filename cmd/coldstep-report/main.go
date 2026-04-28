package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type reportModel struct {
	SchemaVersion string            `json:"schema_version"`
	GeneratedAt   string            `json:"generated_at"`
	Counts        map[string]int    `json:"counts"`
	Indicators    []string          `json:"indicators,omitempty"`
	Notes         map[string]string `json:"notes,omitempty"`
	Extras        map[string]any    `json:"extras,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		exitf("usage: coldstep-report <build-model|assert-integrity|render-summary|render-html|diff|rdns-enrich|otx-enrich|render-ip-summary>")
	}
	switch os.Args[1] {
	case "build-model":
		exitIf(buildModel(os.Args[2:]))
	case "assert-integrity":
		exitIf(assertIntegrity(os.Args[2:]))
	case "render-summary":
		exitIf(renderSummary(os.Args[2:]))
	case "render-html":
		exitIf(renderHTML(os.Args[2:]))
	case "diff":
		exitIf(diffSummary(os.Args[2:]))
	case "rdns-enrich":
		exitIf(markSkippedEnrichment(os.Args[2:], "rdns", "go-rdns-skip-v1"))
	case "otx-enrich":
		exitIf(markSkippedEnrichment(os.Args[2:], "otx", "go-otx-skip-v1"))
	case "render-ip-summary":
		exitIf(renderIPSummary(os.Args[2:]))
	default:
		exitf("unknown subcommand %q", os.Args[1])
	}
}

func buildModel(args []string) error {
	fs := flag.NewFlagSet("build-model", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	current := fs.String("current", envOr("COLDSTEP_REPORT_CURRENT_JSONL", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-events.jsonl")), "")
	baseline := fs.String("baseline", envOr("COLDSTEP_REPORT_BASELINE_JSONL", ""), "")
	out := fs.String("out", envOr("COLDSTEP_REPORT_MODEL_OUT", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	counts, indicators, err := parseJSONLCounts(*current)
	if err != nil {
		return err
	}
	model := reportModel{
		SchemaVersion: "v1.2.0-go",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Counts:        counts,
		Indicators:    indicators,
		Notes: map[string]string{
			"builder": "coldstep-report-go",
		},
		Extras: map[string]any{},
	}
	if strings.TrimSpace(*baseline) != "" {
		baseCounts, _, err := parseJSONLCounts(*baseline)
		if err == nil {
			model.Extras["baseline_counts"] = baseCounts
			model.Extras["diff"] = map[string]int{
				"current_events":  sumMap(counts),
				"baseline_events": sumMap(baseCounts),
			}
		}
	}
	raw, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*out, raw, 0o644)
}

func parseJSONLCounts(path string) (map[string]int, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	counts := map[string]int{}
	indSet := map[string]struct{}{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		typ := asString(row["type"])
		if typ == "" {
			typ = "unknown"
		}
		counts[typ]++
		for _, k := range []string{"dst", "fqdn", "host", "sni"} {
			if v := asString(row[k]); v != "" {
				indSet[v] = struct{}{}
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, nil, err
	}
	indicators := make([]string, 0, len(indSet))
	for k := range indSet {
		indicators = append(indicators, k)
	}
	sort.Strings(indicators)
	return counts, indicators, nil
}

func assertIntegrity(args []string) error {
	fs := flag.NewFlagSet("assert-integrity", flag.ContinueOnError)
	in := fs.String("in", envOr("COLDSTEP_REPORT_MODEL_IN", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	model, err := readModel(*in)
	if err != nil {
		return err
	}
	if model.Counts["exec"] == 0 && model.Counts["tcp"] == 0 && model.Counts["deny"] == 0 {
		return errors.New("integrity gate failed: no meaningful coldstep events found")
	}
	return nil
}

func renderSummary(args []string) error {
	fs := flag.NewFlagSet("render-summary", flag.ContinueOnError)
	in := fs.String("in", envOr("COLDSTEP_REPORT_MODEL_IN", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	summaryPath := fs.String("summary", envOr("GITHUB_STEP_SUMMARY", ""), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	model, err := readModel(*in)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*summaryPath) == "" {
		return nil
	}
	var b strings.Builder
	b.WriteString("## Coldstep detect summary (Go)\n\n")
	b.WriteString("| Type | Count |\n|:--|--:|\n")
	keys := mapKeys(model.Counts)
	for _, k := range keys {
		b.WriteString(fmt.Sprintf("| `%s` | %d |\n", sanitize(k), model.Counts[k]))
	}
	if len(model.Indicators) > 0 {
		b.WriteString("\nIndicators: ")
		limit := model.Indicators
		if len(limit) > 12 {
			limit = limit[:12]
		}
		for i, ind := range limit {
			if i > 0 {
				b.WriteString(" · ")
			}
			b.WriteString("`" + sanitize(ind) + "`")
		}
		b.WriteString("\n")
	}
	f, err := os.OpenFile(*summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(b.String())
	return err
}

func renderHTML(args []string) error {
	fs := flag.NewFlagSet("render-html", flag.ContinueOnError)
	in := fs.String("in", envOr("COLDSTEP_REPORT_MODEL_IN", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	out := fs.String("out", envOr("COLDSTEP_REPORT_HTML_OUT", filepath.Join(envOr("GITHUB_WORKSPACE", "."), "coldstep-detect-report.html")), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	model, err := readModel(*in)
	if err != nil {
		return err
	}
	var rows strings.Builder
	for _, k := range mapKeys(model.Counts) {
		rows.WriteString(fmt.Sprintf("<tr><td><code>%s</code></td><td>%d</td></tr>\n", html.EscapeString(k), model.Counts[k]))
	}
	doc := "<!doctype html><html><head><meta charset=\"utf-8\"><title>Coldstep Detect Report</title></head><body>" +
		"<h1>Coldstep Detect Report (Go)</h1>" +
		"<p>Schema: <code>" + html.EscapeString(model.SchemaVersion) + "</code></p>" +
		"<table border=\"1\" cellspacing=\"0\" cellpadding=\"6\"><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>" +
		rows.String() +
		"</tbody></table></body></html>"
	return os.WriteFile(*out, []byte(doc), 0o644)
}

func diffSummary(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	current := fs.String("current", envOr("NS_CURRENT", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-events.jsonl")), "")
	baseline := fs.String("baseline", envOr("NS_BASELINE", ""), "")
	summary := fs.String("summary", envOr("NS_SUMMARY", envOr("GITHUB_STEP_SUMMARY", "")), "")
	marker := fs.String("marker", envOr("NS_MARKER", "coldstep-prev-diff"), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *summary == "" || *baseline == "" {
		return nil
	}
	cc, _, err := parseJSONLCounts(*current)
	if err != nil {
		return err
	}
	bc, _, err := parseJSONLCounts(*baseline)
	if err != nil {
		return err
	}
	line := fmt.Sprintf("- %s.result=ok (current=%d baseline=%d)\n", *marker, sumMap(cc), sumMap(bc))
	f, err := os.OpenFile(*summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

func markSkippedEnrichment(args []string, key, reason string) error {
	fs := flag.NewFlagSet(key+"-enrich", flag.ContinueOnError)
	in := fs.String("in", envOr("COLDSTEP_REPORT_MODEL_IN", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	model, err := readModel(*in)
	if err != nil {
		return err
	}
	if model.Extras == nil {
		model.Extras = map[string]any{}
	}
	model.Extras[key] = map[string]string{"skipped": reason}
	raw, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*in, raw, 0o644)
}

func renderIPSummary(args []string) error {
	fs := flag.NewFlagSet("render-ip-summary", flag.ContinueOnError)
	in := fs.String("in", envOr("COLDSTEP_REPORT_MODEL_IN", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	summaryPath := fs.String("summary", envOr("GITHUB_STEP_SUMMARY", ""), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	model, err := readModel(*in)
	if err != nil {
		return err
	}
	if *summaryPath == "" {
		return nil
	}
	var b strings.Builder
	b.WriteString("## IP Classification Summary (Go)\n\n")
	if len(model.Indicators) == 0 {
		b.WriteString("- No indicators found.\n")
	} else {
		b.WriteString("| Indicator |\n|:--|\n")
		limit := model.Indicators
		if len(limit) > 20 {
			limit = limit[:20]
		}
		for _, ind := range limit {
			b.WriteString("| `" + sanitize(ind) + "` |\n")
		}
	}
	f, err := os.OpenFile(*summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(b.String())
	return err
}

func readModel(path string) (reportModel, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return reportModel{}, err
	}
	var m reportModel
	if err := json.Unmarshal(raw, &m); err != nil {
		return reportModel{}, err
	}
	if m.Counts == nil {
		m.Counts = map[string]int{}
	}
	return m, nil
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return ""
	}
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func mapKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sumMap(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "|", "·")
	return strings.TrimSpace(s)
}

func exitIf(err error) {
	if err != nil {
		exitf(err.Error())
	}
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
