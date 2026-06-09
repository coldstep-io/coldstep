package actioncli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/coldstep-io/coldstep/internal/atomicwrite"
	"github.com/coldstep-io/coldstep/internal/report/markdown"
	"github.com/coldstep-io/coldstep/internal/safepath"
)

// writeDetailedMarkdownReport reads the JSONL event stream (the source of truth)
// and writes the pure-markdown detailed report to .coldstep-report.md for
// artifact upload. Part of eliminating the separate coldstep-report binary:
// report rendering moves into the userspace stop step.
//
// Best-effort: any failure logs to stderr and returns without erroring, so a
// missing or partial event stream never fails the post-job step. The agent's
// .coldstep-detect.md remains the job-summary source until a later phase swaps
// it for markdown.Aggregate.RenderSimple.
// Returns the parsed Aggregate (or nil when no event stream is present) so the
// caller can reuse it for the --strict required-type gate without re-parsing.
func writeDetailedMarkdownReport(baseDir string) *markdown.Aggregate {
	eventsPath := filepath.Join(baseDir, ".coldstep-events.jsonl")
	f, err := os.Open(eventsPath) // #nosec G304 -- baseDir is GITHUB_WORKSPACE (trusted env), fixed filename //nolint:gosec
	if err != nil {
		// No event stream (e.g. agent never started) — nothing to render.
		return nil
	}
	defer f.Close()

	agg, err := markdown.Parse(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "coldstep: parse events for markdown report: %v\n", err)
		return nil
	}

	outPath := filepath.Join(baseDir, ".coldstep-report.md")
	if werr := atomicwrite.Bytes(outPath, []byte(agg.RenderDetailed()), 0o644); werr != nil {
		fmt.Fprintf(os.Stderr, "coldstep: write %s: %v\n", outPath, werr)
	}
	return agg
}

// warnRemovedAllowlistInputs emits a one-line GitHub Actions warning when a
// consumer still sets an input removed in the allowlist consolidation
// (ignored-nets, ignored-nets-file, bootstrap-allowlist). GitHub exposes any
// `with:` key as INPUT_<NAME> (spaces->_, uppercased; dashes preserved), so a
// non-empty value is detectable even though the input is no longer declared.
// Turns a silent breakage into an actionable message.
func warnRemovedAllowlistInputs() {
	for _, r := range []struct{ env, replacement string }{
		{"INPUT_IGNORED-NETS", "put `!CIDR` entries in `allow`"},
		{"INPUT_IGNORED-NETS-FILE", "put `!CIDR` lines in an `allow-file`"},
		{"INPUT_BOOTSTRAP-ALLOWLIST", "copy the reference packs into your own `allow-file`"},
	} {
		if strings.TrimSpace(os.Getenv(r.env)) != "" {
			name := strings.ToLower(strings.TrimPrefix(r.env, "INPUT_"))
			fmt.Fprintf(os.Stderr, "::warning title=Coldstep removed input::`%s` was removed in the allowlist consolidation; %s\n", name, r.replacement)
		}
	}
}

// parseAggregateFile parses a JSONL event stream into a markdown.Aggregate.
func parseAggregateFile(path string) (*markdown.Aggregate, error) {
	f, err := os.Open(path) // #nosec G304 -- workspace-validated path (safepath.Workspace) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return markdown.Parse(f)
}

// runDiff implements `coldstep-action diff` — the baseline destination-domain
// diff that replaces `coldstep-report diff`. It reads two JSONL streams
// directly (no report model), writes a compact marker block to the job
// summary, and, with --fail-on-new-domain, exits non-zero when current
// introduces destination domains absent from baseline (P1-2 supply-chain
// learning-mode-poisoning gate).
func runDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	ws := getenvDefault("GITHUB_WORKSPACE", ".")
	current := fs.String("current", filepath.Join(ws, ".coldstep-events.jsonl"), "")
	baseline := fs.String("baseline", "", "")
	summary := fs.String("summary", os.Getenv("GITHUB_STEP_SUMMARY"), "")
	marker := fs.String("marker", "coldstep-prev-diff", "")
	failOnNewDomain := fs.Bool("fail-on-new-domain", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*summary) == "" {
		return fmt.Errorf("diff: summary path is required")
	}
	if strings.TrimSpace(*baseline) == "" {
		return fmt.Errorf("diff: baseline path is required")
	}

	currentPath, err := safepath.Workspace(*current, "current")
	if err != nil {
		return err
	}
	baselinePath, err := safepath.Workspace(*baseline, "baseline")
	if err != nil {
		return err
	}
	summaryPath, err := safepath.Workspace(*summary, "GITHUB_STEP_SUMMARY")
	if err != nil {
		return err
	}

	cur, err := parseAggregateFile(currentPath)
	if err != nil {
		return fmt.Errorf("load current events: %w", err)
	}
	base, err := parseAggregateFile(baselinePath)
	if err != nil {
		return fmt.Errorf("load baseline events: %w", err)
	}

	added, removed := markdown.DiffDomains(cur, base)
	result := "no-change"
	if len(added) > 0 || len(removed) > 0 {
		result = "changed"
	}

	block := fmt.Sprintf(
		"\n#### Previous-run traffic diff (compact)\n\n- %s.result=%s\n- %s.new_domains=%d\n- %s.gone_domains=%d\n",
		*marker, result, *marker, len(added), *marker, len(removed),
	)
	f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) // #nosec G304 -- workspace-validated //nolint:gosec
	if err != nil {
		return err
	}
	if _, werr := f.WriteString(block); werr != nil {
		_ = f.Close()
		return werr
	}
	if cerr := f.Close(); cerr != nil {
		return cerr
	}

	if *failOnNewDomain && len(added) > 0 {
		fmt.Fprintf(os.Stderr,
			"::error title=Coldstep new destination domains::%d domain(s) present in current but absent from baseline (P1-2): %s\n",
			len(added), strings.Join(added, ", "))
		return fmt.Errorf("diff: %d new destination domain(s) not present in baseline", len(added))
	}
	return nil
}

// runAssertIntegrity implements `coldstep-action assert-integrity` — the
// anti-blindness required-event-type gate as a standalone subcommand (1:1
// replacement for `coldstep-report assert-integrity`, JSONL-direct, no report
// model). Exits non-zero when expected event types are absent. The detect
// profile selects the required set (standard vs enhanced).
func runAssertIntegrity(args []string) error {
	fs := flag.NewFlagSet("assert-integrity", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	ws := getenvDefault("GITHUB_WORKSPACE", ".")
	in := fs.String("in", filepath.Join(ws, ".coldstep-events.jsonl"), "")
	profile := fs.String("detect-profile", getenvDefault("COLDSTEP_DETECT_PROFILE", ""), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	inPath, err := safepath.Workspace(*in, "in")
	if err != nil {
		return err
	}
	agg, err := parseAggregateFile(inPath)
	if err != nil {
		return fmt.Errorf("load events: %w", err)
	}
	if missing := agg.MissingRequiredTypes(*profile); len(missing) > 0 {
		fmt.Fprintf(os.Stderr,
			"::error title=Coldstep integrity gate::missing required event type(s): %s\n",
			strings.Join(missing, ", "))
		return fmt.Errorf("assert-integrity: missing required event type(s): %s", strings.Join(missing, ", "))
	}
	return nil
}
