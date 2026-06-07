package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/coldstep-io/coldstep/internal/atomicwrite"
	"github.com/coldstep-io/coldstep/internal/report/markdown"
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
func writeDetailedMarkdownReport(baseDir string) {
	eventsPath := filepath.Join(baseDir, ".coldstep-events.jsonl")
	f, err := os.Open(eventsPath) // #nosec G304 -- baseDir is GITHUB_WORKSPACE (trusted env), fixed filename //nolint:gosec
	if err != nil {
		// No event stream (e.g. agent never started) — nothing to render.
		return
	}
	defer f.Close()

	agg, err := markdown.Parse(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "coldstep: parse events for markdown report: %v\n", err)
		return
	}

	outPath := filepath.Join(baseDir, ".coldstep-report.md")
	if werr := atomicwrite.Bytes(outPath, []byte(agg.RenderDetailed()), 0o644); werr != nil {
		fmt.Fprintf(os.Stderr, "coldstep: write %s: %v\n", outPath, werr)
	}
}
