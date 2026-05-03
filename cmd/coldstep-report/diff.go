package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coldstep-io/coldstep/internal/report/model"
	"github.com/coldstep-io/coldstep/internal/safepath"
)

func diffSummary(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	current := fs.String("current", envOr("NS_CURRENT", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-events.jsonl")), "")
	baseline := fs.String("baseline", envOr("NS_BASELINE", ""), "")
	summary := fs.String("summary", envOr("NS_SUMMARY", envOr("GITHUB_STEP_SUMMARY", "")), "")
	marker := fs.String("marker", envOr("NS_MARKER", "coldstep-prev-diff"), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *summary == "" {
		return fmt.Errorf("diff: summary path is required")
	}
	if *baseline == "" {
		return fmt.Errorf("diff: baseline path is required")
	}

	currentPath, err := safepath.Workspace(*current, "NS_CURRENT")
	if err != nil {
		return err
	}
	baselinePath, err := safepath.Workspace(*baseline, "NS_BASELINE")
	if err != nil {
		return err
	}
	summaryPath, err := safepath.Workspace(*summary, "NS_SUMMARY")
	if err != nil {
		return err
	}

	currentEvents, err := model.LoadEvents(currentPath)
	if err != nil {
		return fmt.Errorf("load current events: %w", err)
	}
	baselineEvents, err := model.LoadEvents(baselinePath)
	if err != nil {
		return fmt.Errorf("load baseline events: %w", err)
	}

	diff := model.BuildDiff(currentEvents, baselineEvents)
	if diff.Status != "ok" {
		return fmt.Errorf("diff unavailable: %s", diff.Reason)
	}

	changed := len(diff.TrafficNew) > 0 || len(diff.TrafficGone) > 0 || len(diff.TrafficChanged) > 0
	result := "no-change"
	if changed {
		result = "changed"
	}

	f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(
		f,
		"\n#### Previous-run traffic diff (compact)\n\n- %s.result=%s\n- %s.traffic_new=%d\n- %s.traffic_gone=%d\n- %s.traffic_changed=%d\n",
		*marker,
		result,
		*marker,
		len(diff.TrafficNew),
		*marker,
		len(diff.TrafficGone),
		*marker,
		len(diff.TrafficChanged),
	); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
