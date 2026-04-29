package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/coldstep-io/coldstep/internal/report/integrity"
	"github.com/coldstep-io/coldstep/internal/report/model"
	"github.com/coldstep-io/coldstep/internal/safepath"
)

const buildVersion = "v1.2.0"

func buildModel(args []string) error {
	fs := flag.NewFlagSet("build-model", flag.ContinueOnError)
	current := fs.String("current", envOr("COLDSTEP_REPORT_CURRENT_JSONL", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-events.jsonl")), "")
	baseline := fs.String("baseline", envOr("COLDSTEP_REPORT_BASELINE_JSONL", ""), "")
	out := fs.String("out", envOr("COLDSTEP_REPORT_MODEL_OUT", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	curPath, err := safepath.Workspace(*current, "COLDSTEP_REPORT_CURRENT_JSONL")
	if err != nil {
		return err
	}
	outPath, err := safepath.Workspace(*out, "COLDSTEP_REPORT_MODEL_OUT")
	if err != nil {
		return err
	}
	var basePath string
	if *baseline != "" {
		basePath, err = safepath.Workspace(*baseline, "COLDSTEP_REPORT_BASELINE_JSONL")
		if err != nil {
			return err
		}
	}

	events, err := model.LoadEvents(curPath)
	if err != nil {
		return fmt.Errorf("load current: %w", err)
	}
	var baseEvents []model.Event
	if basePath != "" {
		baseEvents, _ = model.LoadEvents(basePath)
	}

	m := &model.Report{
		SchemaVersion: model.SchemaVersion,
		ProducedBy:    fmt.Sprintf("%s@%s", model.ProducedByPrefix, buildVersion),
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Run: model.RunMeta{
			RunID:        os.Getenv("GITHUB_RUN_ID"),
			WorkflowFile: workflowFileFromRef(os.Getenv("GITHUB_WORKFLOW_REF")),
			Branch:       firstNonEmptyEnv("GITHUB_HEAD_REF", "GITHUB_REF_NAME"),
			RunnerLabel:  os.Getenv("NS_RUNNER_LABEL"),
		},
		CapabilityMatrix: model.BuildCapabilityMatrix(events),
		EventsByType:     model.BuildEventsByType(events),
		Timeline:         model.BuildTimeline(events),
		EgressSankey:     model.BuildEgressSankey(events),
		Diff:             model.BuildDiff(events, baseEvents),
		IPClassification: []model.ClassifiedIndicator{}, // populated in Plan 3
		CapabilityEval:   integrity.Evaluate(events),
		OTX:              json.RawMessage(`null`),
		RDNS:             json.RawMessage(`null`),
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	raw, err := model.MarshalCanonical(m)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, raw, 0o644)
}

func workflowFileFromRef(ref string) string {
	// GITHUB_WORKFLOW_REF format: "{owner}/{repo}/.github/workflows/{file}@{ref}"
	if ref == "" {
		return ""
	}
	at := indexAt(ref, '@')
	if at >= 0 {
		ref = ref[:at]
	}
	slash := lastIndex(ref, '/')
	if slash >= 0 {
		return ref[slash+1:]
	}
	return ref
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func indexAt(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func lastIndex(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}
