package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coldstep-io/coldstep/internal/atomicwrite"
	"github.com/coldstep-io/coldstep/internal/report/integrity"
	"github.com/coldstep-io/coldstep/internal/report/model"
	"github.com/coldstep-io/coldstep/internal/safepath"
)

const buildVersion = "v0.4.1"

func buildModel(args []string) error {
	fs := flag.NewFlagSet("build-model", flag.ContinueOnError)
	current := fs.String("current", envOr("COLDSTEP_REPORT_CURRENT_JSONL", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-events.jsonl")), "")
	baseline := fs.String("baseline", envOr("COLDSTEP_REPORT_BASELINE_JSONL", ""), "")
	out := fs.String("out", envOr("COLDSTEP_REPORT_MODEL_OUT", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	minObs := fs.Float64(
		"min-observation-hours",
		parseFloatEnv("COLDSTEP_MIN_OBS_HOURS"),
		"minimum required wall-clock observation window in hours; sets short_observation_window=true on the model when shorter (P1-2 learning-mode-poisoning gate)",
	)
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
		loaded, loadErr := model.LoadEvents(basePath)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "::warning::baseline load failed for COLDSTEP_REPORT_BASELINE_JSONL (%s): %v; diff will be unavailable\n", basePath, loadErr)
		} else {
			baseEvents = loaded
		}
	}

	prof, err := detectProfileForReport()
	if err != nil {
		return err
	}

	observationHours := model.ObservationHours(events)
	short := false
	if *minObs > 0 && observationHours < *minObs {
		short = true
		minutes := int(math.Round(observationHours * 60))
		fmt.Fprintf(
			os.Stderr,
			"coldstep-report: observation window is %d minutes; --min-observation-hours requires %g hours (H17)\n",
			minutes, *minObs,
		)
		fmt.Fprintf(
			os.Stderr,
			"::warning title=Coldstep short observation window::observation window %.2fh is shorter than --min-observation-hours=%.2f; allowlist promotion is risky (P1-2)\n",
			observationHours, *minObs,
		)
	}

	m := &model.Report{
		SchemaVersion: model.SchemaVersion,
		ProducedBy:    fmt.Sprintf("%s@%s", model.ProducedByPrefix, buildVersion),
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Run: model.RunMeta{
			RunID:         os.Getenv("GITHUB_RUN_ID"),
			WorkflowFile:  workflowFileFromRef(os.Getenv("GITHUB_WORKFLOW_REF")),
			Branch:        firstNonEmptyEnv("GITHUB_HEAD_REF", "GITHUB_REF_NAME"),
			RunnerLabel:   os.Getenv("NS_RUNNER_LABEL"),
			DetectProfile: prof,
		},
		CapabilityMatrix:       model.BuildCapabilityMatrix(events),
		EventsByType:           model.BuildEventsByType(events),
		Timeline:               model.BuildTimeline(events),
		EgressSankey:           model.BuildEgressSankey(events),
		Diff:                   model.BuildDiff(events, baseEvents),
		IPClassification:       []model.ClassifiedIndicator{}, // populated in Plan 3
		CapabilityEval:         integrity.EvaluateForDetectProfile(events, prof),
		OTX:                    json.RawMessage(`null`),
		RDNS:                   json.RawMessage(`null`),
		ObservationHours:       roundTo(observationHours, 4),
		ShortObservationWindow: short,
		MinObservationHours:    *minObs,
		SuspiciousDomains:      model.BuildSuspiciousDomains(events),
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	raw, err := model.MarshalCanonical(m)
	if err != nil {
		return err
	}
	return atomicwrite.Bytes(outPath, raw, 0o644)
}

func detectProfileForReport() (string, error) {
	raw := strings.TrimSpace(os.Getenv("COLDSTEP_DETECT_PROFILE"))
	if raw == "" {
		return "standard", nil
	}
	low := strings.ToLower(raw)
	if low != "standard" && low != "enhanced" {
		return "", fmt.Errorf("invalid COLDSTEP_DETECT_PROFILE %q (use standard or enhanced)", raw)
	}
	return low, nil
}

func workflowFileFromRef(ref string) string {
	// GITHUB_WORKFLOW_REF format: "{owner}/{repo}/.github/workflows/{file}@{ref}"
	if ref == "" {
		return ""
	}
	at := strings.IndexByte(ref, '@')
	if at >= 0 {
		ref = ref[:at]
	}
	slash := strings.LastIndexByte(ref, '/')
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

// parseFloatEnv reads a float-valued env var. Returns 0 when unset, empty,
// or unparseable (matches the "flag absent" default for --min-observation-hours).
func parseFloatEnv(key string) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0
	}
	return v
}

func roundTo(f float64, places int) float64 {
	pow := math.Pow(10, float64(places))
	return math.Round(f*pow) / pow
}
