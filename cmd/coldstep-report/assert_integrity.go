package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coldstep-io/coldstep/internal/report/integrity"
	"github.com/coldstep-io/coldstep/internal/report/model"
	"github.com/coldstep-io/coldstep/internal/safepath"
)

func assertIntegrity(args []string) error {
	fs := flag.NewFlagSet("assert-integrity", flag.ContinueOnError)
	in := fs.String("in", envOr("COLDSTEP_REPORT_MODEL_IN", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-report-model.json")), "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	inPath, err := safepath.Workspace(*in, "COLDSTEP_REPORT_MODEL_IN")
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	if len(raw) > maxReportModelJSONBytes {
		return fmt.Errorf("report model exceeds max size (%d bytes)", maxReportModelJSONBytes)
	}

	var m model.Report
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}

	// P1-2 / 4a: hard-fail when build-model marked the observation window as
	// too short. Allowlist promotion off a short detect window is a known
	// poisoning vector — surface it as an actionable workflow error.
	if m.ShortObservationWindow {
		fmt.Printf(
			"::error title=Coldstep short observation window::observation window %.2fh is shorter than required minimum %.2fh — refusing to promote allowlist (P1-2)\n",
			m.ObservationHours, m.MinObservationHours,
		)
		return errors.New("integrity gate verdict=fail (short_observation_window)")
	}

	// H17: warn-only surface for single-observation and DGA-shaped
	// destinations. The poisoning gate is the diff/window check above —
	// these are reviewer hints (allowlist promotion of a once-seen or
	// DGA-shaped domain warrants a second look), not a hard fail.
	reportLearningModeReviewerHints(m.SuspiciousDomains)

	switch m.CapabilityEval.Verdict {
	case integrity.VerdictPass:
		fmt.Printf("Coldstep Integrity Pass: verdict=%s score=%d\n", m.CapabilityEval.Verdict, m.CapabilityEval.Score)
		return nil
	case integrity.VerdictWarn:
		fmt.Printf("::warning title=Coldstep Integrity Warning::Detect-mode integrity check produced verdict=warn (score: %d).\n", m.CapabilityEval.Score)
		for _, reason := range m.CapabilityEval.Reasons {
			fmt.Printf("::warning::Reason: %s rule=%s type=%s severity=%s\n", reason.Code, reason.Rule, reason.Type, reason.Severity)
		}
		return nil
	case integrity.VerdictFail:
		fmt.Printf("::error title=Coldstep Integrity Failure::Detect-mode integrity check failed (score: %d). Required telemetry was missing.\n", m.CapabilityEval.Score)
		for _, reason := range m.CapabilityEval.Reasons {
			if reason.Severity == model.SeverityFail {
				fmt.Printf("::error::Reason: %s rule=%s type=%s\n", reason.Code, reason.Rule, reason.Type)
			}
		}
		return errors.New("integrity gate verdict=fail")
	default:
		return fmt.Errorf("missing or unsupported capability_eval.verdict: %q", m.CapabilityEval.Verdict)
	}
}

// reportLearningModeReviewerHints prints a warn-only section listing
// destinations that the H17 poisoning heuristic flagged for manual
// review (DGA-shaped left labels and once-seen domains). Empty input
// stays silent. The integrity verdict is not changed — this is a
// reviewer hint, not a gate. Sorted DGA-first so the highest-priority
// reviewer signal sorts to the top of the section.
func reportLearningModeReviewerHints(rows []model.SuspiciousDomain) {
	if len(rows) == 0 {
		return
	}
	var dga, single []model.SuspiciousDomain
	for _, r := range rows {
		switch r.RiskHint {
		case model.RiskHintSuspiciousDGA:
			dga = append(dga, r)
		case model.RiskHintSingleObservation:
			single = append(single, r)
		}
	}
	if len(dga) == 0 && len(single) == 0 {
		return
	}
	fmt.Printf(
		"::warning title=Coldstep learning-mode reviewer hints (H17)::%d DGA-shaped / %d single-observation destination(s) — review before promoting to allowlist\n",
		len(dga), len(single),
	)
	for _, r := range dga {
		fmt.Printf("::warning::DGA-shaped destination: %s (observation_count=%d)\n", r.Domain, r.ObservationCount)
	}
	for _, r := range single {
		fmt.Printf("::warning::Single-observation destination: %s\n", r.Domain)
	}
}
