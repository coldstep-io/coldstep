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
