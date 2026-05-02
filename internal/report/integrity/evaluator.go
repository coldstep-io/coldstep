package integrity

import (
	"sort"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

type Config struct {
	FailThreshold int
	PassThreshold int
	Weights       map[string]float64
}

func defaultConfig() Config {
	return Config{
		FailThreshold: DefaultFailThreshold,
		PassThreshold: DefaultPassThreshold,
		Weights:       DefaultWeights(),
	}
}

func Evaluate(events []model.Event) model.CapabilityEval {
	return EvaluateWithRequired(events, DefaultRequiredTypes(), defaultConfig())
}

// EvaluateForDetectProfile uses stricter required event types when profile is "enhanced".
func EvaluateForDetectProfile(events []model.Event, detectProfile string) model.CapabilityEval {
	return EvaluateWithRequired(events, RequiredTypesForDetectProfile(detectProfile), defaultConfig())
}

func EvaluateWithConfig(events []model.Event, cfg Config) model.CapabilityEval {
	return EvaluateWithRequired(events, DefaultRequiredTypes(), cfg)
}

func EvaluateWithRequired(events []model.Event, required []string, cfg Config) model.CapabilityEval {
	if cfg.FailThreshold == 0 {
		cfg.FailThreshold = DefaultFailThreshold
	}
	if cfg.PassThreshold == 0 {
		cfg.PassThreshold = DefaultPassThreshold
	}
	if cfg.Weights == nil {
		cfg.Weights = DefaultWeights()
	}

	reasonsReq, seenTypes := CheckRequiredTypes(events, required)
	reasonsCanary, canariesSeen, canariesRequired := EvaluateCanaries(events, DefaultCanaryRules())
	reasonsTamper := CheckBPFTamper(events)
	hardFailReasons := append([]model.Reason{}, reasonsReq...)
	hardFailReasons = append(hardFailReasons, reasonsTamper...)

	coverage := EvaluateCoverage(events)
	correlationScore := 100 // v1 placeholder until correlation metric is ported.

	integrityStatus := VerdictPass
	integrityScore := 100
	if len(hardFailReasons) > 0 {
		integrityStatus = VerdictFail
		integrityScore = 0
	} else if len(reasonsCanary) > 0 {
		integrityStatus = VerdictWarn
		// Missing canaries indicate partial observability rather than complete blindness.
		integrityScore = 70
	}

	finalScore := 0
	verdict := VerdictFail
	reasons := append([]model.Reason{}, hardFailReasons...)
	reasons = append(reasons, reasonsCanary...)
	if len(hardFailReasons) == 0 {
		finalScore = BalancedScore(integrityScore, coverage.Score, correlationScore, cfg.Weights)
		switch {
		case finalScore < cfg.FailThreshold:
			verdict = VerdictFail
			reasons = append(reasons, model.Reason{Code: model.ReasonScoreBelowFailThresh, Severity: model.SeverityFail})
		case finalScore < cfg.PassThreshold:
			verdict = VerdictWarn
			reasons = append(reasons, model.Reason{Code: model.ReasonScoreBelowPassThresh, Severity: model.SeverityWarn})
		default:
			verdict = VerdictPass
		}
	}

	// deterministic reasons ordering by (severity desc fail>warn, code, rule, type)
	sort.Slice(reasons, func(i, j int) bool {
		si, sj := severityRank(reasons[i].Severity), severityRank(reasons[j].Severity)
		if si != sj {
			return si < sj
		}
		if reasons[i].Code != reasons[j].Code {
			return reasons[i].Code < reasons[j].Code
		}
		if reasons[i].Rule != reasons[j].Rule {
			return reasons[i].Rule < reasons[j].Rule
		}
		return reasons[i].Type < reasons[j].Type
	})

	return model.CapabilityEval{
		Verdict:          verdict,
		Score:            finalScore,
		Reasons:          reasons,
		Integrity:        model.IntegritySection{Status: integrityStatus, Score: integrityScore, Details: model.IntegritySectionDetail{MissingTypes: missingTypesFromReasons(reasonsReq), SeenTypes: seenTypes, CanariesSeen: canariesSeen, CanariesRequired: canariesRequired}},
		Coverage:         coverage,
		Weights:          cfg.Weights,
		FailThreshold:    cfg.FailThreshold,
		PassThreshold:    cfg.PassThreshold,
		CorrelationScore: correlationScore,
	}
}

func severityRank(s model.Severity) int {
	if s == model.SeverityFail {
		return 0
	}
	return 1
}

func missingTypesFromReasons(reasons []model.Reason) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		if r.Code == model.ReasonRequiredTypeMissing && r.Type != "" {
			out = append(out, r.Type)
		}
	}
	sort.Strings(out)
	return out
}
