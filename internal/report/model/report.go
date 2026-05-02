package model

import "encoding/json"

type Report struct {
	SchemaVersion    string                `json:"schema_version"`
	ProducedBy       string                `json:"produced_by"`
	GeneratedAt      string                `json:"generated_at"`
	Run              RunMeta               `json:"run"`
	CapabilityMatrix []CapabilityCell      `json:"capability_matrix"`
	EventsByType     []EventCount          `json:"events_by_type"`
	Timeline         []TimelineBucket      `json:"timeline"`
	EgressSankey     []SankeyEdge          `json:"egress_sankey"`
	Diff             DiffPayload           `json:"diff"`
	IPClassification []ClassifiedIndicator `json:"ip_classification"`
	CapabilityEval   CapabilityEval        `json:"capability_eval"`
	OTX              json.RawMessage       `json:"otx"`
	RDNS             json.RawMessage       `json:"rdns"`
}

type RunMeta struct {
	RunID         string `json:"run_id"`
	WorkflowFile  string `json:"workflow_file"`
	Branch        string `json:"branch"`
	RunnerLabel   string `json:"runner_label"`
	DetectProfile string `json:"detect_profile,omitempty"` // standard | enhanced (matches COLDSTEP_DETECT_PROFILE on build-model)
}

type CapabilityCell struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Status        string `json:"status"`
	EvidenceCount int    `json:"evidence_count"`
}

type EventCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type TimelineBucket struct {
	Bucket string `json:"bucket"`
	Type   string `json:"type"`
	Count  int    `json:"count"`
}

type SankeyEdge struct {
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	Value      int      `json:"value"`
	Indicators []string `json:"indicators"`
}

type DiffPayload struct {
	Status         string        `json:"status"`
	Reason         string        `json:"reason,omitempty"`
	TrafficNew     []DiffEntry   `json:"traffic_new"`
	TrafficGone    []DiffEntry   `json:"traffic_gone"`
	TrafficChanged []DiffChanged `json:"traffic_changed"`
}

type DiffEntry struct {
	Count       int      `json:"count"`
	Fingerprint string   `json:"fingerprint"`
	Indicators  []string `json:"indicators"`
}

type DiffChanged struct {
	Baseline    int      `json:"baseline"`
	Current     int      `json:"current"`
	Fingerprint string   `json:"fingerprint"`
	Indicators  []string `json:"indicators"`
}

type ClassifiedIndicator struct {
	Indicator  string   `json:"indicator"`
	Kind       string   `json:"kind"`
	Verdict    string   `json:"verdict"`
	Confidence string   `json:"confidence"`
	RDNS       []string `json:"rdns,omitempty"`
	ASN        string   `json:"asn,omitempty"`
	Severity   string   `json:"severity"`
	FirstSeen  string   `json:"first_seen,omitempty"`
}

type CapabilityEval struct {
	Verdict          string             `json:"verdict"`
	Score            int                `json:"score"`
	Reasons          []Reason           `json:"reasons"`
	Integrity        IntegritySection   `json:"integrity"`
	Coverage         CoverageSection    `json:"coverage"`
	Weights          map[string]float64 `json:"weights"`
	FailThreshold    int                `json:"fail_threshold"`
	PassThreshold    int                `json:"pass_threshold"`
	CorrelationScore int                `json:"correlation_score"`
}

type Reason struct {
	Code     ReasonCode `json:"code"`
	Rule     string     `json:"rule,omitempty"`
	Type     string     `json:"type,omitempty"`
	Severity Severity   `json:"severity"`
}

type ReasonCode string

const (
	ReasonRequiredTypeMissing  ReasonCode = "REQUIRED_TYPE_MISSING"
	ReasonCanaryMissing        ReasonCode = "CANARY_MISSING"
	ReasonScoreBelowFailThresh ReasonCode = "SCORE_BELOW_FAIL_THRESHOLD"
	ReasonScoreBelowPassThresh ReasonCode = "SCORE_BELOW_PASS_THRESHOLD"
	// ReasonBPFMapTamperDetected fires when at least one bpf_tamper JSONL
	// event is present in the input stream. It is a hard-fail that forces
	// integrityScore to 0 so the report cannot show a healthy verdict while
	// kernel-side BPF map integrity is being eroded (M-12 anti-blindness).
	ReasonBPFMapTamperDetected ReasonCode = "BPF_MAP_TAMPER_DETECTED"
)

type Severity string

const (
	SeverityFail Severity = "fail"
	SeverityWarn Severity = "warn"
)

type IntegritySection struct {
	Status  string                 `json:"status"`
	Score   int                    `json:"score"`
	Details IntegritySectionDetail `json:"details"`
}

type IntegritySectionDetail struct {
	MissingTypes     []string `json:"missing_types"`
	SeenTypes        []string `json:"seen_types"`
	CanariesSeen     []string `json:"canaries_seen"`
	CanariesRequired []string `json:"canaries_required"`
}

type CoverageSection struct {
	Score           int            `json:"score"`
	CoverageCells   []CoverageCell `json:"coverage_cells"`
	UnobservedPaths []string       `json:"unobserved_paths"`
}

type CoverageCell struct {
	Cell     string `json:"cell"`
	Observed bool   `json:"observed"`
}
