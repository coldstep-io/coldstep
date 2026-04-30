package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coldstep-io/coldstep/internal/cgroup"
	"github.com/coldstep-io/coldstep/internal/policy"
)

type Mode string

const (
	ModeDetect  Mode = "detect"
	ModeEnforce Mode = "enforce"
)

type Config struct {
	Mode            Mode
	StepSummaryPath string
	// DetectLogPath, when set, receives exec lines during the job; the action post step
	// merges this file into GITHUB_STEP_SUMMARY (GitHub freezes per-step summary files
	// when a step ends, so a long-running agent cannot write the summary path directly).
	DetectLogPath string

	AllowedHosts         string
	AllowedIPs           string
	IgnoredIPNets        string
	NoDefaultIgnoredNets bool
	AllowedDomains       []string
	LogLevel             string
	EventsLogPath        string
	TelemetrySummaryPath string
	AgentStatusPath      string
	// FeatureGates holds parsed COLDSTEP_FEATURE_GATES (lowercase keys).
	FeatureGates map[string]string
	// DetectProfile is COLDSTEP_DETECT_PROFILE: "standard" (default) or "enhanced" (merges default feature gates in detect; stricter report integrity when build-model reads the env).
	DetectProfile string
	// CgroupAttachPath is the unified cgroup2 path for link.AttachCgroup (from COLDSTEP_CGROUP_PATH or /proc/self/cgroup).
	CgroupAttachPath string
	SigningKey       string
}

func normalizeDomains(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		domain := strings.ToLower(strings.TrimSpace(part))
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	return out
}

func defaultUnderWorkspace(rel string) string {
	ws := strings.TrimSpace(os.Getenv("GITHUB_WORKSPACE"))
	if ws == "" {
		return rel
	}
	return filepath.Join(ws, rel)
}

// LoadFromEnv reads coldstep configuration from the environment.
func LoadFromEnv() (Config, error) {
	raw := strings.TrimSpace(os.Getenv("CI_GUARD_MODE"))
	rawLower := strings.ToLower(raw)
	if rawLower == "" {
		rawLower = string(ModeDetect)
	}
	if rawLower == "enforce" {
		return Config{}, fmt.Errorf("invalid CI_GUARD_MODE %q (use detect or defend)", raw)
	}
	mode := Mode(rawLower)
	if mode == "defend" {
		mode = ModeEnforce
	}
	if mode != ModeDetect && mode != ModeEnforce {
		return Config{}, fmt.Errorf("invalid CI_GUARD_MODE %q (use detect or defend)", raw)
	}

	summary := os.Getenv("GITHUB_STEP_SUMMARY")
	detectLog := strings.TrimSpace(os.Getenv("COLDSTEP_DETECT_LOG"))
	// Match events log: default to workspace so digest is not silently written only to
	// GITHUB_STEP_SUMMARY when COLDSTEP_DETECT_LOG is missing (e.g. sudo env filtering).
	if detectLog == "" {
		detectLog = defaultUnderWorkspace(".coldstep-detect.md")
	}
	allowedDomains := normalizeDomains(os.Getenv("COLDSTEP_ALLOWED_DOMAINS"))
	if mode == ModeEnforce && len(allowedDomains) == 0 {
		return Config{}, fmt.Errorf("CI_GUARD_MODE=defend requires non-empty allowlist (set COLDSTEP_ALLOWED_DOMAINS)")
	}

	hosts := os.Getenv("COLDSTEP_ALLOWED_HOSTS")
	ips := os.Getenv("COLDSTEP_ALLOWED_IPS")
	ignored := strings.TrimSpace(os.Getenv("COLDSTEP_IGNORED_IP_NETS"))
	noDefaultIgnored := envBoolTrue("COLDSTEP_NO_DEFAULT_IGNORED_NETS")
	if _, err := policy.BuildPolicyEx(hosts, ips, ignored, !noDefaultIgnored); err != nil {
		return Config{}, err
	}
	logLevel := strings.TrimSpace(os.Getenv("COLDSTEP_LOG_LEVEL"))
	if logLevel == "" {
		logLevel = "info"
	}

	eventsLog := strings.TrimSpace(os.Getenv("COLDSTEP_EVENTS_LOG"))
	if eventsLog == "" {
		eventsLog = defaultUnderWorkspace(".coldstep-events.jsonl")
	}

	telemetrySummary := strings.TrimSpace(os.Getenv("COLDSTEP_TELEMETRY_JSON"))
	if telemetrySummary == "" {
		telemetrySummary = defaultUnderWorkspace(".coldstep-telemetry.json")
	}

	agentStatus := strings.TrimSpace(os.Getenv("COLDSTEP_AGENT_STATUS"))
	if agentStatus == "" {
		agentStatus = defaultUnderWorkspace(".coldstep-ready.json")
	}

	profile := strings.ToLower(strings.TrimSpace(os.Getenv("COLDSTEP_DETECT_PROFILE")))
	if profile == "" {
		profile = "standard"
	}
	if profile != "standard" && profile != "enhanced" {
		return Config{}, fmt.Errorf("invalid COLDSTEP_DETECT_PROFILE %q (use standard or enhanced)", os.Getenv("COLDSTEP_DETECT_PROFILE"))
	}

	gates := ParseFeatureGates(os.Getenv("COLDSTEP_FEATURE_GATES"))
	gates = mergeEnhancedFeatureGates(profile, gates)

	cgPath, err := cgroup.AttachPath(os.Getenv("COLDSTEP_CGROUP_PATH"))
	if err != nil {
		return Config{}, err
	}

	return Config{
		Mode:                 mode,
		StepSummaryPath:      summary,
		DetectLogPath:        detectLog,
		AllowedHosts:         hosts,
		AllowedIPs:           ips,
		IgnoredIPNets:        ignored,
		NoDefaultIgnoredNets: noDefaultIgnored,
		AllowedDomains:       allowedDomains,
		LogLevel:             logLevel,
		EventsLogPath:        eventsLog,
		TelemetrySummaryPath: telemetrySummary,
		AgentStatusPath:      agentStatus,
		FeatureGates:         gates,
		DetectProfile:        profile,
		CgroupAttachPath:     cgPath,
		SigningKey:           os.Getenv("COLDSTEP_SIGNING_KEY"),
	}, nil
}

// mergeEnhancedFeatureGates adds proc_tree, tls_sni, fs_events when profile is enhanced and the key is absent (explicit user gates win).
func mergeEnhancedFeatureGates(profile string, gates map[string]string) map[string]string {
	p := strings.ToLower(strings.TrimSpace(profile))
	if p != "enhanced" {
		if gates == nil {
			return map[string]string{}
		}
		return gates
	}
	if gates == nil {
		gates = map[string]string{}
	}
	for _, key := range []string{"proc_tree", "tls_sni", "fs_events"} {
		if _, ok := gates[key]; !ok {
			gates[key] = "1"
		}
	}
	return gates
}

func envBoolTrue(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	return strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes") || strings.EqualFold(v, "on")
}

// Policy returns the parsed allow-list policy (never nil; may be disabled).
func (c Config) Policy() (*policy.Policy, error) {
	return policy.BuildPolicyEx(c.AllowedHosts, c.AllowedIPs, c.IgnoredIPNets, !c.NoDefaultIgnoredNets)
}

// PublicMode returns the user-facing mode label for JSONL and digest ("detect" | "defend").
// Blocking behavior still uses [ModeEnforce] internally.
func (c Config) PublicMode() string {
	if c.Mode == ModeEnforce {
		return "defend"
	}
	return string(c.Mode)
}
