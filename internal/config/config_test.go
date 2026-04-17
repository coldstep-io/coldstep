//go:build !windows

// Go tests are not built or run on Windows (out of scope; avoids Smart App Control blocking
// unsigned *.test.exe — see https://support.microsoft.com/en-us/windows/smart-app-control-has-blocked-part-of-this-app-0729fff1-48bf-4b25-aa97-632fe55ccca2).
// Authoritative runs: GitHub Actions ubuntu-latest.

package config

import (
	"net"
	"strings"
	"testing"

	"github.com/coldstep-io/coldstep/internal/policy"
)

func clearColdstepPolicyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("COLDSTEP_IGNORED_IP_NETS", "")
	t.Setenv("COLDSTEP_NO_DEFAULT_IGNORED_NETS", "")
	t.Setenv("COLDSTEP_FEATURE_GATES", "")
}

func TestLoadFromEnv_DetectDefault(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	c, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeDetect {
		t.Fatalf("mode: got %q want detect", c.Mode)
	}
}

func TestLoadFromEnv_DefaultWhenUnset(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	c, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeDetect {
		t.Fatalf("mode: got %q want detect", c.Mode)
	}
}

func TestLoadFromEnv_DetectCaseInsensitive(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "DETECT")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	c, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeDetect {
		t.Fatalf("mode: got %q want detect", c.Mode)
	}
}

func TestLoadFromEnv_DefaultDetectLogUnderWorkspace(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "/tmp/gh-step-summary")
	t.Setenv("GITHUB_WORKSPACE", "/tmp/ghws")
	t.Setenv("COLDSTEP_DETECT_LOG", "")
	c, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := "/tmp/ghws/.coldstep-detect.md"
	if c.DetectLogPath != want {
		t.Fatalf("DetectLogPath: got %q want %q", c.DetectLogPath, want)
	}
}

func TestLoadFromEnv_DetectLogPath(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("GITHUB_WORKSPACE", "")
	t.Setenv("COLDSTEP_DETECT_LOG", "/tmp/coldstep-detect.log")
	c, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.DetectLogPath != "/tmp/coldstep-detect.log" {
		t.Fatalf("DetectLogPath: got %q", c.DetectLogPath)
	}
}

func TestLoadFromEnv_PreventRejected(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "prevent")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid CI_GUARD_MODE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadFromEnv_InvalidMode(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "nope")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadFromEnv_InvalidAllowedIP(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "not-an-ip")
	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadFromEnv_InvalidIgnoredCIDR(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("COLDSTEP_IGNORED_IP_NETS", "not-a-cidr")
	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadFromEnv_NoDefaultIgnoredNets(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("COLDSTEP_NO_DEFAULT_IGNORED_NETS", "true")
	c, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !c.NoDefaultIgnoredNets {
		t.Fatal("expected NoDefaultIgnoredNets")
	}
	p, err := c.Policy()
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Classify("", net.ParseIP("10.0.0.1")); got != policy.ClassMonitor {
		t.Fatalf("without defaults, 10.0.0.1 should be monitor, got %q", got)
	}
}

func TestLoadFromEnv_ModeDefaultsToDetect(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	c, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeDetect {
		t.Fatalf("mode: got %q want %q", c.Mode, ModeDetect)
	}
}

func TestLoadFromEnv_InvalidModeRejected(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "invalid")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid CI_GUARD_MODE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadFromEnv_EnforceRequiresAllowlist(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "enforce")
	t.Setenv("COLDSTEP_ALLOWED_DOMAINS", "  ")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "requires non-empty allowlist") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadFromEnv_AllowlistNormalization(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "enforce")
	t.Setenv("COLDSTEP_ALLOWED_DOMAINS", " Example.COM,foo.com  example.com\tFOO.com ")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	c, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "foo.com"}
	if len(c.AllowedDomains) != len(want) {
		t.Fatalf("AllowedDomains len: got %d want %d (%v)", len(c.AllowedDomains), len(want), c.AllowedDomains)
	}
	for i := range want {
		if c.AllowedDomains[i] != want[i] {
			t.Fatalf("AllowedDomains[%d]: got %q want %q", i, c.AllowedDomains[i], want[i])
		}
	}
}

func TestParseFeatureGates(t *testing.T) {
	t.Parallel()
	m := ParseFeatureGates(" proc_tree=1 , FS_EVENTS=false ")
	if got := m["proc_tree"]; got != "1" {
		t.Fatalf("proc_tree: got %q", got)
	}
	if got := m["fs_events"]; got != "false" {
		t.Fatalf("fs_events: got %q", got)
	}
	if FeatureGateEnabled(m, "PROC_TREE") != true {
		t.Fatalf("PROC_TREE should enable")
	}
	if FeatureGateEnabled(m, "proc_tree") != true {
		t.Fatalf("proc_tree should enable")
	}
	if FeatureGateEnabled(m, "missing") {
		t.Fatalf("missing gate should be disabled")
	}
}

func TestParseFeatureGates_InvalidPairsIgnored(t *testing.T) {
	t.Parallel()
	m := ParseFeatureGates("nonsense,foo=bar=qux,,=nokey,noval=")
	if len(m) != 1 || m["foo"] != "bar=qux" {
		t.Fatalf("unexpected map: %#v", m)
	}
}

func TestLoadFromEnv_CgroupPath(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CgroupAttachPath == "" {
		t.Fatal("expected non-empty CgroupAttachPath")
	}
}

func TestLoadFromEnv_FeatureGates(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("COLDSTEP_FEATURE_GATES", "proc_tree=1,other=0")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !FeatureGateEnabled(cfg.FeatureGates, "proc_tree") {
		t.Fatalf("expected proc_tree enabled")
	}
	if FeatureGateEnabled(cfg.FeatureGates, "other") {
		t.Fatalf("expected other disabled")
	}
}

func TestLoadFromEnv_DefaultArtifactPathsUnderWorkspace(t *testing.T) {
	clearColdstepPolicyEnv(t)
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("GITHUB_WORKSPACE", "/tmp/ws")
	c, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(c.EventsLogPath, ".coldstep-events.jsonl") {
		t.Fatalf("EventsLogPath: %q", c.EventsLogPath)
	}
	if !strings.Contains(c.EventsLogPath, "ws") {
		t.Fatalf("expected workspace in path: %q", c.EventsLogPath)
	}
	if c.DetectLogPath != "/tmp/ws/.coldstep-detect.md" {
		t.Fatalf("DetectLogPath: got %q", c.DetectLogPath)
	}
}
