package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// httpNotifyClient bounds post-step webhook/API calls so a stuck egress target
// cannot hang the composite until the job's global timeout.
var httpNotifyClient = &http.Client{Timeout: 60 * time.Second}

const (
	maxReadyStatusJSONBytes = 512 << 10 // agent status should be tiny; bound disk/memory abuse
	maxGitHubEventJSONBytes = 8 << 20   // $GITHUB_EVENT_PATH payload cap before full json.Unmarshal
	maxHTTPResponseDrain    = 256 << 10 // discard bodies after POST so connections can reuse
)

type startConfig struct {
	Mode                 string
	AllowedDomains       string
	AllowedDomainsFile   string
	AllowedHosts         string
	AllowedHostsFile     string
	AllowedIPs           string
	AllowedIPsFile       string
	IgnoredIPNets        string
	IgnoredIPNetsFile    string
	NoDefaultIgnoredNets bool
	LogLevel             string
	FeatureGates         string
	DetectProfile        string
	ReleasePath          string
	FailOnError          bool
	ReadyTimeoutSeconds  int
	SmokeTestEgress      bool
	IoUringDisable       bool
	SigningKey           string
	ReportJobSummary     bool
	BootstrapAllowlist   string
}

type stopConfig struct {
	FailOnError      bool
	ReportJobSummary bool
	ReportPRSummary  bool
	GithubToken      string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: coldstep-action <start|stop> [flags]")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "start":
		cfg, err := parseStartFlags(os.Args[2:])
		if err != nil {
			fatal(err)
		}
		fatal(runStart(cfg))
	case "stop":
		cfg, err := parseStopFlags(os.Args[2:])
		if err != nil {
			fatal(err)
		}
		fatal(runStop(cfg))
	default:
		fatal(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}

func parseStartFlags(args []string) (startConfig, error) {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := startConfig{}
	fs.StringVar(&cfg.Mode, "mode", "detect", "")
	fs.StringVar(&cfg.AllowedDomains, "allowed-domains", "", "")
	fs.StringVar(&cfg.AllowedDomainsFile, "allowed-domains-file", "", "")
	fs.StringVar(&cfg.AllowedHosts, "allowed-hosts", "", "")
	fs.StringVar(&cfg.AllowedHostsFile, "allowed-hosts-file", "", "")
	fs.StringVar(&cfg.AllowedIPs, "allowed-ips", "", "")
	fs.StringVar(&cfg.AllowedIPsFile, "allowed-ips-file", "", "")
	fs.StringVar(&cfg.IgnoredIPNets, "ignored-ip-nets", "", "")
	fs.StringVar(&cfg.IgnoredIPNetsFile, "ignored-ip-nets-file", "", "")
	fs.BoolVar(&cfg.NoDefaultIgnoredNets, "no-default-ignored-nets", false, "")
	fs.StringVar(&cfg.LogLevel, "log-level", "info", "")
	fs.StringVar(&cfg.FeatureGates, "feature-gates", "", "")
	fs.StringVar(&cfg.DetectProfile, "detect-profile", "standard", "")
	fs.StringVar(&cfg.ReleasePath, "release-path", "", "")
	fs.BoolVar(&cfg.FailOnError, "fail-on-error", false, "")
	fs.IntVar(&cfg.ReadyTimeoutSeconds, "ready-timeout-seconds", 1500, "")
	fs.BoolVar(&cfg.SmokeTestEgress, "smoke-test-egress", false, "")
	fs.BoolVar(&cfg.IoUringDisable, "io-uring-disable", true, "")
	fs.StringVar(&cfg.SigningKey, "signing-key", "", "")
	fs.BoolVar(&cfg.ReportJobSummary, "report-job-summary", true, "")
	fs.StringVar(&cfg.BootstrapAllowlist, "bootstrap-allowlist", "false", "")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func parseStopFlags(args []string) (stopConfig, error) {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := stopConfig{}
	fs.BoolVar(&cfg.FailOnError, "fail-on-error", false, "")
	fs.BoolVar(&cfg.ReportJobSummary, "report-job-summary", true, "")
	fs.BoolVar(&cfg.ReportPRSummary, "report-pr-summary", false, "")
	fs.StringVar(&cfg.GithubToken, "github-token", "", "")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// normalizeCompositeMode maps user-facing mode names to CI_GUARD_MODE (detect or defend).
func normalizeCompositeMode(raw string) (string, error) {
	mode := strings.TrimSpace(strings.ToLower(raw))
	if mode == "" {
		mode = "detect"
	}
	if mode == "enforce" {
		return "", fmt.Errorf("invalid mode %q (use detect or defend)", strings.TrimSpace(raw))
	}
	if mode != "detect" && mode != "defend" {
		return "", fmt.Errorf("invalid mode %q (use detect or defend)", strings.TrimSpace(raw))
	}
	return mode, nil
}

func runStart(cfg startConfig) error {
	if runtimeOS() != "linux" {
		return errors.New("coldstep requires a Linux runner (use runs-on: ubuntu-latest)")
	}

	actionPath := getenvDefault("GITHUB_ACTION_PATH", mustGetwd())
	baseDir := getenvDefault("GITHUB_WORKSPACE", actionPath)
	binPath := filepath.Join(actionPath, "bin", "coldstep")
	buildScript := filepath.Join(actionPath, "scripts", "build-agent-linux.sh")
	pidFile := filepath.Join(actionPath, ".coldstep.pid")
	detectLog := filepath.Join(baseDir, ".coldstep-detect.md")
	agentStatus := filepath.Join(baseDir, ".coldstep-ready.json")
	stderrLog := filepath.Join(baseDir, ".coldstep-agent.stderr.log")
	readyMarker := filepath.Join(actionPath, ".coldstep.ready.ok")

	if err := os.MkdirAll(filepath.Join(actionPath, "bin"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(detectLog, []byte{}, 0o644); err != nil {
		return err
	}
	_ = os.Remove(agentStatus)
	_ = os.Remove(readyMarker)
	if cfg.FailOnError {
		_ = os.Remove(stderrLog)
	}

	if cfg.IoUringDisable {
		_ = exec.Command("sudo", "sysctl", "-w", "io_uring_disabled=2").Run()
	}

	if cfg.ReleasePath != "" {
		src := cfg.ReleasePath
		if !filepath.IsAbs(src) {
			src = filepath.Join(baseDir, src)
		}
		if _, err := os.Stat(src); err != nil {
			return fmt.Errorf("release-path not found: %w", err)
		}
		raw, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(binPath, raw, 0o755); err != nil {
			return err
		}
	} else {
		cmd := exec.Command("bash", buildScript, actionPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	mode, err := normalizeCompositeMode(cfg.Mode)
	if err != nil {
		return err
	}

	domainsMerged, err := mergeInlineAndAllowlistFiles(baseDir, cfg.AllowedDomains, cfg.AllowedDomainsFile)
	if err != nil {
		return err
	}
	hostsMerged, err := mergeInlineAndAllowlistFiles(baseDir, cfg.AllowedHosts, cfg.AllowedHostsFile)
	if err != nil {
		return err
	}
	ipsMerged, err := mergeInlineAndAllowlistFiles(baseDir, cfg.AllowedIPs, cfg.AllowedIPsFile)
	if err != nil {
		return err
	}
	ignoredMerged, err := mergeInlineAndAllowlistFiles(baseDir, cfg.IgnoredIPNets, cfg.IgnoredIPNetsFile)
	if err != nil {
		return err
	}

	if truthyInput(cfg.BootstrapAllowlist) {
		dPath := filepath.Join(actionPath, "scripts", "coldstep_bootstrap", "allowlist-domains-v1.txt")
		iPath := filepath.Join(actionPath, "scripts", "coldstep_bootstrap", "allowlist-ips-v1.txt")
		var merr error
		domainsMerged, merr = appendBootstrapTokens(domainsMerged, dPath)
		if merr != nil {
			return merr
		}
		ipsMerged, merr = appendBootstrapTokens(ipsMerged, iPath)
		if merr != nil {
			return merr
		}
	}

	childEnv := os.Environ()
	childEnv = append(childEnv,
		"GITHUB_WORKSPACE="+baseDir,
		"COLDSTEP_DETECT_LOG="+detectLog,
		"COLDSTEP_ALLOWED_DOMAINS="+domainsMerged,
		"COLDSTEP_ALLOWED_HOSTS="+hostsMerged,
		"COLDSTEP_ALLOWED_IPS="+ipsMerged,
		"COLDSTEP_IGNORED_IP_NETS="+ignoredMerged,
		"COLDSTEP_NO_DEFAULT_IGNORED_NETS="+boolString(cfg.NoDefaultIgnoredNets),
		"COLDSTEP_FEATURE_GATES="+cfg.FeatureGates,
		"COLDSTEP_DETECT_PROFILE="+strings.TrimSpace(cfg.DetectProfile),
		"CI_GUARD_MODE="+mode,
		"COLDSTEP_LOG_LEVEL="+cfg.LogLevel,
		"COLDSTEP_AGENT_STATUS="+agentStatus,
		"COLDSTEP_SIGNING_KEY="+cfg.SigningKey,
		"COLDSTEP_REPORT_JOB_SUMMARY="+boolString(cfg.ReportJobSummary),
	)

	cmd := exec.Command("sudo", "-E", binPath, "run")
	cmd.Env = childEnv
	cmd.Dir = actionPath
	stderr, err := os.OpenFile(stderrLog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer stderr.Close()
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	// stopAgent terminates the child if we return an error after a successful Start.
	stopAgent := func() {
		if p := cmd.Process; p != nil {
			_ = p.Signal(syscall.SIGTERM)
		}
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		stopAgent()
		return err
	}

	if cfg.SmokeTestEgress {
		_ = exec.Command("bash", "-c", "sleep 1; timeout 10 bash -c 'printf \"x\" >/dev/udp/1.1.1.1/53' >/dev/null 2>&1 || true; timeout 10 bash -c 'printf \"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n\" >/dev/tcp/example.com/80' >/dev/null 2>&1 || true").Start()
	}

	if cfg.FailOnError {
		seconds := clamp(cfg.ReadyTimeoutSeconds, 60, 2700)
		outcome := waitForReady(agentStatus, time.Duration(seconds)*time.Second, cmd.Process.Pid)
		if outcome != "ready" {
			stopAgent()
			return fmt.Errorf("coldstep agent did not report ready (%s)", outcome)
		}
		if err := os.WriteFile(readyMarker, []byte("true"), 0o644); err != nil {
			stopAgent()
			return err
		}
	}
	return nil
}

func runStop(cfg stopConfig) error {
	actionPath := getenvDefault("GITHUB_ACTION_PATH", mustGetwd())
	baseDir := getenvDefault("GITHUB_WORKSPACE", actionPath)
	pidFile := filepath.Join(actionPath, ".coldstep.pid")
	detectLog := filepath.Join(baseDir, ".coldstep-detect.md")
	agentStatus := filepath.Join(baseDir, ".coldstep-ready.json")
	readyMarker := filepath.Join(actionPath, ".coldstep.ready.ok")

	if cfg.FailOnError {
		if _, err := os.Stat(readyMarker); err != nil {
			ok, _ := readReady(agentStatus)
			if !ok {
				return errors.New("coldstep agent did not report ready (operational fail-on-error)")
			}
		}
	}

	if raw, err := os.ReadFile(pidFile); err == nil {
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err == nil && pid > 0 {
			if p, perr := os.FindProcess(pid); perr == nil {
				_ = p.Signal(syscall.SIGTERM)
			}
		}
	}
	time.Sleep(400 * time.Millisecond)

	body := ""
	if raw, err := os.ReadFile(detectLog); err == nil {
		body = string(raw)
	}

	if cfg.ReportJobSummary {
		if summaryPath := strings.TrimSpace(os.Getenv("GITHUB_STEP_SUMMARY")); summaryPath != "" && strings.TrimSpace(body) != "" {
			safe := sanitizeDigestForMarkdown(body)
			block := "## Coldstep - digest (exec / network / enforcement)\n\n" + safe
			if !strings.HasSuffix(block, "\n") {
				block += "\n"
			}
			f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "coldstep: open GITHUB_STEP_SUMMARY: %v\n", err)
			} else {
				if _, werr := f.WriteString(block); werr != nil {
					fmt.Fprintf(os.Stderr, "coldstep: write GITHUB_STEP_SUMMARY: %v\n", werr)
				}
				if cerr := f.Close(); cerr != nil {
					fmt.Fprintf(os.Stderr, "coldstep: close GITHUB_STEP_SUMMARY: %v\n", cerr)
				}
			}
		}
	}
	// Intentionally keep .coldstep-detect.md on disk: it is the agent's primary
	// digest artifact and several workflows (`Verify detect capabilities`,
	// `List workspace outputs`, `coldstep-report build-model`, etc.) read it
	// after Stop. The runner is ephemeral, so cleanup is not needed.

	if cfg.ReportPRSummary && strings.TrimSpace(body) != "" {
		token := strings.TrimSpace(cfg.GithubToken)
		if token == "" {
			token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
		}
		if token != "" {
			if err := postPRComment(token, sanitizeDigestForMarkdown(body)); err != nil {
				fmt.Fprintf(os.Stderr, "coldstep: report-pr-summary: %v\n", err)
			}
		}
	}
	return nil
}

func postPRComment(token, body string) error {
	repo := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
	if repo == "" {
		return nil
	}
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return nil
	}
	eventPath := strings.TrimSpace(os.Getenv("GITHUB_EVENT_PATH"))
	if eventPath == "" {
		return nil
	}
	raw, err := os.ReadFile(eventPath)
	if err != nil {
		return err
	}
	if len(raw) > maxGitHubEventJSONBytes {
		return fmt.Errorf("GITHUB_EVENT payload exceeds max (%d bytes)", maxGitHubEventJSONBytes)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	pr, ok := payload["pull_request"].(map[string]any)
	if !ok {
		return nil
	}
	number, ok := pr["number"].(float64)
	if !ok {
		return nil
	}
	comment := map[string]string{"body": "## Coldstep digest\n\n" + truncate(body, 65000)}
	b, err := json.Marshal(comment)
	if err != nil {
		return err
	}
	urlStr := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%d/comments", parts[0], parts[1], int(number))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, urlStr, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpNotifyClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("github comment failed: %s", resp.Status)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHTTPResponseDrain))
	return nil
}

// classifyReadyStatus mirrors composite TypeScript readiness parsing for
// .coldstep-ready.json (including ok field absence vs false).
func classifyReadyStatus(raw []byte) (ready, explicitFail, malformed, incomplete bool) {
	if len(raw) > maxReadyStatusJSONBytes {
		return false, false, true, false
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return false, false, true, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return false, false, true, false
	}
	val, hasOk := m["ok"]
	if !hasOk {
		return false, false, false, true
	}
	var okBool bool
	if err := json.Unmarshal(val, &okBool); err != nil {
		return false, true, false, false
	}
	if okBool {
		return true, false, false, false
	}
	return false, true, false, false
}

func waitForReady(statusPath string, timeout time.Duration, pid int) string {
	deadline := time.Now().Add(timeout)
	var malformedSince *time.Time
	const malformedBudget = 45 * time.Second

	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(statusPath)
		if err != nil {
			malformedSince = nil
		} else {
			ok, explicitFail, malformed, incomplete := classifyReadyStatus(raw)
			switch {
			case ok:
				return "ready"
			case explicitFail:
				return "explicit_not_ready"
			case malformed:
				if malformedSince == nil {
					t := time.Now()
					malformedSince = &t
				}
				if time.Since(*malformedSince) >= malformedBudget {
					return "malformed_status"
				}
			case incomplete:
				malformedSince = nil
			}
		}

		if !pidAlive(pid) {
			return "child_exit"
		}
		time.Sleep(150 * time.Millisecond)
	}
	return "timeout"
}

func readReady(path string) (ok bool, known bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	ready, explicitFail, _, incomplete := classifyReadyStatus(raw)
	switch {
	case ready:
		return true, true
	case explicitFail:
		return false, true
	case incomplete:
		return false, false
	default:
		return false, false
	}
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil
}

func sanitizeDigestForMarkdown(body string) string {
	if body == "" {
		return body
	}
	body = strings.TrimPrefix(body, "\uFEFF")
	body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(body, "\n")
	backticks := regexp.MustCompile("`{3,}")
	tildes := regexp.MustCompile("~{3,}")
	for i := range lines {
		line := lines[i]
		if len(line) > 4096 {
			// Clip at a valid UTF-8 boundary to avoid producing invalid byte sequences.
			end := 4096
			for end > 0 && !utf8.ValidString(line[:end]) {
				end--
			}
			line = line[:end] + " ...(truncated)"
		}
		line = strings.ReplaceAll(line, "\\", "\\\\")
		line = strings.ReplaceAll(line, "<", "&lt;")
		line = backticks.ReplaceAllStringFunc(line, func(m string) string {
			return strings.Repeat("\\`", len(m))
		})
		line = tildes.ReplaceAllStringFunc(line, func(m string) string {
			return strings.Repeat("\\~", len(m))
		})
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	end := max
	for end > 0 && !utf8.ValidString(s[:end]) {
		end--
	}
	return s[:end] + "\n\n_(truncated)_\n"
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func getenvDefault(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v
}

func runtimeOS() string {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("RUNNER_OS"))); v != "" {
		return v
	}
	return strings.ToLower(runtime.GOOS)
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func fatal(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
