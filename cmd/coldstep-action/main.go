// Command coldstep-action is the entry-point binary invoked by the GitHub
// composite action wrapper.
//
// It owns two subcommands wired to the composite's pre/post phases:
//
//   - start: stages the agent binary (either prebuilt via --release-path or
//     compiled by scripts/build-agent-linux.sh), resolves the merged
//     allow policy (incl. !CIDR ignores) from inline + file inputs, then re-execs
//     the agent under `sudo -E` so it can attach BPF programs. When
//     --fail-on-error is set, start blocks until the agent writes a healthy
//     .coldstep-ready.json (or returns an explicit not-ready / timeout /
//     child-exit verdict).
//
//   - stop: SIGTERMs the agent via its pidfile, drains the on-disk digest,
//     and emits the configured surfaces — GitHub Actions job summary, PR
//     comment via the GitHub REST API, or both — depending on --report.
//
// All filesystem and subprocess inputs come from controlled sources
// (GITHUB_ACTION_PATH / GITHUB_WORKSPACE / GITHUB_EVENT_PATH /
// GITHUB_STEP_SUMMARY / GITHUB_REPOSITORY); see the gosec exclusions in
// .github/workflows/coldstep-ci-runner.yml for the rationale.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// githubRepoPartRE validates org and repo name segments from GITHUB_REPOSITORY.
// GitHub allows alphanumeric, hyphens, dots, and underscores in org/repo names.
var githubRepoPartRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Markdown fence runs escaped per-line by sanitizeDigestForMarkdown. Compiled
// once at package scope — the function runs over every digest line, so a
// per-call MustCompile was needless work on the post-step hot path.
var (
	markdownBacktickRunRE = regexp.MustCompile("`{3,}")
	markdownTildeRunRE    = regexp.MustCompile("~{3,}")
)

const (
	maxReadyStatusJSONBytes = 512 << 10 // agent status should be tiny; bound disk/memory abuse
	maxGitHubEventJSONBytes = 8 << 20   // $GITHUB_EVENT_PATH payload cap before full json.Unmarshal
	maxHTTPResponseDrain    = 256 << 10 // discard bodies after POST so connections can reuse
)

type startConfig struct {
	Mode                 string
	Allow                string
	AllowFile            string
	NoDefaultIgnoredNets bool
	LogLevel             string
	DetectProfile        string
	ReleasePath          string
	FailOnError          bool
	ReadyTimeoutSeconds  int
	SmokeTestEgress      bool
	IoUringDisable       bool
	SigningKey           string
	Report               string
}

type stopConfig struct {
	FailOnError bool
	Report      string
	GithubToken string
	// Strict enables the anti-blindness required-event-type gate (replaces the
	// coldstep-report assert-integrity step): a non-zero exit when expected
	// JSONL event types are missing. DetectProfile selects the required set.
	Strict        bool
	DetectProfile string
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
	case "diff":
		fatal(runDiff(os.Args[2:]))
	case "assert-integrity":
		fatal(runAssertIntegrity(os.Args[2:]))
	default:
		fatal(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}

func parseStartFlags(args []string) (startConfig, error) {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := startConfig{}
	fs.StringVar(&cfg.Mode, "mode", "detect", "")
	fs.StringVar(&cfg.Allow, "allow", "", "")
	fs.StringVar(&cfg.AllowFile, "allow-file", "", "")
	fs.BoolVar(&cfg.NoDefaultIgnoredNets, "no-default-ignored-nets", false, "")
	fs.StringVar(&cfg.LogLevel, "log-level", "info", "")
	fs.StringVar(&cfg.DetectProfile, "detect-profile", "standard", "")
	fs.StringVar(&cfg.ReleasePath, "release-path", "", "")
	fs.BoolVar(&cfg.FailOnError, "fail-on-error", false, "")
	fs.IntVar(&cfg.ReadyTimeoutSeconds, "ready-timeout-seconds", 1500, "")
	fs.BoolVar(&cfg.SmokeTestEgress, "smoke-test-egress", false, "")
	fs.BoolVar(&cfg.IoUringDisable, "io-uring-disable", true, "")
	fs.StringVar(&cfg.SigningKey, "signing-key", "", "")
	fs.StringVar(&cfg.Report, "report", "job-summary", "")
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
	fs.StringVar(&cfg.Report, "report", "job-summary", "")
	fs.StringVar(&cfg.GithubToken, "github-token", "", "")
	fs.BoolVar(&cfg.Strict, "strict", false, "")
	fs.StringVar(&cfg.DetectProfile, "detect-profile", getenvDefault("COLDSTEP_DETECT_PROFILE", ""), "")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// digestIntegrityMarker is the H11 tamper-evidence HTML comment appended to
// `.coldstep-detect.md`. It returns the empty string for an empty / whitespace
// body so the marker is only emitted when there is a real digest to protect.
// The leading newline guarantees the comment lands on its own line even when
// the agent's digest does not end in `\n`; the trailing newline keeps the
// file POSIX-clean.
func digestIntegrityMarker(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(body))
	return fmt.Sprintf("\n<!-- coldstep-digest-sha256: %s -->\n", hex.EncodeToString(sum[:]))
}

// parseReportFlags maps the unified `report` input to per-surface booleans
// for runStop. Defaults to job-summary when the input is empty.
func parseReportFlags(report string) (jobSummary, prSummary bool) {
	switch strings.ToLower(strings.TrimSpace(report)) {
	case "pr-comment":
		return false, true
	case "both":
		return true, true
	case "none":
		return false, false
	default: // "" or "job-summary"
		return true, false
	}
}

// normalizeCompositeMode maps user-facing mode names to CI_GUARD_MODE (detect or defend).
func normalizeCompositeMode(raw string) (string, error) {
	mode := strings.TrimSpace(strings.ToLower(raw))
	if mode == "" {
		mode = "detect"
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
	// Bug #9: pidFile lives under $GITHUB_WORKSPACE (baseDir) so the Go
	// entrypoints, the legacy TS entrypoints (src/start.ts and src/stop.ts),
	// and external workflow steps all agree on where to find the agent's
	// PID. Mixed-entrypoint use otherwise no-ops the stop SIGTERM, leaving
	// the agent to be SIGKILLed on runner teardown with no digest flush.
	pidFile := filepath.Join(baseDir, ".coldstep.pid")
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
		if out, err := exec.Command("sudo", "sysctl", "-w", "kernel.io_uring_disabled=2").CombinedOutput(); err != nil {
			fmt.Printf("::warning::io-uring-disable: sysctl kernel.io_uring_disabled=2 failed (%v): %s; io_uring-based syscall bypasses may not be blocked on this runner\n", err, strings.TrimSpace(string(out)))
		}
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

	// Prefer env var for signing-key so it never appears in /proc/<pid>/cmdline.
	// --signing-key flag still works for direct binary invocation.
	if cfg.SigningKey == "" {
		cfg.SigningKey = os.Getenv("COLDSTEP_SIGNING_KEY")
	}

	mode, err := normalizeCompositeMode(cfg.Mode)
	if err != nil {
		return err
	}

	allowMerged, err := mergeInlineAndAllowlistFiles(baseDir, cfg.Allow, cfg.AllowFile)
	if err != nil {
		return err
	}
	allow := classifyAllowTokens(splitAllowInlineTokens(allowMerged))

	// Ignored nets come solely from `!CIDR` entries in allow / allow-file —
	// classifyAllowTokens already routed those into allow.ignoredNets above.
	// The removed ignored-nets / ignored-nets-file / bootstrap-allowlist inputs
	// are warned about (not silently dropped) when a consumer still sets them.
	warnRemovedAllowlistInputs()

	if mode == "defend" {
		if err := rejectDefendWildcards(allow); err != nil {
			return err
		}
	}

	detectProfile := strings.ToLower(strings.TrimSpace(cfg.DetectProfile))
	featureGates := ""
	if detectProfile == "enhanced" {
		featureGates = "proc_tree=1,tls_sni=1,fs_events=1"
	}

	childEnv := os.Environ()
	childEnv = append(childEnv,
		"GITHUB_WORKSPACE="+baseDir,
		"COLDSTEP_DETECT_LOG="+detectLog,
		"COLDSTEP_ALLOWED_DOMAINS="+strings.Join(allow.domains, ","),
		"COLDSTEP_ALLOWED_HOSTS="+strings.Join(allow.hosts, ","),
		"COLDSTEP_ALLOWED_IPS="+strings.Join(allow.ips, ","),
		"COLDSTEP_IGNORED_IP_NETS="+strings.Join(allow.ignoredNets, ","),
		"COLDSTEP_NO_DEFAULT_IGNORED_NETS="+boolString(cfg.NoDefaultIgnoredNets),
		"COLDSTEP_FEATURE_GATES="+featureGates,
		"COLDSTEP_DETECT_PROFILE="+detectProfile,
		"CI_GUARD_MODE="+mode,
		"COLDSTEP_LOG_LEVEL="+cfg.LogLevel,
		"COLDSTEP_AGENT_STATUS="+agentStatus,
		"COLDSTEP_SIGNING_KEY="+cfg.SigningKey,
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
	// Bug #15: cmd.Process.Pid is the sudo PID, not the agent's. On most
	// PAM stacks sudo forks before exec'ing the agent — using sudoPid for
	// pidAlive polling masks an agent crash (sudo can stay alive after its
	// child dies), and sending SIGTERM to sudo does not propagate. Walk the
	// /proc descendant tree to find the agent, falling back to sudoPid only
	// if discovery times out (so we never end up with a zero PID).
	sudoPid := cmd.Process.Pid
	agentPid := findAgentPID(sudoPid, 2*time.Second)
	// stopAgent terminates the agent (not sudo) if we return an error after
	// a successful Start.
	stopAgent := func() {
		if agentPid > 0 {
			if p, perr := os.FindProcess(agentPid); perr == nil {
				_ = p.Signal(syscall.SIGTERM)
			}
		}
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(agentPid)), 0o644); err != nil {
		stopAgent()
		return err
	}

	if cfg.SmokeTestEgress {
		_ = exec.Command("bash", "-c", "sleep 1; timeout 10 bash -c 'printf \"x\" >/dev/udp/1.1.1.1/53' >/dev/null 2>&1 || true; timeout 10 bash -c 'printf \"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n\" >/dev/tcp/example.com/80' >/dev/null 2>&1 || true").Start()
	}

	if cfg.FailOnError {
		seconds := clamp(cfg.ReadyTimeoutSeconds, 60, 2700)
		outcome := waitForReady(agentStatus, time.Duration(seconds)*time.Second, agentPid)
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
	// Bug #9: must match runStart's pidFile path so mixed-entrypoint runs
	// (Go start + TS stop, or vice versa) read the same file.
	pidFile := filepath.Join(baseDir, ".coldstep.pid")
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
			// Poll for the agent to exit instead of using a fixed sleep. The
			// previous 400ms hard sleep was shorter than the agent's actual
			// shutdown drain on defend-mode runs (BPF ringbuf flush + digest
			// write), producing truncated `.coldstep-detect.md` files. The 10s
			// upper bound matches the defend-mode drain budget so we wait long
			// enough on slow runners without hanging forever on a stuck agent.
			waitForAgentExit(pid, 10*time.Second, 100*time.Millisecond)
		}
	}

	// Report-binary elimination (Phase 1): render the pure-markdown detailed
	// report from the JSONL source of truth and write it to .coldstep-report.md
	// for artifact upload. Best-effort — never fails the job; the agent's
	// .coldstep-detect.md remains the job-summary source until later phases swap
	// it for the markdown generator's simple report.
	reportAgg := writeDetailedMarkdownReport(baseDir)

	body := ""
	if raw, err := os.ReadFile(detectLog); err == nil {
		body = string(raw)
	}

	// H11: tamper-evidence hash of the digest file. The SHA-256 covers the
	// agent-written digest content (everything currently in `body`); we then
	// append the marker comment to the on-disk file and to `body` so
	// downstream surfaces (Job Summary, PR comment) carry the same value.
	// Best-effort: a failure here logs to stderr and continues — the digest
	// remains readable without the integrity comment. JSONL signing remains
	// the cryptographically strong guarantee; this is a lightweight surface
	// for unsigned runs.
	if marker := digestIntegrityMarker(body); marker != "" {
		if f, ferr := os.OpenFile(detectLog, os.O_APPEND|os.O_WRONLY, 0o644); ferr != nil {
			fmt.Fprintf(os.Stderr, "coldstep: open detect log for hash marker: %v\n", ferr)
		} else {
			if _, werr := f.WriteString(marker); werr != nil {
				fmt.Fprintf(os.Stderr, "coldstep: write hash marker: %v\n", werr)
			}
			if cerr := f.Close(); cerr != nil {
				fmt.Fprintf(os.Stderr, "coldstep: close detect log: %v\n", cerr)
			}
		}
		body += marker
	}

	reportJobSummary, reportPRSummary := parseReportFlags(cfg.Report)

	if reportJobSummary {
		// Job summary now comes from the pure-markdown generator's simple report
		// (rendered from the JSONL source of truth), not the agent's
		// .coldstep-detect.md digest. Fall back to the legacy digest body only
		// when no event stream was parsed (e.g. agent never started).
		block := ""
		if reportAgg != nil {
			block = reportAgg.RenderSimple()
		} else if strings.TrimSpace(body) != "" {
			block = "## Coldstep - digest (exec / network / defend)\n\n" + sanitizeDigestForMarkdown(body)
		}
		if summaryPath := strings.TrimSpace(os.Getenv("GITHUB_STEP_SUMMARY")); summaryPath != "" && strings.TrimSpace(block) != "" {
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

	if reportPRSummary && strings.TrimSpace(body) != "" {
		token := strings.TrimSpace(cfg.GithubToken)
		if token == "" {
			token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
		}
		if token != "" {
			if err := postPRComment(token, sanitizeDigestForMarkdown(body)); err != nil {
				fmt.Fprintf(os.Stderr, "coldstep: report pr-comment: %v\n", err)
			}
		}
	}

	// Anti-blindness gate (--strict): replaces coldstep-report assert-integrity.
	// Run last so the report is still posted/attached before a missing-type
	// failure aborts the step.
	if cfg.Strict {
		if reportAgg == nil {
			return errors.New("strict: no .coldstep-events.jsonl to evaluate required event types")
		}
		if missing := reportAgg.MissingRequiredTypes(cfg.DetectProfile); len(missing) > 0 {
			return fmt.Errorf("strict: missing required event type(s): %s", strings.Join(missing, ", "))
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
	if len(parts) != 2 || !githubRepoPartRE.MatchString(parts[0]) || !githubRepoPartRE.MatchString(parts[1]) {
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
	if bytes.Equal(val, []byte("null")) {
		return false, false, true, false // null ok field is malformed, not explicit-fail
	}
	var okBool bool
	if err := json.Unmarshal(val, &okBool); err != nil {
		return false, false, true, false // malformed, not explicit-fail
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
		if err == nil {
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
		} else {
			// Read errors are transient I/O (status file mid-write,
			// briefly missing); they are not a parseable-but-malformed
			// status, so they must not advance the malformed budget.
			// Reset the window and fall through to the liveness check.
			malformedSince = nil
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

// waitForAgentExit polls pidAlive at the given tick until the agent process
// is gone or the timeout elapses. Emits one stderr line either way so logs
// distinguish a clean drain from a hung agent. Returns true when the agent
// exited within the budget.
func waitForAgentExit(pid int, timeout, tick time.Duration) bool {
	if pid <= 0 || timeout <= 0 || tick <= 0 {
		return false
	}
	start := time.Now()
	deadline := start.Add(timeout)
	for {
		if !pidAlive(pid) {
			fmt.Fprintf(os.Stderr, "coldstep: agent pid=%d exited cleanly after %s\n", pid, time.Since(start).Round(time.Millisecond))
			return true
		}
		if !time.Now().Before(deadline) {
			fmt.Fprintf(os.Stderr, "coldstep: agent pid=%d still alive after %s; proceeding with digest read anyway\n", pid, timeout)
			return false
		}
		time.Sleep(tick)
	}
}

func sanitizeDigestForMarkdown(body string) string {
	if body == "" {
		return body
	}
	body = strings.TrimPrefix(body, "\uFEFF")
	body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(body, "\n")
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
		line = markdownBacktickRunRE.ReplaceAllStringFunc(line, func(m string) string {
			return strings.Repeat("\\`", len(m))
		})
		line = markdownTildeRunRE.ReplaceAllStringFunc(line, func(m string) string {
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
