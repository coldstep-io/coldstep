//go:build integration && linux && !windows

// Root-requiring BPF tests: Linux only (never Windows). CI ubuntu-latest is the intended runner.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coldstep-io/coldstep/internal/config"
	"golang.org/x/sys/unix"
)

// utsFieldString returns a NUL-terminated field from unix.Utsname.
func utsFieldString(b [65]byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

// skipIfUnsupportedSyscallBPFKernel skips tests that require trace_connect raw_tp/sys_enter BPF to load.
// WSL/Microsoft-style Linux kernels often reject the same CO-RE program that loads on GitHub ubuntu-latest;
// CI remains authoritative (see README.md).
// Set COLDSTEP_FORCE_SYSCALL_BPF_TESTS=1 to run these tests anyway.
func skipIfUnsupportedSyscallBPFKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("COLDSTEP_FORCE_SYSCALL_BPF_TESTS") == "1" {
		return
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return
	}
	rel := strings.ToLower(utsFieldString(uts.Release))
	if strings.Contains(rel, "-microsoft-") {
		t.Skip("WSL/Microsoft-style kernel: syscall egress BPF parity not assumed; use coldstep-ci integration on ubuntu-latest (or COLDSTEP_FORCE_SYSCALL_BPF_TESTS=1)")
	}
}

func TestRun_DetectWritesSummary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	dir := t.TempDir()
	summary := filepath.Join(dir, "summary.md")
	if err := os.WriteFile(summary, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	detectLog := filepath.Join(dir, ".coldstep-detect.md")
	if err := os.WriteFile(detectLog, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(300 * time.Millisecond)

	script := filepath.Join(dir, "noop.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(script).Run(); err != nil {
		t.Fatal(err)
	}

	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	b, err := os.ReadFile(detectLog)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("## Coldstep")) || !bytes.Contains(b, []byte("| **exec** |")) {
		t.Fatalf("expected Coldstep table with exec row, got:\n%s", string(b))
	}
}

func TestRun_TCPConnectLogged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	dir := t.TempDir()
	detect := filepath.Join(dir, "detect.md")
	if err := os.WriteFile(detect, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("COLDSTEP_DETECT_LOG", detect)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(400 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second)
	if err != nil {
		t.Fatalf("dial 1.1.1.1:443: %v", err)
	}
	_ = conn.Close()

	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	b, err := os.ReadFile(detect)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("**tcp**")) {
		t.Fatalf("expected **tcp** in detect log, got:\n%s", string(b))
	}
	if !bytes.Contains(b, []byte("1.1.1.1")) && !bytes.Contains(b, []byte(":443`")) {
		t.Fatalf("expected TCP remote with 1.1.1.1:443 in detect log, got:\n%s", string(b))
	}
	if !bytes.Contains(b, []byte("monitor")) {
		t.Fatalf("expected policy monitor in detect log, got:\n%s", string(b))
	}
}

func TestRun_ExecJSONLIncludesExePath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	dir := t.TempDir()
	summary := filepath.Join(dir, "summary.md")
	if err := os.WriteFile(summary, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, ".coldstep-events.jsonl")

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	t.Setenv("COLDSTEP_EVENTS_LOG", events)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(350 * time.Millisecond)

	script := filepath.Join(dir, "noop2.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(script).Run(); err != nil {
		t.Fatal(err)
	}

	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"type":"exec"`)) {
			continue
		}
		if bytes.Contains(line, []byte(`"exe":"/`)) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected exec JSONL with non-empty absolute exe path:\n%s", b)
	}
}

func TestRun_ProcForkJSONLWhenFeatureGate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	dir := t.TempDir()
	summary := filepath.Join(dir, "summary.md")
	if err := os.WriteFile(summary, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, "events.jsonl")
	detect := filepath.Join(dir, "detect.md")

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	t.Setenv("COLDSTEP_EVENTS_LOG", events)
	t.Setenv("COLDSTEP_DETECT_LOG", detect)
	t.Setenv("COLDSTEP_FEATURE_GATES", "proc_tree=1")

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(400 * time.Millisecond)

	if err := exec.Command("bash", "-c", "true").Run(); err != nil {
		t.Fatal(err)
	}

	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"type":"proc_fork"`)) {
		t.Fatalf("expected proc_fork in jsonl:\n%s", string(b))
	}
}

func TestRun_UDPSendtoLoggedJSONL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed:", err)
	}
	dir := t.TempDir()
	detect := filepath.Join(dir, "detect.md")
	events := filepath.Join(dir, ".coldstep-events.jsonl")
	if err := os.WriteFile(detect, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("COLDSTEP_DETECT_LOG", detect)
	t.Setenv("COLDSTEP_EVENTS_LOG", events)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(450 * time.Millisecond)

	// nc -u may still use UDP connect(); SOCK_DGRAM sendto avoids connect so sys_enter sendto fires.
	cmd := exec.Command("python3", "-c", "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'x',('1.1.1.1',53));s.close()")
	if err := cmd.Run(); err != nil {
		t.Logf("udp probe (non-fatal): %v", err)
	}

	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"type":"udp"`)) {
		t.Fatalf("expected at least one udp JSONL line, got:\n%s", b)
	}
	if !bytes.Contains(b, []byte(`"dport":53`)) {
		t.Fatalf("expected udp JSONL with dport 53, got:\n%s", b)
	}
}

func TestRun_HTTPSendtoPort80JSONL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed:", err)
	}
	dir := t.TempDir()
	detect := filepath.Join(dir, "detect.md")
	events := filepath.Join(dir, ".coldstep-events.jsonl")
	probe := filepath.Join(dir, "http_sendto_probe.py")
	if err := os.WriteFile(detect, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("COLDSTEP_DETECT_LOG", detect)
	t.Setenv("COLDSTEP_EVENTS_LOG", events)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(450 * time.Millisecond)

	// BPF http path requires sys_sendto with non-NULL sockaddr (trace_connect.bpf.c); use sendto after TCP connect.
	py := `import socket
addr = ("example.com", 80)
req = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(addr)
s.sendto(req, 0, addr)
s.close()
`
	if err := os.WriteFile(probe, []byte(py), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", probe)
	if err := cmd.Run(); err != nil {
		t.Logf("http probe (non-fatal): %v", err)
	}

	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"type":"http"`)) {
		t.Fatalf("expected at least one http JSONL line, got:\n%s", b)
	}
	if !bytes.Contains(b, []byte(`"dport":80`)) {
		t.Fatalf("expected http JSONL with dport 80, got:\n%s", b)
	}
}

func TestRun_TLSClientHelloSNIJSONL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed:", err)
	}
	dir := t.TempDir()
	detect := filepath.Join(dir, "detect.md")
	events := filepath.Join(dir, ".coldstep-events.jsonl")
	summary := filepath.Join(dir, "summary.md")
	if err := os.WriteFile(detect, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(summary, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	t.Setenv("COLDSTEP_DETECT_LOG", detect)
	t.Setenv("COLDSTEP_EVENTS_LOG", events)
	t.Setenv("COLDSTEP_FEATURE_GATES", "tls_sni=1")

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(500 * time.Millisecond)

	// --http1.1 prevents curl from using QUIC/HTTP3; with QUIC the TLS ClientHello is
	// embedded inside QUIC Initial packets (UDP) rather than a raw TCP write/sendto, which
	// bypasses the write(2)/sendto(2) BPF sniff. HTTP/1.1 forces TLS over TCP.
	cmd := exec.Command("curl", "-fsS", "-4", "--http1.1", "--max-time", "10", "https://example.com", "-o", "/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("curl https://example.com: %v\n%s", err, out)
	}

	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"type":"tls"`)) {
		t.Fatalf("expected tls JSONL line, got:\n%s", string(b))
	}
	if !bytes.Contains(b, []byte(`"sni":"example.com"`)) {
		t.Fatalf("expected tls JSONL with sni example.com, got:\n%s", string(b))
	}
}

func TestRun_FSEventJSONLWhenFeatureGate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	if _, err := exec.LookPath("touch"); err != nil {
		t.Skip("touch not found:", err)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not found:", err)
	}

	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	detect := filepath.Join(dir, "detect.md")
	summary := filepath.Join(dir, "summary.md")
	if err := os.WriteFile(detect, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(summary, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	t.Setenv("COLDSTEP_DETECT_LOG", detect)
	t.Setenv("COLDSTEP_EVENTS_LOG", eventsPath)
	t.Setenv("COLDSTEP_FEATURE_GATES", "fs_events=1")

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(500 * time.Millisecond)

	tmpFile := filepath.Join(dir, "ns-test-create.txt")
	cmd := exec.Command("bash", "-c", "touch "+tmpFile+" && rm "+tmpFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("probe command: %v\n%s", err, out)
	}

	time.Sleep(300 * time.Millisecond)
	cancel()
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	data, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}

	var foundFS bool
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, `"type":"fs_event"`) {
			foundFS = true
			break
		}
	}
	if !foundFS {
		t.Fatalf("expected at least one fs_event JSONL line; got:\n%s", string(data))
	}
}

// bpfMapGetNextID is BPF_MAP_GET_NEXT_ID from Linux UAPI linux/bpf.h — bpftool map list issues bpf(BPF_MAP_GET_NEXT_ID, …).
const bpfMapGetNextID = 12

// validateBPFAuditJSONL returns nil when JSONL satisfies bpf_audit field assertions (non-empty comm;
// when requireBPFMapGetNextID is true, at least one record must have cmd==BPF_MAP_GET_NEXT_ID).
func validateBPFAuditJSONL(data []byte, requireBPFMapGetNextID bool) error {
	var sawAudit bool
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev struct {
			Type string `json:"type"`
			Cmd  uint32 `json:"cmd"`
			Comm string `json:"comm"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Type != "bpf_audit" {
			continue
		}
		sawAudit = true
		if strings.TrimSpace(ev.Comm) == "" {
			return fmt.Errorf("bpf_audit line has empty comm: %s", line)
		}
		if !requireBPFMapGetNextID {
			return nil
		}
		if ev.Cmd == bpfMapGetNextID {
			return nil
		}
	}
	if !sawAudit {
		return fmt.Errorf("no bpf_audit JSONL record")
	}
	if requireBPFMapGetNextID {
		return fmt.Errorf("no bpf_audit with cmd=%d (BPF_MAP_GET_NEXT_ID)", bpfMapGetNextID)
	}
	return nil
}

func requireValidBPFAuditJSONL(t *testing.T, data []byte, requireBPFMapGetNextID bool) {
	t.Helper()
	if err := validateBPFAuditJSONL(data, requireBPFMapGetNextID); err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
}

func TestRun_BPFAuditLoggedJSONL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")
	detect := filepath.Join(dir, "detect.md")

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("COLDSTEP_EVENTS_LOG", events)
	t.Setenv("COLDSTEP_DETECT_LOG", detect)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	// Detect mode writes .coldstep-ready.json before the bpf-audit raw_tp attaches; a fixed sleep can run
	// bpftool before the audit ring reader starts. Poll JSONL until bpf_audit appears or timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	_, bpftoolErr := exec.LookPath("bpftool")
	hasBpftool := bpftoolErr == nil

	deadline := time.Now().Add(14 * time.Second)
	validated := false
	for time.Now().Before(deadline) {
		if hasBpftool {
			// bpftool map list triggers BPF_MAP_GET_NEXT_ID (12).
			_ = exec.Command("bpftool", "map", "list").Run()
		}
		time.Sleep(150 * time.Millisecond)
		b, rerr := os.ReadFile(events)
		if rerr != nil {
			continue
		}
		if !bytes.Contains(b, []byte(`"type":"bpf_audit"`)) {
			continue
		}
		if validateBPFAuditJSONL(b, hasBpftool) == nil {
			validated = true
			break
		}
	}

	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	if validated {
		return
	}

	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"type":"bpf_audit"`)) {
		if !hasBpftool {
			t.Skip("no bpf_audit events and no bpftool to trigger them")
		}
		t.Fatalf("expected bpf_audit in jsonl:\n%s", string(b))
	}
	requireValidBPFAuditJSONL(t, b, hasBpftool)
}
