//go:build integration && linux && !windows

// Root-requiring BPF tests: Linux only (never Windows). CI ubuntu-latest is the intended runner.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
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
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}

	// The agent writes data only (JSONL); report rendering moved to userspace
	// (coldstep-action). Assert the exec event landed in the event stream.
	b, err := os.ReadFile(filepath.Join(dir, ".coldstep-events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"type":"exec"`)) {
		t.Fatalf("expected an exec event in the JSONL stream, got:\n%s", string(b))
	}
}

func TestRun_TCPConnectLogged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	dir := t.TempDir()

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")

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
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}

	// Agent writes data only — assert the tcp event in the JSONL stream.
	b, err := os.ReadFile(filepath.Join(dir, ".coldstep-events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"type":"tcp"`)) {
		t.Fatalf("expected a tcp event in the JSONL stream, got:\n%s", string(b))
	}
	if !bytes.Contains(b, []byte("1.1.1.1")) {
		t.Fatalf("expected 1.1.1.1 in the JSONL stream, got:\n%s", string(b))
	}
}

func TestRun_DefendModeBlockedConnectEmitsDenyJSONL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	dir := t.TempDir()
	detect := filepath.Join(dir, "detect.md")
	events := filepath.Join(dir, ".coldstep-events.jsonl")
	summary := filepath.Join(dir, "summary.md")
	ready := filepath.Join(dir, ".coldstep-ready.json")
	if err := os.WriteFile(detect, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(summary, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("CI_GUARD_MODE", "defend")
	t.Setenv("COLDSTEP_ALLOWED_DOMAINS", "localhost")
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "127.0.0.1/32")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	t.Setenv("COLDSTEP_DETECT_LOG", detect)
	t.Setenv("COLDSTEP_EVENTS_LOG", events)
	t.Setenv("COLDSTEP_AGENT_STATUS", ready)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	// Wait for readiness — with the fix, this flips true only after the deny
	// reader goroutine is alive, so a connect issued right after won't race the reader.
	readyDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(readyDeadline) {
		b, rerr := os.ReadFile(ready)
		if rerr == nil && bytes.Contains(b, []byte(`"ok":true`)) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 8.8.8.8 is outside the default ignored RFC1918 ranges (10/8, 172.16/12) and outside
	// the 127.0.0.1/32 allowlist, so the cgroup defend hook should block this connect
	// with EPERM and emit a deny event on the deny_events ringbuf.
	if conn, derr := net.DialTimeout("tcp", "8.8.8.8:53", 1*time.Second); derr == nil {
		_ = conn.Close()
	}

	// Poll JSONL for a deny row (drain margin separate from fix 3's stop.ts pid-exit wait).
	denyDeadline := time.Now().Add(3 * time.Second)
	var data []byte
	sawDeny := false
	for time.Now().Before(denyDeadline) {
		data, _ = os.ReadFile(events)
		if bytes.Contains(data, []byte(`"type":"deny"`)) {
			sawDeny = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	if rerr := <-errCh; rerr != nil && !errors.Is(rerr, context.Canceled) {
		t.Fatalf("Run: %v", rerr)
	}

	if !sawDeny {
		// Re-read after cancel in case the agent flushed on shutdown.
		data, _ = os.ReadFile(events)
		if !bytes.Contains(data, []byte(`"type":"deny"`)) {
			t.Fatalf("expected a \"type\":\"deny\" JSONL row within 3s after blocked connect; got:\n%s", string(data))
		}
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
	if err != nil && !errors.Is(err, context.Canceled) {
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

// TestRun_ExecKernelTruthIdentity verifies Sub-project C (ORDER 5): the exec
// JSONL carries the in-kernel exe_inode, and an atomic replace of the binary at
// the same path produces a different inode — the spoof-resistant identity that
// comm / exe path alone cannot provide. Uses a real ELF binary (not a shebang
// script) so mm->exe_file resolves to the exec'd file itself, and rename(2) (not
// truncate-in-place) so the replacement gets a fresh inode.
func TestRun_ExecKernelTruthIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	srcA, srcB := "/usr/bin/true", "/usr/bin/false"
	for _, p := range []string{srcA, srcB} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("%s not present: %v", p, err)
		}
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

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()
	time.Sleep(350 * time.Millisecond)

	bin := filepath.Join(dir, "idbin")
	cp := func(src, dst string) {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Exec #1: idbin is a copy of /usr/bin/true.
	cp(srcA, bin)
	if err := exec.Command(bin).Run(); err != nil {
		t.Fatalf("exec idbin (true): %v", err)
	}

	// Atomic-replace idbin with /usr/bin/false (new inode via rename), exec #2.
	tmp := filepath.Join(dir, "idbin.next")
	cp(srcB, tmp)
	if err := os.Rename(tmp, bin); err != nil {
		t.Fatal(err)
	}
	_ = exec.Command(bin).Run() // /usr/bin/false exits 1; we only need the exec event

	cancel()
	if err = <-errCh; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}

	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	var inodes []uint64
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"type":"exec"`)) || !bytes.Contains(line, []byte(`/idbin"`)) {
			continue
		}
		var ev struct {
			Exe      string `json:"exe"`
			ExeInode uint64 `json:"exe_inode"`
		}
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("unmarshal exec line: %v\n%s", err, line)
		}
		if ev.ExeInode == 0 {
			t.Fatalf("exec for %s has zero exe_inode (kernel-truth walk failed):\n%s", ev.Exe, line)
		}
		inodes = append(inodes, ev.ExeInode)
	}
	if len(inodes) < 2 {
		t.Fatalf("expected >=2 exec events for /idbin with inode, got %d:\n%s", len(inodes), b)
	}
	if inodes[0] == inodes[len(inodes)-1] {
		t.Fatalf("exe_inode did not change after atomic binary replace: %d == %d",
			inodes[0], inodes[len(inodes)-1])
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
	if err != nil && !errors.Is(err, context.Canceled) {
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
	if err != nil && !errors.Is(err, context.Canceled) {
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
	if err != nil && !errors.Is(err, context.Canceled) {
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

// TestRun_HTTPWritePort80JSONL covers BG-04: HTTP/1 plaintext on dport 80 emitted via
// write(2)/pwrite64(2) after a TCP connect must produce a "type":"http" JSONL row, same as
// the sendto(2) arm. Mirrors TestRun_HTTPSendtoPort80JSONL but uses write/os.write and
// pwrite to exercise the write/pwrite* dispatch arm in trace_connect.bpf.c.
func TestRun_HTTPWritePort80JSONL(t *testing.T) {
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
	probe := filepath.Join(dir, "http_write_probe.py")
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

	// Issue both write() and pwrite() so the test asserts the new write/pwrite* sniff arm.
	// socket.send() invokes sendto(2) under the hood; os.write(fd, ...) is plain write(2),
	// and os.pwrite(fd, ...) is pwrite64(2) — both hit handle_write_obs_sys_enter.
	py := `import os
import socket
addr = ("example.com", 80)
req1 = b"GET /a HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
req2 = b"GET /b HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(addr)
os.write(s.fileno(), req1)
s.close()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(addr)
os.pwrite(s.fileno(), req2, 0)
s.close()
`
	if err := os.WriteFile(probe, []byte(py), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", probe)
	if err := cmd.Run(); err != nil {
		t.Logf("http write probe (non-fatal): %v", err)
	}

	cancel()
	err = <-errCh
	if err != nil && !errors.Is(err, context.Canceled) {
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
	if err != nil && !errors.Is(err, context.Canceled) {
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

func TestRun_TLSClientHelloSendtoSockaddrJSONL(t *testing.T) {
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
	probe := filepath.Join(dir, "tls_sendto_probe.py")
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
	t.Setenv("COLDSTEP_FEATURE_GATES", "tls_sni=1")

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(450 * time.Millisecond)

	// Mirrors internal/telemetry buildSyntheticClientHelloWithSNI: TCP sendto(+sockaddr)
	// after connect must classify as TLS ClientHello (same parity as HTTP sendto).
	py := `import socket
import struct

def build_synthetic_clienthello_sni(host: str) -> bytes:
    hb = host.encode('ascii')
    if not (0 < len(hb) <= 200):
        raise ValueError(host)
    list_len = 1 + 2 + len(hb)
    ext_val = bytearray(2 + list_len)
    struct.pack_into('>H', ext_val, 0, list_len)
    ext_val[2] = 0
    struct.pack_into('>H', ext_val, 3, len(hb))
    ext_val[5 : 5 + len(hb)] = hb
    ext_block = bytearray(4 + len(ext_val))
    struct.pack_into('>H', ext_block, 0, 0)
    struct.pack_into('>H', ext_block, 2, len(ext_val))
    ext_block[4:] = ext_val
    ch = bytearray()
    ch.extend(bytes([0x03, 0x03]))
    ch.extend(bytes(32))
    ch.append(0)
    ch.extend(bytes([0x00, 0x02, 0x13, 0x01]))
    ch.extend(bytes([0x01, 0x00]))
    ext_len = len(ext_block)
    ch.extend(struct.pack('>H', ext_len))
    ch.extend(ext_block)
    ch_len = len(ch)
    hs = bytearray([0x01])
    hs.extend([(ch_len >> 16) & 0xFF, (ch_len >> 8) & 0xFF, ch_len & 0xFF])
    hs.extend(ch)
    rec_body = bytes(hs)
    rec_len = len(rec_body)
    out = bytearray([0x16, 0x03, 0x01, (rec_len >> 8) & 0xFF, rec_len & 0xFF])
    out.extend(rec_body)
    return bytes(out)

addr = ("example.com", 443)
buf = build_synthetic_clienthello_sni("example.com")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(addr)
s.sendto(buf, 0, addr)
s.close()
`
	if err := os.WriteFile(probe, []byte(py), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", probe)
	if err := cmd.Run(); err != nil {
		t.Logf("tls sendto probe (non-fatal): %v", err)
	}

	cancel()
	err = <-errCh
	if err != nil && !errors.Is(err, context.Canceled) {
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

func TestRun_TLSClientHelloPwriteJSONL(t *testing.T) {
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
	probe := filepath.Join(dir, "tls_pwrite_probe.py")
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
	t.Setenv("COLDSTEP_FEATURE_GATES", "tls_sni=1")

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(450 * time.Millisecond)

	// Same synthetic ClientHello as sendto test; emit via os.pwrite(fd, buf, 0) after connect (NR_PWRITE64).
	py := `import os
import socket
import struct

def build_synthetic_clienthello_sni(host: str) -> bytes:
    hb = host.encode('ascii')
    if not (0 < len(hb) <= 200):
        raise ValueError(host)
    list_len = 1 + 2 + len(hb)
    ext_val = bytearray(2 + list_len)
    struct.pack_into('>H', ext_val, 0, list_len)
    ext_val[2] = 0
    struct.pack_into('>H', ext_val, 3, len(hb))
    ext_val[5 : 5 + len(hb)] = hb
    ext_block = bytearray(4 + len(ext_val))
    struct.pack_into('>H', ext_block, 0, 0)
    struct.pack_into('>H', ext_block, 2, len(ext_val))
    ext_block[4:] = ext_val
    ch = bytearray()
    ch.extend(bytes([0x03, 0x03]))
    ch.extend(bytes(32))
    ch.append(0)
    ch.extend(bytes([0x00, 0x02, 0x13, 0x01]))
    ch.extend(bytes([0x01, 0x00]))
    ext_len = len(ext_block)
    ch.extend(struct.pack('>H', ext_len))
    ch.extend(ext_block)
    ch_len = len(ch)
    hs = bytearray([0x01])
    hs.extend([(ch_len >> 16) & 0xFF, (ch_len >> 8) & 0xFF, ch_len & 0xFF])
    hs.extend(ch)
    rec_body = bytes(hs)
    rec_len = len(rec_body)
    out = bytearray([0x16, 0x03, 0x01, (rec_len >> 8) & 0xFF, rec_len & 0xFF])
    out.extend(rec_body)
    return bytes(out)

addr = ("example.com", 443)
buf = build_synthetic_clienthello_sni("example.com")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(addr)
os.pwrite(s.fileno(), buf, 0)
s.close()
`
	if err := os.WriteFile(probe, []byte(py), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", probe)
	if err := cmd.Run(); err != nil {
		t.Logf("tls pwrite probe (non-fatal): %v", err)
	}

	cancel()
	err = <-errCh
	if err != nil && !errors.Is(err, context.Canceled) {
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
	if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
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

// bpfMapGetNextID is BPF_MAP_GET_NEXT_ID from Linux UAPI linux/bpf.h.
const bpfMapGetNextID = 12

// triggerBPFMapGetNextIDSyscalls walks map IDs via bpf(BPF_MAP_GET_NEXT_ID, …).
// Newer bpftool releases may implement "map list" without that syscall (breaking the
// audit JSONL probe on ubuntu-24.04+); cilium/ebpf always uses the UAPI path we assert on.
func triggerBPFMapGetNextIDSyscalls() (emitted bool) {
	first, err := ebpf.MapGetNextID(0)
	if err != nil {
		return false
	}
	emitted = true
	id := first
	for range 64 {
		next, err := ebpf.MapGetNextID(id)
		if err != nil {
			break
		}
		id = next
	}
	return emitted
}

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
	emittedMapGetNextDuringPoll := false
	for time.Now().Before(deadline) {
		emittedMapGetNext := triggerBPFMapGetNextIDSyscalls()
		if emittedMapGetNext {
			emittedMapGetNextDuringPoll = true
		}
		if hasBpftool {
			_ = exec.Command("bpftool", "map", "list").Run()
		}
		// Only require cmd=12 when we actually issued BPF_MAP_GET_NEXT_ID; bpftool alone is not enough on newer distros.
		requireMapGetNextID := emittedMapGetNext
		time.Sleep(150 * time.Millisecond)
		b, rerr := os.ReadFile(events)
		if rerr != nil {
			continue
		}
		if !bytes.Contains(b, []byte(`"type":"bpf_audit"`)) {
			continue
		}
		if validateBPFAuditJSONL(b, requireMapGetNextID) == nil {
			validated = true
			break
		}
	}

	cancel()
	err = <-errCh
	if err != nil && !errors.Is(err, context.Canceled) {
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
		if !emittedMapGetNextDuringPoll && !hasBpftool {
			t.Skip("no bpf_audit events and no probe for BPF_MAP_GET_NEXT_ID")
		}
		t.Fatalf("expected bpf_audit in jsonl:\n%s", string(b))
	}
	requireValidBPFAuditJSONL(t, b, emittedMapGetNextDuringPoll)
}
