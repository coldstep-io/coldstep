//go:build integration && linux && !windows

package agent

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coldstep-io/coldstep/internal/config"
)

// sendUDPTo fires one unconnected UDP datagram (sendto → cgroup/sendmsg4) at
// dst. Errors are returned, not fatal: a denied send fails with EPERM and the
// caller asserts via the JSONL deny stream, not the syscall result.
func sendUDPTo(t *testing.T, dst string) error {
	t.Helper()
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	addr, err := net.ResolveUDPAddr("udp4", dst)
	if err != nil {
		t.Fatalf("resolve %s: %v", dst, err)
	}
	_, werr := pc.WriteTo([]byte("x"), addr)
	return werr
}

// denyLinesWithDst returns the JSONL deny rows whose dst field contains ip.
func denyLinesWithDst(data []byte, ip string) [][]byte {
	var out [][]byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.Contains(line, []byte(`"type":"deny"`)) && bytes.Contains(line, []byte(ip)) {
			out = append(out, line)
		}
	}
	return out
}

// Defend-mode DNS regression (hosted-runner EAI_AGAIN incident):
//  1. UDP to loopback (the systemd-resolved stub address 127.0.0.53:53) must
//     NOT be denied — the BPF loopback bypass in defend_policy.inc:dst_in_ignored.
//  2. UDP to an explicit IPv4-literal allow: entry must NOT be denied — pins
//     the answer to the upstream report's open question ("IP-literal allow
//     entries aren't honored for the sendmsg4/UDP DNS path"): they are.
//  3. UDP to a non-allowlisted public IP MUST be denied — proves enforcement
//     was live, so 1 and 2 are not vacuously green.
func TestRun_DefendModeUDPLoopbackAndLiteralAllowNotDenied(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	dir := t.TempDir()
	events := filepath.Join(dir, ".coldstep-events.jsonl")
	summary := filepath.Join(dir, "summary.md")
	ready := filepath.Join(dir, ".coldstep-ready.json")
	if err := os.WriteFile(summary, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("CI_GUARD_MODE", "defend")
	t.Setenv("COLDSTEP_ALLOWED_DOMAINS", "localhost")
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "1.1.1.1/32")
	// Deterministic allowlist: the test host's resolv.conf must not leak
	// resolver IPs into the sets under test.
	t.Setenv("COLDSTEP_NO_RESOLVER_AUTOALLOW", "1")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	t.Setenv("COLDSTEP_EVENTS_LOG", events)
	t.Setenv("COLDSTEP_AGENT_STATUS", ready)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	if !waitForReady(ready, 10*time.Second) {
		cancel()
		<-errCh
		t.Fatal("agent never reported ready")
	}

	// Send the must-not-deny probes first, then the must-deny probe; once the
	// must-deny row lands, the earlier sends have certainly been adjudicated.
	if werr := sendUDPTo(t, "127.0.0.53:53"); werr != nil {
		t.Errorf("UDP to loopback 127.0.0.53:53 failed (loopback bypass regressed?): %v", werr)
	}
	if werr := sendUDPTo(t, "1.1.1.1:53"); werr != nil {
		t.Errorf("UDP to allowlisted literal 1.1.1.1:53 failed (sendmsg4 literal-allow regressed?): %v", werr)
	}
	_ = sendUDPTo(t, "9.9.9.9:53") // expected EPERM in defend mode

	denyDeadline := time.Now().Add(5 * time.Second)
	var data []byte
	for time.Now().Before(denyDeadline) {
		data, _ = os.ReadFile(events)
		if len(denyLinesWithDst(data, "9.9.9.9")) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	if rerr := <-errCh; rerr != nil && !errors.Is(rerr, context.Canceled) {
		t.Fatalf("Run: %v", rerr)
	}
	// Re-read after shutdown so late ring drains are included.
	data, _ = os.ReadFile(events)

	if len(denyLinesWithDst(data, "9.9.9.9")) == 0 {
		t.Fatalf("expected a deny row for non-allowlisted 9.9.9.9 (enforcement not live — other assertions vacuous); events:\n%s", string(data))
	}
	if lines := denyLinesWithDst(data, "127.0.0.53"); len(lines) > 0 {
		t.Errorf("loopback 127.0.0.53 was denied — BPF loopback bypass regressed:\n%s", bytes.Join(lines, []byte("\n")))
	}
	if lines := denyLinesWithDst(data, "1.1.1.1"); len(lines) > 0 {
		t.Errorf("allowlisted literal 1.1.1.1 was denied on the UDP path:\n%s", bytes.Join(lines, []byte("\n")))
	}
}
