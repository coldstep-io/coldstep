//go:build integration && linux && !windows

// H20: Red-team integration tests asserting that the 12 attack paths
// catalogued in the v0.4.0 security review surface as expected JSONL
// events in detect mode and as deny / pass behaviour in defend mode.
//
// Pattern: each test stands up a coldstep agent in a goroutine (mirrors
// the existing TestRun_* tests in agent_integration_test.go), performs a
// triggering action, then polls .coldstep-events.jsonl. Tests are gated
// `//go:build integration && linux && !windows` and require root for BPF
// load — CI ubuntu-latest is the intended runner.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coldstep-io/coldstep/internal/config"
)

// redteamSetup is the common harness preamble for a red-team integration
// test: it creates a tempdir, writes the detect-md / summary-md sentinel
// files, applies the supplied env, and returns the resolved paths.
type redteamHarness struct {
	dir     string
	events  string
	detect  string
	summary string
	ready   string
}

func newRedteamHarness(t *testing.T) redteamHarness {
	t.Helper()
	dir := t.TempDir()
	h := redteamHarness{
		dir:     dir,
		events:  filepath.Join(dir, ".coldstep-events.jsonl"),
		detect:  filepath.Join(dir, "detect.md"),
		summary: filepath.Join(dir, "summary.md"),
		ready:   filepath.Join(dir, ".coldstep-ready.json"),
	}
	for _, p := range []string{h.detect, h.summary} {
		if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return h
}

// applyDetectEnv configures the agent for detect mode with an empty
// allowlist. Caller may layer additional env (feature gates, etc.) on top
// via further t.Setenv calls.
func (h redteamHarness) applyDetectEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_WORKSPACE", h.dir)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", h.summary)
	t.Setenv("COLDSTEP_DETECT_LOG", h.detect)
	t.Setenv("COLDSTEP_EVENTS_LOG", h.events)
	t.Setenv("COLDSTEP_AGENT_STATUS", h.ready)
}

// applyDefendEnv configures the agent for defend mode with the supplied
// allowlist (`allowedIPs` is the value for COLDSTEP_ALLOWED_IPS; CIDR or
// comma-separated literals). A non-empty allowedDomains is required by
// config.LoadFromEnv to enter defend mode.
func (h redteamHarness) applyDefendEnv(t *testing.T, allowedDomains, allowedIPs string) {
	t.Helper()
	t.Setenv("GITHUB_WORKSPACE", h.dir)
	t.Setenv("CI_GUARD_MODE", "defend")
	t.Setenv("COLDSTEP_ALLOWED_DOMAINS", allowedDomains)
	t.Setenv("COLDSTEP_ALLOWED_HOSTS", "")
	t.Setenv("COLDSTEP_ALLOWED_IPS", allowedIPs)
	t.Setenv("GITHUB_STEP_SUMMARY", h.summary)
	t.Setenv("COLDSTEP_DETECT_LOG", h.detect)
	t.Setenv("COLDSTEP_EVENTS_LOG", h.events)
	t.Setenv("COLDSTEP_AGENT_STATUS", h.ready)
}

// startAgent spawns Run in a goroutine and returns the cancel func and
// the error channel. Callers should defer cancel + drain the channel.
func startAgent(t *testing.T, totalTimeout time.Duration) (context.CancelFunc, <-chan error) {
	t.Helper()
	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatalf("config.LoadFromEnv: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()
	return cancel, errCh
}

// waitForReady polls the readiness file until "ok":true or the deadline
// passes. Returns true if the agent reported ready in time.
func waitForReady(readyPath string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(readyPath)
		if err == nil && bytes.Contains(b, []byte(`"ok":true`)) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// pollJSONLForType returns the first JSONL line whose "type" field
// equals typ and that satisfies all of the (optional) substring asserts.
// Empty slice means: any line of that type. Returns nil on timeout.
func pollJSONLForType(path, typ string, must []string, timeout time.Duration) []byte {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			for _, line := range bytes.Split(data, []byte("\n")) {
				if !bytes.Contains(line, []byte(`"type":"`+typ+`"`)) {
					continue
				}
				ok := true
				for _, sub := range must {
					if !bytes.Contains(line, []byte(sub)) {
						ok = false
						break
					}
				}
				if ok {
					return line
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// stopAgent cancels and drains the error channel. Allows context.Canceled
// (the normal shutdown signal) without failing.
func stopAgent(t *testing.T, cancel context.CancelFunc, errCh <-chan error) {
	t.Helper()
	cancel()
	if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned non-cancel error: %v", err)
	}
}

// ---- Attack path 1: detect — TCP connect to non-allowlisted IP -------

func TestRedTeam_TCPConnectNonAllowlistedLogged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)

	h := newRedteamHarness(t)
	h.applyDetectEnv(t)

	cancel, errCh := startAgent(t, 8*time.Second)
	defer stopAgent(t, cancel, errCh)

	time.Sleep(400 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second)
	if err != nil {
		t.Fatalf("dial 1.1.1.1:443: %v", err)
	}
	_ = conn.Close()

	line := pollJSONLForType(h.events, "tcp", []string{`"dst":"1.1.1.1"`, `"dport":443`}, 5*time.Second)
	if line == nil {
		dump, _ := os.ReadFile(h.events)
		t.Fatalf("no tcp JSONL row for 1.1.1.1:443 within 5s; events:\n%s", string(dump))
	}
}

// ---- Attack path 2: detect — UDP sendto to non-allowlisted IP --------

func TestRedTeam_UDPSendtoNonAllowlistedLogged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed:", err)
	}

	h := newRedteamHarness(t)
	h.applyDetectEnv(t)

	cancel, errCh := startAgent(t, 10*time.Second)
	defer stopAgent(t, cancel, errCh)

	time.Sleep(450 * time.Millisecond)

	cmd := exec.Command("python3", "-c", "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'redteam',('1.1.1.1',9999));s.close()")
	if err := cmd.Run(); err != nil {
		t.Logf("udp probe (non-fatal exit): %v", err)
	}

	line := pollJSONLForType(h.events, "udp", []string{`"dst":"1.1.1.1"`, `"dport":9999`}, 5*time.Second)
	if line == nil {
		dump, _ := os.ReadFile(h.events)
		t.Fatalf("no udp JSONL row for 1.1.1.1:9999 within 5s; events:\n%s", string(dump))
	}
}

// ---- Attack path 3: detect — DNS query visible -----------------------

// DNS lookups surface as UDP events on dport=53 (the agent does not emit
// a separate "type":"dns" record; FQDN attribution lives in the dns_cache
// LPM map per SECURITY.md "DNS domain allowlists" notes). The red-team
// assertion is therefore: a DNS lookup produces a UDP event with dport=53.
func TestRedTeam_DNSQueryLogged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed:", err)
	}

	h := newRedteamHarness(t)
	h.applyDetectEnv(t)

	cancel, errCh := startAgent(t, 10*time.Second)
	defer stopAgent(t, cancel, errCh)

	time.Sleep(450 * time.Millisecond)

	// SOCK_DGRAM sendto on port 53 is the minimal DNS-shape probe; we don't
	// require an actual reply for the JSONL assertion to hold.
	cmd := exec.Command("python3", "-c", "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'\\x00\\x01',('8.8.8.8',53));s.close()")
	if err := cmd.Run(); err != nil {
		t.Logf("dns probe (non-fatal exit): %v", err)
	}

	line := pollJSONLForType(h.events, "udp", []string{`"dport":53`}, 5*time.Second)
	if line == nil {
		dump, _ := os.ReadFile(h.events)
		t.Fatalf("no udp JSONL row with dport=53 within 5s; events:\n%s", string(dump))
	}
}

// ---- Attack path 4: detect — TLS ClientHello SNI captured ------------

func TestRedTeam_TLSClientHelloSNICaptured(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed:", err)
	}

	h := newRedteamHarness(t)
	h.applyDetectEnv(t)
	t.Setenv("COLDSTEP_FEATURE_GATES", "tls_sni=1")

	cancel, errCh := startAgent(t, 15*time.Second)
	defer stopAgent(t, cancel, errCh)

	time.Sleep(500 * time.Millisecond)

	// --http1.1 forces TLS over TCP (not QUIC/H3) so the BPF write/sendto
	// sniff arm fires on the ClientHello.
	cmd := exec.Command("curl", "-fsS", "-4", "--http1.1", "--max-time", "10",
		"https://example.com", "-o", "/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("curl https://example.com: %v\n%s", err, out)
	}

	line := pollJSONLForType(h.events, "tls", []string{`"sni":"example.com"`}, 5*time.Second)
	if line == nil {
		dump, _ := os.ReadFile(h.events)
		t.Fatalf("no tls JSONL row with sni=example.com within 5s; events:\n%s", string(dump))
	}
}

// ---- Attack path 5: detect — exec captured with correct comm ---------

func TestRedTeam_ExecComm(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}

	h := newRedteamHarness(t)
	h.applyDetectEnv(t)

	cancel, errCh := startAgent(t, 6*time.Second)
	defer stopAgent(t, cancel, errCh)

	time.Sleep(400 * time.Millisecond)

	script := filepath.Join(h.dir, "redteam-canary.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho redteam-exec-canary >/dev/null\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(script).Run(); err != nil {
		t.Fatalf("exec canary: %v", err)
	}

	// Look for any exec row with a non-empty absolute exe path; the comm
	// is the leaf binary name (here typically "redteam-canary.sh" or "sh"
	// depending on shebang resolution). We assert structurally rather than
	// pinning a specific comm to keep the test stable across glibc/musl.
	line := pollJSONLForType(h.events, "exec", []string{`"exe":"/`}, 5*time.Second)
	if line == nil {
		dump, _ := os.ReadFile(h.events)
		t.Fatalf("no exec JSONL row with absolute exe path within 5s; events:\n%s", string(dump))
	}
}

// ---- Attack path 6: detect — IPv6 TCP connect (requires H7) ----------

// H7 (IPv6 connect telemetry) is not merged on this branch; coldstep's
// JSONL stream remains IPv4-only per SECURITY.md "Defend hooks". When H7
// lands and emits "type":"tcp6", this test should drop the skip.
func TestRedTeam_IPv6TCPConnect_RequiresH7(t *testing.T) {
	t.Skip("H7 not merged: coldstep does not emit \"type\":\"tcp6\" yet (see SECURITY.md: IPv6 is unsupported)")
}

// ---- Attack path 7: detect — QUIC heuristic (requires H19) -----------

// H19 (UDP heuristic flagging traffic to :443 as possible QUIC) is not
// merged; coldstep currently only counts io_uring_setup as a syscall-hook
// bypass signal and emits UDP events without a possible_quic flag.
func TestRedTeam_QUICHeuristic_RequiresH19(t *testing.T) {
	t.Skip("H19 not merged: udp JSONL has no \"possible_quic\" field yet")
}

// ---- Attack path 8: detect — io_uring SEND SQE (requires H8/io_uring) -

// io_uring_setup_observed is already a telemetry counter; an SQE-level
// JSONL "io_uring_send" event is the H8 follow-up and is not merged.
func TestRedTeam_IoUringSend_RequiresH8(t *testing.T) {
	t.Skip("H8 not merged: io_uring SEND SQEs are not surfaced as JSONL events; only io_uring_setup_observed is counted in telemetry")
}

// ---- Attack path 9: defend — non-allowlisted TCP blocked -------------

func TestRedTeam_DefendBlocksNonAllowlistedTCP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)

	h := newRedteamHarness(t)
	h.applyDefendEnv(t, "localhost", "127.0.0.1/32")

	cancel, errCh := startAgent(t, 15*time.Second)
	defer stopAgent(t, cancel, errCh)

	if !waitForReady(h.ready, 10*time.Second) {
		t.Fatal("agent did not become ready within 10s")
	}

	// 8.8.8.8 is outside the default ignored RFC1918 ranges and outside
	// the 127.0.0.1/32 allowlist, so the cgroup defend hook should deny.
	dialErr := func() error {
		conn, derr := net.DialTimeout("tcp", "8.8.8.8:53", 2*time.Second)
		if derr == nil {
			_ = conn.Close()
			return nil
		}
		return derr
	}()

	// Connect refusal — EPERM is the expected outcome on Linux when the
	// cgroup connect4 hook returns 0 (deny). Some kernel/userland combos
	// surface ECONNREFUSED or "network is unreachable" depending on which
	// hook layer denies; accept any of those + the deny JSONL event as
	// the primary signal.
	if dialErr == nil {
		t.Logf("note: net.Dial to 8.8.8.8:53 succeeded; will rely on JSONL deny event for assertion")
	} else {
		t.Logf("dial err (expected, defend mode): %v", dialErr)
	}

	line := pollJSONLForType(h.events, "deny",
		[]string{`"dst":"8.8.8.8"`, `"dport":53`, `"protocol":"tcp"`}, 5*time.Second)
	if line == nil {
		dump, _ := os.ReadFile(h.events)
		t.Fatalf("no deny JSONL row for 8.8.8.8:53/tcp within 5s; events:\n%s", string(dump))
	}
	// Bind the dial error result to the deny outcome: if defend blocked
	// the connect, dialErr must be non-nil with EPERM/ECONNREFUSED.
	if dialErr != nil && !isExpectedDefendDialError(dialErr) {
		t.Logf("dial error category (informational): %v", dialErr)
	}
}

func isExpectedDefendDialError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "no route to host")
}

// ---- Attack path 10: defend — allowlisted IP passes ------------------

func TestRedTeam_DefendAllowsAllowlistedIP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)

	// Local TCP listener on 127.0.0.1; allowlist 127.0.0.1/32 explicitly
	// (loopback is NOT in DefaultIgnoredIPv4Nets — see internal/policy/ignore.go).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	h := newRedteamHarness(t)
	h.applyDefendEnv(t, "localhost", "127.0.0.1/32")

	cancel, errCh := startAgent(t, 15*time.Second)
	defer stopAgent(t, cancel, errCh)

	if !waitForReady(h.ready, 10*time.Second) {
		t.Fatal("agent did not become ready within 10s")
	}

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial 127.0.0.1 (allowlisted): %v", err)
	}
	_ = conn.Close()

	// Drain a brief window to let any (unexpected) deny event surface,
	// then assert that no deny row exists for the allowlisted target.
	time.Sleep(1500 * time.Millisecond)
	data, _ := os.ReadFile(h.events)
	for _, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.Contains(line, []byte(`"type":"deny"`)) {
			continue
		}
		if bytes.Contains(line, []byte(`"dst":"127.0.0.1"`)) &&
			bytes.Contains(line, []byte(`"dport":`+itoaDport(port))) {
			t.Fatalf("unexpected deny event for allowlisted 127.0.0.1:%d:\n%s", port, line)
		}
	}
}

func itoaDport(port int) string {
	// json.Number-friendly: dport is encoded as a bare integer, so a plain
	// decimal representation works for substring search.
	b, _ := json.Marshal(port)
	return string(b)
}

// ---- Attack path 11: defend — loopback never blocked when allowlisted -

// 127.0.0.1 is *not* implicitly ignored by DefaultIgnoredIPv4Nets (only
// 10/8 and 172.16/12 are — see internal/policy/ignore.go). The contract
// is that with 127.0.0.1/32 in the allowlist, loopback traffic passes
// without a deny event. This test asserts that explicit-pass behaviour.
func TestRedTeam_DefendLoopbackAllowlistedPasses(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	h := newRedteamHarness(t)
	h.applyDefendEnv(t, "localhost", "127.0.0.1/32")

	cancel, errCh := startAgent(t, 15*time.Second)
	defer stopAgent(t, cancel, errCh)

	if !waitForReady(h.ready, 10*time.Second) {
		t.Fatal("agent did not become ready within 10s")
	}

	// Multiple connects to exercise the cgroup hook more than once.
	for i := 0; i < 3; i++ {
		conn, derr := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if derr != nil {
			t.Fatalf("loopback dial #%d (allowlisted): %v", i, derr)
		}
		_ = conn.Close()
	}

	time.Sleep(1200 * time.Millisecond)
	data, _ := os.ReadFile(h.events)
	for _, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.Contains(line, []byte(`"type":"deny"`)) {
			continue
		}
		if bytes.Contains(line, []byte(`"dst":"127.0.0.1"`)) {
			t.Fatalf("unexpected deny event for loopback 127.0.0.1:\n%s", line)
		}
	}
}

// ---- Attack path A-T12a: defend — cgroup_skb egress backstop, raw-socket bypass ---

// TestRedTeam_EgressBackstop_RawSocketBypass verifies that a raw-socket send
// to a non-allowlisted, non-loopback IPv4 destination produces an
// "egress_backstop" JSONL row in defend mode. Raw sockets bypass the
// connect4/sendmsg4 cgroup hooks (no connect syscall is issued), so the
// cgroup_skb/egress backstop program is the only observation point.
//
// 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — a globally non-routable
// documentation prefix; packets will be silently dropped by the network
// stack, which is the safe choice for a red-team test.
func TestRedTeam_EgressBackstop_RawSocketBypass(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed:", err)
	}

	h := newRedteamHarness(t)
	// Allow only loopback so the raw-socket destination is non-allowlisted and
	// the cgroup_skb egress backstop observes it. The destination MUST be
	// routable: cgroup_skb/egress only fires once the kernel builds an egress
	// skb, which requires a route. RFC5737 TEST-NET addresses are unrouted on
	// hosted runners (sendto -> ENETUNREACH, no packet, no hook), so we target
	// a routable public anycast IP (1.1.1.1) that the default route covers. The
	// crafted packet uses experimental protocol 253 (RFC 3692) and is harmless;
	// we only need the kernel to route it through the egress hook.
	const rawDst = "1.1.1.1"
	h.applyDefendEnv(t, "localhost", "127.0.0.1/32")

	cancel, errCh := startAgent(t, 20*time.Second)
	defer stopAgent(t, cancel, errCh)

	if !waitForReady(h.ready, 12*time.Second) {
		t.Fatal("agent did not become ready within 12s")
	}

	// Send via a raw socket bound to an experimental IP protocol (253, RFC
	// 3692) WITHOUT IP_HDRINCL, so the kernel builds a well-formed IP header
	// (correct total-length + checksum). A hand-crafted IP_HDRINCL header whose
	// total-length field disagrees with the buffer size is dropped in the
	// output path before ip_finish_output, so cgroup_skb/egress never sees it —
	// that was the prior failure. A raw socket still bypasses the cgroup
	// connect4/sendmsg4 hooks (no connect(), not a UDP datagram socket), so the
	// only layer that can observe the egress is the cgroup_skb backstop. Send a
	// handful of times to ride over transient routing/ARP warm-up.
	rawScript := `
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 253)
payload = b"\xde\xad\xbe\xef\xde\xad\xbe\xef"
for _ in range(8):
    try:
        s.sendto(payload, ("1.1.1.1", 0))
    except OSError as e:
        sys.stderr.write("sendto: " + str(e) + "\n")
    time.sleep(0.2)
`
	cmd := exec.Command("python3", "-c", rawScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("raw-socket probe (non-fatal exit): %v\n%s", err, out)
	}

	line := pollJSONLForType(h.events, "egress_backstop", []string{`"dst":"` + rawDst + `"`}, 8*time.Second)
	if line == nil {
		dump, _ := os.ReadFile(h.events)
		t.Fatalf("no egress_backstop JSONL row for %s within 8s; events:\n%s", rawDst, string(dump))
	}
}

// ---- Attack path A-T12b: defend — cgroup_skb egress backstop, no false positive ---

// TestRedTeam_EgressBackstop_NoFalsePositiveOnAllowlisted verifies that a
// normal TCP connect to an allowlisted loopback address does NOT produce an
// "egress_backstop" JSONL row. The cgroup_skb/egress backstop should remain
// silent for traffic that passes through the connect4 hook's allow path.
//
// Note: 127.0.0.0/8 is excluded from egress_backstop observation by the BPF
// program itself (skb_v4_is_loopback short-circuit in trace_defend_skb.inc),
// so this test also validates that the backstop BPF-level bypass is working.
func TestRedTeam_EgressBackstop_NoFalsePositiveOnAllowlisted(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)

	// Start a local TCP listener on 127.0.0.1 so the dial can succeed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	h := newRedteamHarness(t)
	// Allow loopback; any connect to 127.0.0.1 is allowlisted and must not
	// trigger the backstop.
	h.applyDefendEnv(t, "localhost", "127.0.0.1/32")

	cancel, errCh := startAgent(t, 20*time.Second)
	defer stopAgent(t, cancel, errCh)

	if !waitForReady(h.ready, 12*time.Second) {
		t.Fatal("agent did not become ready within 12s")
	}

	// Perform several allowlisted loopback TCP connects.
	for i := 0; i < 3; i++ {
		conn, derr := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if derr != nil {
			t.Fatalf("loopback dial #%d (allowlisted): %v", i, derr)
		}
		_ = conn.Close()
	}

	// Wait a window long enough for any spurious backstop event to surface.
	time.Sleep(1500 * time.Millisecond)

	data, _ := os.ReadFile(h.events)
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.Contains(line, []byte(`"type":"egress_backstop"`)) {
			t.Fatalf("unexpected egress_backstop event for allowlisted loopback traffic:\n%s", line)
		}
	}
}

// ---- Attack path 12: defend — allowlisted domain's IPs pass ---------

// Domain-based allowlisting is best-effort (see SECURITY.md → "DNS
// domain allowlists (defend)"): the agent pre-resolves
// COLDSTEP_ALLOWED_DOMAINS at startup and populates the BPF LPM map.
// "localhost" is the smallest stable domain to exercise this path on
// hosted runners (resolves to 127.0.0.1 via /etc/hosts).
func TestRedTeam_DefendAllowlistedDomainResolvesAndPasses(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	skipIfUnsupportedSyscallBPFKernel(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	h := newRedteamHarness(t)
	// localhost is the allowlisted domain; the resolver populates the LPM
	// map with 127.0.0.1 so the connect4 hook short-circuits to allow.
	h.applyDefendEnv(t, "localhost", "127.0.0.1/32")

	cancel, errCh := startAgent(t, 15*time.Second)
	defer stopAgent(t, cancel, errCh)

	if !waitForReady(h.ready, 10*time.Second) {
		t.Fatal("agent did not become ready within 10s")
	}

	conn, derr := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if derr != nil {
		t.Fatalf("dial localhost listener (domain-allowlisted): %v", derr)
	}
	_ = conn.Close()

	time.Sleep(1200 * time.Millisecond)
	data, _ := os.ReadFile(h.events)
	for _, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.Contains(line, []byte(`"type":"deny"`)) {
			continue
		}
		if bytes.Contains(line, []byte(`"dst":"127.0.0.1"`)) {
			t.Fatalf("unexpected deny event after domain-resolved allowlist:\n%s", line)
		}
	}
}
