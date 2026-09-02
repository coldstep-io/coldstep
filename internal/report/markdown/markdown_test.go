package markdown

import (
	"strings"
	"testing"
)

const sampleJSONL = `{"type":"meta","ts":"t0"}
{"type":"tcp","dst":"140.82.112.3","dport":443,"fqdn":"github.com"}
{"type":"tcp","dst":"140.82.112.3","dport":443,"fqdn":"github.com"}
{"type":"tcp","dst":"151.101.0.223","dport":443,"fqdn":"pypi.org"}
{"type":"udp","dst":"8.8.8.8","dport":53,"fqdn":"dns.google"}
{"type":"udp","dst":"140.82.112.3","dport":443,"possible_quic":true}
{"type":"quic_candidate","dst_ip":"140.82.112.3"}
{"type":"http","method":"GET"}
{"type":"tls","sni":"github.com","confidence":"full","dst":"140.82.112.3"}
{"type":"tls","sni":"","confidence":"partial","dst":"1.2.3.4"}
{"type":"tcp6","dst":"2606:4700::1111","dport":443,"fqdn":"one.one.one.one"}
{"type":"deny","comm":"curl","protocol":"tcp","dst":"5.6.7.8","dport":80,"reason":"dst_not_allowlisted","hook_family":"cgroup","mode":"defend"}
not-json-garbage-line
`

func parseSample(t *testing.T) *Aggregate {
	t.Helper()
	a, err := Parse(strings.NewReader(sampleJSONL))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return a
}

func TestParse_Counts(t *testing.T) {
	a := parseSample(t)
	if a.TCPConns != 4 { // 3 tcp + 1 tcp6
		t.Errorf("TCPConns=%d want 4", a.TCPConns)
	}
	if a.UDPSends != 2 {
		t.Errorf("UDPSends=%d want 2", a.UDPSends)
	}
	if a.HTTPReqs != 1 {
		t.Errorf("HTTPReqs=%d want 1", a.HTTPReqs)
	}
	if a.QUICCandidates != 1 {
		t.Errorf("QUICCandidates=%d want 1", a.QUICCandidates)
	}
	if a.IPv6Events != 1 {
		t.Errorf("IPv6Events=%d want 1", a.IPv6Events)
	}
	if a.TLSFull != 1 || a.TLSPartial != 1 {
		t.Errorf("TLS full/partial=%d/%d want 1/1", a.TLSFull, a.TLSPartial)
	}
	if len(a.Denies) != 1 || a.Denies[0].Comm != "curl" {
		t.Errorf("Denies=%+v want 1 curl", a.Denies)
	}
	if a.Mode != "defend" {
		t.Errorf("Mode=%q want defend", a.Mode)
	}
	if a.ParseErrors != 1 {
		t.Errorf("ParseErrors=%d want 1 (garbage line)", a.ParseErrors)
	}
	// github.com appears on 2 tcp; unique dests = github.com, pypi.org,
	// dns.google, 140.82.112.3 (the bare-IP udp/quic), one.one.one.one
	if a.Dests["github.com"] != 2 {
		t.Errorf("github.com count=%d want 2", a.Dests["github.com"])
	}
}

// A stream with only agent meta rows captured no workload telemetry — on
// short jobs with fail-on-error unset the workload can finish before BPF
// attach. The report must say so loudly instead of rendering a green
// "no anomalies" verdict that proves nothing (upstream issue: silent empty
// capture on short detect jobs).
func TestRenderSimple_CapturedNothingBanner(t *testing.T) {
	a, err := Parse(strings.NewReader(`{"type":"meta","ts":"t0","mode":"detect"}` + "\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !a.CapturedNothing() {
		t.Fatal("CapturedNothing() = false for meta-only stream, want true")
	}
	simple := a.RenderSimple()
	if !strings.Contains(simple, "no events captured") {
		t.Errorf("RenderSimple missing captured-nothing banner:\n%s", simple)
	}
	if strings.Contains(simple, "✅") {
		t.Errorf("RenderSimple must not render a green verdict when nothing was captured:\n%s", simple)
	}
	if detailed := a.RenderDetailed(); !strings.Contains(detailed, "no events captured") {
		t.Errorf("RenderDetailed missing captured-nothing banner:\n%s", detailed)
	}

	// One real workload event flips it back to the normal verdict.
	a2, err := Parse(strings.NewReader(`{"type":"meta","ts":"t0","mode":"detect"}
{"type":"exec","comm":"bash"}
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if a2.CapturedNothing() {
		t.Fatal("CapturedNothing() = true with an exec event, want false")
	}
	if strings.Contains(a2.RenderSimple(), "no events captured") {
		t.Error("captured-nothing banner must not render when workload events exist")
	}
}

// A defend run where everything was allowlisted produces zero deny events.
// Mode must still come from the meta line, not be inferred as detect.
func TestParse_DefendModeFromMeta_NoDenies(t *testing.T) {
	jsonl := `{"type":"meta","ts":"t0","mode":"defend"}
{"type":"tcp","dst":"140.82.112.3","dport":443,"fqdn":"github.com"}
`
	a, err := Parse(strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(a.Denies) != 0 {
		t.Fatalf("Denies=%d want 0", len(a.Denies))
	}
	if a.Mode != "defend" {
		t.Errorf("Mode=%q want defend (from meta, no deny events)", a.Mode)
	}
	if got := a.modeLabel(); got != "defend" {
		t.Errorf("modeLabel=%q want defend", got)
	}
	if !strings.Contains(a.RenderSimple(), "defend") {
		t.Error("RenderSimple should label the run defend")
	}
}

func TestTopDests_Stable(t *testing.T) {
	a := parseSample(t)
	top := a.topDests(2)
	if len(top) != 2 || top[0].name != "github.com" || top[0].count != 2 {
		t.Fatalf("top[0]=%+v want github.com/2", top[0])
	}
}

func TestRenders_NoHTML(t *testing.T) {
	a := parseSample(t)
	for name, out := range map[string]string{
		"simple":   a.RenderSimple(),
		"detailed": a.RenderDetailed(),
	} {
		if strings.Contains(out, "<") {
			t.Errorf("%s report contains '<' (HTML not allowed):\n%s", name, out)
		}
		if strings.Contains(out, "<!--") {
			t.Errorf("%s report contains HTML comment", name)
		}
	}
}

func TestRenderSimple_Content(t *testing.T) {
	a := parseSample(t)
	out := a.RenderSimple()
	for _, want := range []string{
		"## coldstep — defend 🚨 1 egress blocked",
		"| denied | 1 |",
		"github.com (2)",
		"`.coldstep-report.md`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("simple missing %q\n---\n%s", want, out)
		}
	}
}

func TestRenderDetailed_Content(t *testing.T) {
	a := parseSample(t)
	out := a.RenderDetailed()
	for _, want := range []string{
		"# coldstep detailed report",
		"## Coverage scope",
		"## Denies",
		"| curl | tcp | 5.6.7.8 | 80 | dst_not_allowlisted | cgroup |",
		"## TLS SNI confidence",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detailed missing %q\n---\n%s", want, out)
		}
	}
}

func TestRenderDetailed_EmptyDenies(t *testing.T) {
	a, _ := Parse(strings.NewReader(`{"type":"tcp","dst":"1.1.1.1","dport":443,"fqdn":"a.com"}` + "\n"))
	out := a.RenderDetailed()
	if !strings.Contains(out, "## Denies\n\n_none_") {
		t.Errorf("expected _none_ denies section:\n%s", out)
	}
	if strings.Contains(out, "🚨") {
		t.Errorf("clean run must not show alert verdict")
	}
}

// richJSONL exercises every event class the Phase-2 parity port added, so the
// detailed report is provably lossless vs the agent digest's signal set.
const richJSONL = `{"type":"exec","comm":"sh"}
{"type":"proc_fork"}
{"type":"fs_event","op":"open","path":"/etc/passwd"}
{"type":"ktls_offload"}
{"type":"tcp_state","new_state":"established"}
{"type":"io_uring_send"}
{"type":"io_uring_tls","sni":"evil.example"}
{"type":"bpf_audit","cmd":5}
{"type":"bpf_tamper","asset":"map:defend_cfg"}
{"type":"bpf_self_defense","target_kind":"map","action":"denied"}
{"type":"egress_backstop","dst":"9.9.9.9"}
`

func TestParse_RichSignalCounts(t *testing.T) {
	a, err := Parse(strings.NewReader(richJSONL))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	checks := map[string]int{
		"Execs": a.Execs, "ProcForks": a.ProcForks, "FSEvents": a.FSEvents,
		"KTLSOffload": a.KTLSOffload, "TCPStateEvents": a.TCPStateEvents,
		"IoUringSend": a.IoUringSend, "IoUringTLS": a.IoUringTLS,
		"BPFAudit": a.BPFAudit, "BPFTamper": a.BPFTamper,
		"BpfSelfDefenseDenied": a.BpfSelfDefenseDenied, "EgressBackstop": a.EgressBackstop,
	}
	for name, got := range checks {
		if got != 1 {
			t.Errorf("%s = %d, want 1", name, got)
		}
	}
}

func TestRenderDetailed_SurfacesRichSignals(t *testing.T) {
	a, err := Parse(strings.NewReader(richJSONL))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	out := a.RenderDetailed()
	for _, want := range []string{
		"## Process & filesystem", "## Coverage & defend signals",
		"BPF self-defense denials", "egress backstop", "io_uring send",
		"BPF tamper",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detailed report missing %q:\n%s", want, out)
		}
	}
	// bpf_tamper must drive the headline verdict (anti-blindness).
	if !strings.Contains(out, "BPF tamper detected") {
		t.Errorf("tamper must drive verdict:\n%s", out)
	}
	if strings.Contains(out, "<") {
		t.Errorf("detailed report contains '<' (HTML not allowed):\n%s", out)
	}
}

func TestParse_MetaSignals(t *testing.T) {
	meta := `{"type":"meta","agent_version":"v9.9","kernel_release":"6.6.0","detect_profile":"enhanced","allowlist_ip_count":3,"allowlist_entry_count":2,"runner_has_ipv6":true,"runner_env":"dind","dropped_events":{"udp":5},"events_file_sha256":"abc123","bpf":[{"name":"connect4","ok":true},{"name":"lsm/socket_sendpage","ok":false}]}` + "\n"
	a, err := Parse(strings.NewReader(meta))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !a.MetaSeen || a.AllowlistIPs != 3 || a.RunnerEnv != "dind" || a.EventsSHA256 != "abc123" {
		t.Fatalf("meta not parsed: %+v", a)
	}
	if d := a.degradedBPF(); len(d) != 1 || d[0] != "lsm/socket_sendpage" {
		t.Fatalf("degradedBPF = %v want [lsm/socket_sendpage]", d)
	}
	out := a.RenderDetailed()
	for _, want := range []string{"agent v9.9", "Docker-in-Docker", "## BPF health", "failed to attach", "dropped events", "events_sha256: `abc123`"} {
		if !strings.Contains(out, want) {
			t.Errorf("detailed missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "<") {
		t.Errorf("HTML in report:\n%s", out)
	}
	sim := a.RenderSimple()
	if !strings.Contains(sim, "BPF hooks degraded") || !strings.Contains(sim, "Docker-in-Docker") {
		t.Errorf("simple missing degraded/dind:\n%s", sim)
	}
}

func TestMissingRequiredTypes(t *testing.T) {
	// Standard profile: meta+exec+tcp required.
	a, _ := Parse(strings.NewReader(`{"type":"meta"}` + "\n" + `{"type":"tcp"}` + "\n"))
	if got := a.MissingRequiredTypes(""); len(got) != 1 || got[0] != "exec" {
		t.Fatalf("standard missing = %v want [exec]", got)
	}
	full := `{"type":"meta"}` + "\n" + `{"type":"exec"}` + "\n" + `{"type":"tcp"}` + "\n"
	b, _ := Parse(strings.NewReader(full))
	if got := b.MissingRequiredTypes(""); len(got) != 0 {
		t.Fatalf("standard complete missing = %v want none", got)
	}
	// Enhanced widens the required set.
	if got := b.MissingRequiredTypes("enhanced"); len(got) == 0 {
		t.Fatalf("enhanced should report missing udp/http/tls/proc_fork/fs_event")
	}
}

// TestRenders_SanitizeInjectedCells guards against Markdown table injection from
// attacker-influenced JSONL fields (process comm, destination FQDN/SNI, deny
// reason): a `|`, backtick, newline, or `<` must not survive into a table cell.
func TestRenders_SanitizeInjectedCells(t *testing.T) {
	jsonl := strings.Join([]string{
		`{"type":"tcp","fqdn":"evil|x.example.com","dst":"1.2.3.4","dport":443}`,
		`{"type":"deny","comm":"sh|` + "`" + `id` + "`" + `","protocol":"tcp","dst":"a|b.com","dport":80,"reason":"x|y","hook_family":"cgroup","mode":"defend"}`,
	}, "\n") + "\n"
	a, err := Parse(strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for name, out := range map[string]string{"detailed": a.RenderDetailed(), "simple": a.RenderSimple()} {
		// No raw pipe from data should appear beyond the table delimiters. The
		// injected `evil|x` / `sh|`+backtick must be neutralized: no backtick-id,
		// and the dest/comm pipes replaced by the middot.
		if strings.Contains(out, "evil|x.example.com") {
			t.Errorf("%s: raw injected pipe survived in dest:\n%s", name, out)
		}
		if strings.Contains(out, "`id`") {
			t.Errorf("%s: raw backtick survived in comm:\n%s", name, out)
		}
	}
	det := a.RenderDetailed()
	if !strings.Contains(det, "evil·x.example.com") {
		t.Errorf("expected sanitized dest (pipe->middot) in detailed:\n%s", det)
	}
}

// TestRenders_NeutralizeLinkBrackets ensures a hostile SNI/FQDN cannot smuggle a
// Markdown link/image into the Job Summary or report via `[text](url)` syntax.
func TestRenders_NeutralizeLinkBrackets(t *testing.T) {
	jsonl := `{"type":"tls","sni":"[click](http://evil.example)","confidence":"full","dst":"1.2.3.4"}` + "\n" +
		`{"type":"tcp","fqdn":"[click](http://evil.example)","dst":"1.2.3.4","dport":443}` + "\n"
	a, err := Parse(strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for name, out := range map[string]string{"detailed": a.RenderDetailed(), "simple": a.RenderSimple()} {
		if strings.Contains(out, "[click]") || strings.Contains(out, "](http://evil.example)") {
			t.Errorf("%s: raw link brackets survived — link injection possible:\n%s", name, out)
		}
	}
}

// An over-long record must be counted as a parse error and skipped, not end
// the scan. Before the bufio.Reader rewrite a single record above
// maxEventLineBytes stopped bufio.Scanner permanently: every event after it was
// dropped and Parse returned an error the caller used to discard the whole
// report.
func TestParse_OversizedLineIsSkippedNotFatal(t *testing.T) {
	huge := `{"type":"tcp","pad":"` + strings.Repeat("A", maxEventLineBytes) + `"}`
	stream := `{"type":"meta","ts":"t0"}` + "\n" +
		huge + "\n" +
		`{"type":"exec"}` + "\n" +
		`{"type":"tcp","dst":"1.2.3.4","dport":443,"fqdn":"after.example.com"}` + "\n"

	a, err := Parse(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("Parse returned error for an over-long record: %v", err)
	}
	if a.ParseErrors != 1 {
		t.Errorf("ParseErrors=%d want 1 (the oversized record)", a.ParseErrors)
	}
	// Records after the oversized one must still be aggregated.
	if a.Execs != 1 {
		t.Errorf("Execs=%d want 1 — events after the oversized record were dropped", a.Execs)
	}
	if a.TCPConns != 1 {
		t.Errorf("TCPConns=%d want 1", a.TCPConns)
	}
	if _, ok := a.Dests["after.example.com"]; !ok {
		t.Errorf("destination after the oversized record missing: %v", a.Dests)
	}
	if missing := a.MissingRequiredTypes("standard"); len(missing) != 0 {
		t.Errorf("MissingRequiredTypes=%v want none", missing)
	}
}

// A final record with no trailing newline must still be aggregated.
func TestParse_UnterminatedFinalLine(t *testing.T) {
	a, err := Parse(strings.NewReader(`{"type":"meta"}` + "\n" + `{"type":"exec"}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if a.Execs != 1 {
		t.Errorf("Execs=%d want 1", a.Execs)
	}
}

// CRLF-terminated streams (a Windows-authored fixture) must parse.
func TestParse_CRLFTerminated(t *testing.T) {
	a, err := Parse(strings.NewReader("{\"type\":\"meta\"}\r\n{\"type\":\"exec\"}\r\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if a.Execs != 1 || !a.MetaSeen {
		t.Errorf("Execs=%d MetaSeen=%v want 1/true", a.Execs, a.MetaSeen)
	}
}
