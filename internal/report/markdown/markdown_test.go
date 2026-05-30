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
