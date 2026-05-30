// Package markdown renders coldstep run reports as pure Markdown — no embedded
// HTML (no <details>, no <!-- comments -->). It reads the JSONL event stream
// (.coldstep-events.jsonl), the source of truth, and produces two outputs:
//
//   - RenderSimple   — the at-a-glance report for $GITHUB_STEP_SUMMARY.
//   - RenderDetailed — the full report written to .coldstep-report.md and
//     uploaded as a workflow artifact.
//
// This package replaces the model -> integrity -> html pipeline behind the
// separate coldstep-report binary. It depends only on encoding/json + stdlib so
// it builds and unit-tests on any GOOS (no BPF, no Linux).
package markdown

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Deny is one blocked egress, flattened for rendering.
type Deny struct {
	Comm       string
	Protocol   string
	Dst        string
	Dport      uint16
	Reason     string
	HookFamily string
}

// Aggregate is the rolled-up signal from one JSONL event stream. It is the
// single intermediate between raw events and both report renders.
type Aggregate struct {
	Mode string // "defend" / "detect" (best-effort from deny/meta events)

	TCPConns int
	UDPSends int
	HTTPReqs int

	Denies []Deny

	TLSFull     int
	TLSPartial  int
	TLSInferred int
	TLSUnknown  int

	QUICCandidates int
	IPv6Events     int

	// Dests maps a destination label (FQDN when known, else dst host) to the
	// number of egress events seen for it.
	Dests map[string]int

	// EventsSHA256, when set, is rendered as a plain line (never an HTML
	// comment) for tamper-evidence.
	EventsSHA256 string

	ParseErrors int
	TotalEvents int
}

// minimal per-type shapes — only the fields the reports consume. Decoupled
// from internal/telemetry so this package stays dependency-light.
type typedLine struct {
	Type string `json:"type"`
}

type netLine struct {
	Dst          string `json:"dst"`
	Dport        uint16 `json:"dport"`
	FQDN         string `json:"fqdn"`
	PossibleQUIC bool   `json:"possible_quic"`
}

type tlsLine struct {
	Confidence string `json:"confidence"`
	SNI        string `json:"sni"`
	Dst        string `json:"dst"`
}

type denyLine struct {
	Comm       string `json:"comm"`
	Protocol   string `json:"protocol"`
	Dst        string `json:"dst"`
	Dport      uint16 `json:"dport"`
	Reason     string `json:"reason"`
	HookFamily string `json:"hook_family"`
	Mode       string `json:"mode"`
}

// Parse reads a JSONL event stream and rolls it up into an Aggregate. Malformed
// lines are counted in ParseErrors and skipped — a single bad line never aborts
// the report (defence-in-depth against a build step appending garbage).
func Parse(r io.Reader) (*Aggregate, error) {
	a := &Aggregate{Dests: make(map[string]int)}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var t typedLine
		if err := json.Unmarshal(line, &t); err != nil {
			a.ParseErrors++
			continue
		}
		a.TotalEvents++
		switch t.Type {
		case "tcp", "tcp6":
			a.TCPConns++
			if t.Type == "tcp6" {
				a.IPv6Events++
			}
			a.countDest(line)
		case "udp", "udp6":
			a.UDPSends++
			if t.Type == "udp6" {
				a.IPv6Events++
			}
			a.countDest(line)
		case "http":
			a.HTTPReqs++
		case "quic_candidate":
			a.QUICCandidates++
		case "tls":
			a.countTLS(line)
		case "deny":
			a.countDeny(line)
		}
	}
	if err := sc.Err(); err != nil {
		return a, fmt.Errorf("scan events: %w", err)
	}
	return a, nil
}

func (a *Aggregate) countDest(line []byte) {
	var n netLine
	if json.Unmarshal(line, &n) != nil {
		return
	}
	key := n.FQDN
	if key == "" {
		key = n.Dst
	}
	if key == "" {
		return
	}
	a.Dests[key]++
}

func (a *Aggregate) countTLS(line []byte) {
	var tl tlsLine
	if json.Unmarshal(line, &tl) != nil {
		return
	}
	switch tl.Confidence {
	case "full":
		a.TLSFull++
	case "partial":
		a.TLSPartial++
	case "inferred":
		a.TLSInferred++
	default:
		a.TLSUnknown++
	}
}

func (a *Aggregate) countDeny(line []byte) {
	var d denyLine
	if json.Unmarshal(line, &d) != nil {
		return
	}
	if d.Mode != "" {
		a.Mode = d.Mode
	}
	a.Denies = append(a.Denies, Deny{
		Comm:       d.Comm,
		Protocol:   d.Protocol,
		Dst:        d.Dst,
		Dport:      d.Dport,
		Reason:     d.Reason,
		HookFamily: d.HookFamily,
	})
}

type destCount struct {
	name  string
	count int
}

// topDests returns up to n destinations sorted by count desc, then name asc for
// stable output.
func (a *Aggregate) topDests(n int) []destCount {
	out := make([]destCount, 0, len(a.Dests))
	for k, v := range a.Dests {
		out = append(out, destCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].name < out[j].name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (a *Aggregate) modeLabel() string {
	if a.Mode == "" {
		return "detect"
	}
	return a.Mode
}

func (a *Aggregate) verdict() string {
	if len(a.Denies) > 0 {
		return fmt.Sprintf("🚨 %d egress blocked", len(a.Denies))
	}
	return "✅ no anomalies (IPv4 TCP/UDP in scope)"
}

// RenderSimple produces the at-a-glance report for the job summary.
func (a *Aggregate) RenderSimple() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## coldstep — %s %s\n\n", a.modeLabel(), a.verdict())

	fmt.Fprintln(&b, "| metric | value |")
	fmt.Fprintln(&b, "|---|---|")
	fmt.Fprintf(&b, "| egress connections | %d |\n", a.TCPConns)
	fmt.Fprintf(&b, "| udp sends | %d |\n", a.UDPSends)
	fmt.Fprintf(&b, "| unique destinations | %d |\n", len(a.Dests))
	fmt.Fprintf(&b, "| denied | %d |\n", len(a.Denies))
	fmt.Fprintf(&b, "| TLS SNI (full/partial) | %d / %d |\n", a.TLSFull, a.TLSPartial)
	fmt.Fprintf(&b, "| coverage gaps | IPv6 events %d · QUIC candidates %d |\n", a.IPv6Events, a.QUICCandidates)

	if top := a.topDests(3); len(top) > 0 {
		parts := make([]string, len(top))
		for i, d := range top {
			parts[i] = fmt.Sprintf("%s (%d)", d.name, d.count)
		}
		fmt.Fprintf(&b, "\nTop destinations: %s\n", strings.Join(parts, " · "))
	}
	fmt.Fprintln(&b, "\nFull report: `.coldstep-report.md` (artifact)")
	return b.String()
}

// RenderDetailed produces the full report written to .coldstep-report.md.
func (a *Aggregate) RenderDetailed() string {
	var b strings.Builder
	fmt.Fprintln(&b, "# coldstep detailed report")
	fmt.Fprintf(&b, "\n## Verdict\n\n%s · mode %s · %d events\n", a.verdict(), a.modeLabel(), a.TotalEvents)

	fmt.Fprintln(&b, "\n## Coverage scope")
	fmt.Fprintln(&b, "\n| class | status |")
	fmt.Fprintln(&b, "|---|---|")
	fmt.Fprintln(&b, "| IPv4 TCP/UDP | observed |")
	fmt.Fprintf(&b, "| IPv6 | %s |\n", observedIf(a.IPv6Events > 0))
	fmt.Fprintf(&b, "| QUIC/HTTP3 | %s |\n", candidatesIf(a.QUICCandidates))

	fmt.Fprintln(&b, "\n## Destinations")
	if len(a.Dests) == 0 {
		fmt.Fprintln(&b, "\n_none observed_")
	} else {
		fmt.Fprintln(&b, "\n| destination | egress events |")
		fmt.Fprintln(&b, "|---|---|")
		for _, d := range a.topDests(100) {
			fmt.Fprintf(&b, "| %s | %d |\n", d.name, d.count)
		}
	}

	fmt.Fprintln(&b, "\n## Denies")
	if len(a.Denies) == 0 {
		fmt.Fprintln(&b, "\n_none_")
	} else {
		fmt.Fprintln(&b, "\n| process | proto | destination | port | reason | hook |")
		fmt.Fprintln(&b, "|---|---|---|---|---|---|")
		for _, d := range a.Denies {
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %s | %s |\n",
				d.Comm, d.Protocol, d.Dst, d.Dport, d.Reason, dashIfEmpty(d.HookFamily))
		}
	}

	fmt.Fprintln(&b, "\n## TLS SNI confidence")
	fmt.Fprintln(&b, "\n| level | count |")
	fmt.Fprintln(&b, "|---|---|")
	fmt.Fprintf(&b, "| full | %d |\n", a.TLSFull)
	fmt.Fprintf(&b, "| partial | %d |\n", a.TLSPartial)
	fmt.Fprintf(&b, "| inferred | %d |\n", a.TLSInferred)
	fmt.Fprintf(&b, "| unknown | %d |\n", a.TLSUnknown)

	fmt.Fprintln(&b, "\n## Integrity")
	fmt.Fprintf(&b, "\nparse errors: %d\n", a.ParseErrors)
	if a.EventsSHA256 != "" {
		fmt.Fprintf(&b, "\nevents_sha256: `%s`\n", a.EventsSHA256)
	}
	return b.String()
}

func observedIf(b bool) string {
	if b {
		return "observed"
	}
	return "not observed"
}

func candidatesIf(n int) string {
	if n > 0 {
		return fmt.Sprintf("%d candidate(s), not inspected", n)
	}
	return "not observed"
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
