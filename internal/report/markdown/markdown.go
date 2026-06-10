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

	// Process / filesystem activity (enhanced-profile event streams).
	Execs     int
	ProcForks int
	FSEvents  int

	Denies []Deny

	TLSFull     int
	TLSPartial  int
	TLSInferred int
	TLSUnknown  int

	QUICCandidates int
	IPv6Events     int

	// Coverage / bypass-class and defend self-protection signals. Each is a
	// JSONL event count; non-zero surfaces a coverage or defend row so the
	// pure-markdown report does not silently lose the agent-digest KPIs.
	KTLSOffload          int // ktls_offload — kernel-TLS hides the SNI
	TCPStateEvents       int // tcp_state — kernel-confirmed handshake transitions
	IoUringSend          int // io_uring_send — async send bypassing syscall arms
	IoUringTLS           int // io_uring_tls — TLS ClientHello over io_uring
	BPFAudit             int // bpf_audit — bpf() syscall observations
	BPFTamper            int // bpf_tamper — BPF map/prog tamper detected
	BpfSelfDefenseDenied int // bpf_self_defense — denied tamper of coldstep objects
	EgressBackstop       int // egress_backstop — egress that bypassed address hooks

	// Dests maps a destination label (FQDN when known, else dst host) to the
	// number of egress events seen for it.
	Dests map[string]int

	// seen is the set of JSONL event types observed, for the required-type
	// integrity gate (replaces the model-based integrity.CheckRequiredTypes).
	seen map[string]struct{}

	// domains is the set of destination FQDNs / SNIs observed (bare IPs
	// excluded), for the baseline diff gate (replaces model.BuildDiff's
	// domain set). Populated from net fqdn + tls sni.
	domains map[string]struct{}

	// EventsSHA256, when set, is rendered as a plain line (never an HTML
	// comment) for tamper-evidence.
	EventsSHA256 string

	// Fields below are populated from the shutdown `meta` event (last JSONL
	// line), which carries the agent's self-reported run context + health.
	AgentVersion     string
	KernelRelease    string
	DetectProfile    string
	AllowlistIPs     int
	AllowlistEntries int
	RunnerHasIPv6    bool
	RunnerEnv        string // "dind" / "unknown" / "" — DinD = inner-container blind spot
	BPF              []BPFStatus
	DroppedEvents    map[string]uint64
	MetaSeen         bool

	ParseErrors int
	TotalEvents int
	// NonMetaEvents counts every event except the meta rows the agent writes
	// about itself. Zero means the run captured no workload telemetry at all —
	// on short jobs with fail-on-error unset the workload can finish before
	// BPF attach, leaving a stream that looks green while proving nothing.
	// CapturedNothing surfaces that distinctly from "observed nothing".
	NonMetaEvents int
}

// CapturedNothing reports whether the stream carried no workload telemetry
// (only agent meta rows, or nothing at all). Distinct from a quiet job: an
// attached agent always captures at least the job's own exec events.
func (a *Aggregate) CapturedNothing() bool {
	return a.NonMetaEvents == 0
}

// BPFStatus is the report-local view of a BPF attach outcome from the meta
// event (decoupled from internal/telemetry to keep this package dependency-light).
type BPFStatus struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
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
	a := &Aggregate{Dests: make(map[string]int), seen: make(map[string]struct{}), domains: make(map[string]struct{})}
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
		if t.Type != "meta" {
			a.NonMetaEvents++
		}
		a.seen[t.Type] = struct{}{}
		switch t.Type {
		case "meta":
			a.countMeta(line)
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
		case "exec":
			a.Execs++
		case "proc_fork":
			a.ProcForks++
		case "fs_event":
			a.FSEvents++
		case "quic_candidate":
			a.QUICCandidates++
		case "tls":
			a.countTLS(line)
		case "ktls_offload":
			a.KTLSOffload++
		case "tcp_state":
			a.TCPStateEvents++
		case "io_uring_send":
			a.IoUringSend++
		case "io_uring_tls":
			a.IoUringTLS++
		case "bpf_audit":
			a.BPFAudit++
		case "bpf_tamper":
			a.BPFTamper++
		case "bpf_self_defense":
			a.BpfSelfDefenseDenied++
		case "egress_backstop":
			a.EgressBackstop++
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
	if n.FQDN != "" && !isBareIPv4(n.FQDN) {
		a.domains[strings.ToLower(n.FQDN)] = struct{}{}
	}
}

type metaLine struct {
	BPF              []BPFStatus       `json:"bpf"`
	AllowlistIPs     int               `json:"allowlist_ip_count"`
	AllowlistEntries int               `json:"allowlist_entry_count"`
	RunnerHasIPv6    bool              `json:"runner_has_ipv6"`
	RunnerEnv        string            `json:"runner_env"`
	DroppedEvents    map[string]uint64 `json:"dropped_events"`
	EventsSHA256     string            `json:"events_file_sha256"`
	DetectProfile    string            `json:"detect_profile"`
	AgentVersion     string            `json:"agent_version"`
	KernelRelease    string            `json:"kernel_release"`
	Mode             string            `json:"mode"`
}

func (a *Aggregate) countMeta(line []byte) {
	var m metaLine
	if json.Unmarshal(line, &m) != nil {
		return
	}
	a.MetaSeen = true
	// Meta is the authoritative mode source: it lets a defend run with zero
	// deny events still label as defend (deny events alone cannot prove a
	// defend run happened). Legacy artifacts omit it and fall back to the
	// deny-derived mode set in countDeny.
	if m.Mode != "" {
		a.Mode = m.Mode
	}
	a.BPF = m.BPF
	a.AllowlistIPs = m.AllowlistIPs
	a.AllowlistEntries = m.AllowlistEntries
	a.RunnerHasIPv6 = m.RunnerHasIPv6
	a.RunnerEnv = m.RunnerEnv
	a.DroppedEvents = m.DroppedEvents
	a.DetectProfile = m.DetectProfile
	a.AgentVersion = m.AgentVersion
	a.KernelRelease = m.KernelRelease
	if m.EventsSHA256 != "" {
		a.EventsSHA256 = m.EventsSHA256
	}
}

// degradedBPF returns the names of BPF hooks that failed to attach (ok=false),
// sorted, for the coverage-honesty section.
func (a *Aggregate) degradedBPF() []string {
	var out []string
	for _, s := range a.BPF {
		if !s.OK {
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return out
}

func (a *Aggregate) countTLS(line []byte) {
	var tl tlsLine
	if json.Unmarshal(line, &tl) != nil {
		return
	}
	if tl.SNI != "" && !isBareIPv4(tl.SNI) {
		a.domains[strings.ToLower(tl.SNI)] = struct{}{}
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

// Domains returns the sorted set of destination FQDNs / SNIs observed (bare
// IPs excluded). Used by the baseline diff gate.
func (a *Aggregate) Domains() []string {
	out := make([]string, 0, len(a.domains))
	for d := range a.domains {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// DiffDomains returns the destination domains added in current vs baseline and
// those gone (in baseline, absent from current), each sorted. Replaces the
// model-based baseline diff; bare IPs are excluded so dial-time IP rotation
// does not create churn (the P1-2 supply-chain gate keys on `added`).
func DiffDomains(current, baseline *Aggregate) (added, removed []string) {
	for d := range current.domains {
		if _, ok := baseline.domains[d]; !ok {
			added = append(added, d)
		}
	}
	for d := range baseline.domains {
		if _, ok := current.domains[d]; !ok {
			removed = append(removed, d)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// isBareIPv4 reports whether host is an IPv4 dotted-quad (four all-digit
// labels) — such destinations are excluded from the domain diff.
func isBareIPv4(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) != 4 {
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
		for _, r := range l {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// RequiredTypes returns the JSONL event types an integrity-strict run expects.
// "enhanced" widens the set to the observe-only egress/process/fs signals.
// Ported from internal/report/integrity (drops the model dependency).
func RequiredTypes(detectProfile string) []string {
	if strings.EqualFold(strings.TrimSpace(detectProfile), "enhanced") {
		return []string{"meta", "exec", "tcp", "udp", "http", "tls", "proc_fork", "fs_event"}
	}
	return []string{"meta", "exec", "tcp"}
}

// MissingRequiredTypes returns the required event types absent from the stream,
// sorted. Empty result means the anti-blindness required-type gate passes.
func (a *Aggregate) MissingRequiredTypes(detectProfile string) []string {
	var missing []string
	for _, req := range RequiredTypes(detectProfile) {
		if _, ok := a.seen[req]; !ok {
			missing = append(missing, req)
		}
	}
	sort.Strings(missing)
	return missing
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
	if a.BPFTamper > 0 {
		return fmt.Sprintf("🚨 BPF tamper detected (%d) — telemetry integrity compromised", a.BPFTamper)
	}
	if len(a.Denies) > 0 {
		return fmt.Sprintf("🚨 %d egress blocked", len(a.Denies))
	}
	if a.EgressBackstop > 0 {
		return fmt.Sprintf("⚠️ %d egress reached the backstop (bypassed address hooks)", a.EgressBackstop)
	}
	if a.CapturedNothing() {
		return "⚠️ no events captured — the job may have finished before BPF attach; this proves nothing about egress (set fail-on-error: true for short jobs)"
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
	fmt.Fprintf(&b, "| exec / fork / fs | %d / %d / %d |\n", a.Execs, a.ProcForks, a.FSEvents)
	fmt.Fprintf(&b, "| TLS SNI (full/partial) | %d / %d |\n", a.TLSFull, a.TLSPartial)
	fmt.Fprintf(&b, "| coverage gaps | IPv6 events %d · QUIC candidates %d · io_uring %d |\n", a.IPv6Events, a.QUICCandidates, a.IoUringSend+a.IoUringTLS)
	if a.BpfSelfDefenseDenied > 0 || a.EgressBackstop > 0 {
		fmt.Fprintf(&b, "| defend self-protection | self-defense denials %d · egress backstop %d |\n", a.BpfSelfDefenseDenied, a.EgressBackstop)
	}
	if degraded := a.degradedBPF(); len(degraded) > 0 {
		fmt.Fprintf(&b, "| 🚨 BPF hooks degraded | %d not attached: %s |\n", len(degraded), strings.Join(degraded, ", "))
	}
	if a.RunnerEnv == "dind" {
		fmt.Fprintln(&b, "| ⚠️ Docker-in-Docker | inner-container traffic not observable |")
	}

	if top := a.topDests(3); len(top) > 0 {
		parts := make([]string, len(top))
		for i, d := range top {
			parts[i] = fmt.Sprintf("%s (%d)", mdCell(d.name), d.count)
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
	if a.MetaSeen {
		fmt.Fprintf(&b, "\nagent %s · kernel %s · profile %s · allowlist %d IP(s) / %d entr(ies)\n",
			mdCell(dashIfEmpty(a.AgentVersion)), mdCell(dashIfEmpty(a.KernelRelease)), mdCell(dashIfEmpty(a.DetectProfile)),
			a.AllowlistIPs, a.AllowlistEntries)
	}
	if a.RunnerEnv == "dind" {
		fmt.Fprintln(&b, "\n⚠️ Docker-in-Docker detected: traffic from inner containers is not observable from the outer runner cgroup namespace.")
	}
	if a.RunnerHasIPv6 && a.modeLabel() != "defend" && a.IPv6Events == 0 {
		fmt.Fprintln(&b, "\n⚠️ Runner has IPv6 connectivity but no IPv6 egress was observed in detect mode — IPv6 paths are not enforced.")
	}

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
			fmt.Fprintf(&b, "| %s | %d |\n", mdCell(d.name), d.count)
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
				mdCell(d.Comm), mdCell(d.Protocol), mdCell(d.Dst), d.Dport, mdCell(d.Reason), mdCell(dashIfEmpty(d.HookFamily)))
		}
	}

	fmt.Fprintln(&b, "\n## Process & filesystem")
	fmt.Fprintln(&b, "\n| stream | count |")
	fmt.Fprintln(&b, "|---|---|")
	fmt.Fprintf(&b, "| exec | %d |\n", a.Execs)
	fmt.Fprintf(&b, "| proc_fork | %d |\n", a.ProcForks)
	fmt.Fprintf(&b, "| fs_event | %d |\n", a.FSEvents)

	fmt.Fprintln(&b, "\n## TLS SNI confidence")
	fmt.Fprintln(&b, "\n| level | count |")
	fmt.Fprintln(&b, "|---|---|")
	fmt.Fprintf(&b, "| full | %d |\n", a.TLSFull)
	fmt.Fprintf(&b, "| partial | %d |\n", a.TLSPartial)
	fmt.Fprintf(&b, "| inferred | %d |\n", a.TLSInferred)
	fmt.Fprintf(&b, "| unknown | %d |\n", a.TLSUnknown)
	if a.KTLSOffload > 0 {
		fmt.Fprintf(&b, "\n%d socket(s) used kernel-TLS offload — the SNI is structurally hidden from userspace for those.\n", a.KTLSOffload)
	}

	fmt.Fprintln(&b, "\n## Coverage & defend signals")
	fmt.Fprintln(&b, "\n| signal | count | meaning |")
	fmt.Fprintln(&b, "|---|---|---|")
	fmt.Fprintf(&b, "| IPv6 egress | %d | non-loopback IPv6 egress events |\n", a.IPv6Events)
	fmt.Fprintf(&b, "| QUIC/HTTP3 candidates | %d | UDP/443 flows, payload not inspectable |\n", a.QUICCandidates)
	fmt.Fprintf(&b, "| io_uring send | %d | async sends bypassing syscall arms |\n", a.IoUringSend)
	fmt.Fprintf(&b, "| io_uring TLS | %d | TLS ClientHello observed over io_uring |\n", a.IoUringTLS)
	fmt.Fprintf(&b, "| egress backstop | %d | egress that bypassed connect4/sendmsg4 (raw socket / post-connect) |\n", a.EgressBackstop)
	fmt.Fprintf(&b, "| BPF self-defense denials | %d | denied tamper of coldstep's own BPF objects |\n", a.BpfSelfDefenseDenied)
	fmt.Fprintf(&b, "| BPF audit | %d | bpf() syscall observations |\n", a.BPFAudit)
	fmt.Fprintf(&b, "| BPF tamper | %d | detected BPF map/prog tamper (anti-blindness) |\n", a.BPFTamper)
	fmt.Fprintf(&b, "| TCP state transitions | %d | kernel-confirmed handshakes |\n", a.TCPStateEvents)

	fmt.Fprintln(&b, "\n## BPF health")
	if degraded := a.degradedBPF(); len(degraded) > 0 {
		fmt.Fprintf(&b, "\n🚨 %d hook(s) failed to attach (coverage gap): %s\n", len(degraded), strings.Join(degraded, ", "))
	} else if a.MetaSeen {
		fmt.Fprintf(&b, "\n✅ all %d reported BPF hook(s) attached.\n", len(a.BPF))
	} else {
		fmt.Fprintln(&b, "\n_no meta event — BPF health unavailable_")
	}

	fmt.Fprintln(&b, "\n## Integrity")
	fmt.Fprintf(&b, "\nparse errors: %d\n", a.ParseErrors)
	if len(a.DroppedEvents) > 0 {
		keys := make([]string, 0, len(a.DroppedEvents))
		for k := range a.DroppedEvents {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = fmt.Sprintf("%s=%d", k, a.DroppedEvents[k])
		}
		fmt.Fprintf(&b, "\ndropped events (ringbuf pressure): %s\n", strings.Join(parts, " · "))
	}
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

// mdCell sanitizes a string for safe interpolation into a Markdown table cell.
// JSONL string fields (process comm, destination FQDN/SNI, deny reason) are
// influenced by observed traffic and process state, so a raw `|`, backtick,
// newline, `<`, or link brackets would break the table or inject content into
// the Job Summary / report artifact. The `[`/`]` substitution neutralizes
// Markdown link/image syntax (e.g. a hostile SNI `[x](http://evil)` would
// otherwise render as a clickable link). Mirrors the old digest's sanitizeCell
// (lost when the report pipeline was rewritten).
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "·")
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "<", "‹")
	s = strings.ReplaceAll(s, "[", "［")
	s = strings.ReplaceAll(s, "]", "］")
	return strings.TrimSpace(s)
}
