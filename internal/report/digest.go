// Package report builds the Coldstep markdown digest from in-memory telemetry
// rows produced by the agent. The digest is the user-facing artifact written
// to GITHUB_STEP_SUMMARY / .coldstep-detect.md.
//
// The package is split into three files:
//
//   - digest_types.go: row types, DigestInput, small utility functions
//     (Truncate*, BPFCmdName) that have no dependencies on the rendering layer.
//   - digest_aggregation.go: classification and aggregation helpers used by
//     both the markdown builder and downstream tooling (hot-egress ranking,
//     ringbuf summing, KPI visibility predicates, empty-state reasons).
//   - digest.go (this file): the markdown writers and the top-level
//     BuildDetectMarkdown / WriteDetectDigest entry points.
//
// Output is GitHub Flavored Markdown (GFM) only — standard Markdown plus the
// GFM HTML subset (<details>, <summary>, <br>, <hr>, <table>). No <font>,
// <p align>, <sub>, or <center>; those are not in the GFM allowlist and render
// as literal text in Job Summaries.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/coldstep-io/coldstep/internal/atomicwrite"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// allowlistStaleThreshold is the digest's TTL-staleness boundary (H9 DNS-6b).
// Above this age the digest emits a ⚠️ box reminding operators that DNS TTLs
// may have expired since the BPF map snapshot was programmed.
const allowlistStaleThreshold = 5 * time.Minute

// partialEgressTotal sums the BG-01 per-syscall partial-observe counters so the
// headline-verdict "Review" threshold flips on any non-zero partial-observe.
func partialEgressTotal(in DigestInput) int {
	return in.SendfileObserved + in.SpliceObserved + in.SendmmsgFirstOnly
}

func droppedTotal(in DigestInput) int {
	t := 0
	for _, v := range in.DroppedCounts {
		t += v
	}
	return t
}

// ipv6EgressObserved returns the total non-loopback IPv6 egress attempts
// observed by the cgroup/connect6 + cgroup/sendmsg6 hooks. Non-zero means
// IPv6 destinations were contacted during the run. Under Phase 2, defend
// mode enforces on these — see ipv6DefendActive for the predicate that
// chooses the ✅/⚠️ verdict.
func ipv6EgressObserved(in DigestInput) uint32 {
	return in.IPv6ConnectObserved + in.IPv6SendmsgObserved
}

// ipv6DefendActive reports whether Phase 2 IPv6 enforcement is fully
// configured for this defend run. It returns true when defend mode is
// active AND the agent programmed at least one entry into the BPF
// allowed_ipv6 LPM trie (AAAA-resolved or literal). False covers two
// cases: detect mode (no enforcement at all) and defend mode with a
// pure block-all IPv6 posture (allowlist empty), which is functional
// but should be flagged so operators can spot a missing AAAA config.
func ipv6DefendActive(in DigestInput) bool {
	return isBlockingDigestMode(in.DefendMode) && in.DefendIPv6AllowlistSize > 0
}

// ipv6HooksLoaded reports whether the IPv6 enforcement hooks
// (cgroup/connect6, cgroup/sendmsg6) are loaded for this run. Today the
// IPv6 hooks are only attached in defend mode — detect mode never attaches
// them, so detect mode is treated as "no IPv6 hooks". When the runner has
// IPv6 connectivity (MetaEvent.RunnerHasIPv6) and no IPv6 hooks are loaded,
// the verdict is downgraded so the headline reflects the partial coverage.
func ipv6HooksLoaded(in DigestInput) bool {
	return isBlockingDigestMode(in.DefendMode)
}

// verdictEmoji returns ✅ / ⚠️ / 🚨 for the headline. Mirrors the prior
// blockquote badge logic but is now embedded directly in the `##` heading.
func verdictEmoji(in DigestInput) string {
	bpfOK := true
	for _, row := range in.BPF {
		if !row.OK {
			bpfOK = false
			break
		}
	}
	// P2-1 Phase 2: IPv6 in defend mode is gated by the allowed_ipv6 LPM
	// trie when populated (any traffic outside it gets EPERM at the
	// cgroup/connect6+sendmsg6 hooks). The "bypass" alert only fires when
	// defend mode observed IPv6 egress AND the IPv6 allowlist is empty —
	// in that block-all posture the events were denied, but the operator
	// likely meant to add AAAA destinations and should see it. Detect
	// mode still flags IPv6 as a ⚠️ visibility gap (handled in the review
	// check below).
	defendIPv6Bypass := isBlockingDigestMode(in.DefendMode) &&
		ipv6EgressObserved(in) > 0 &&
		in.DefendIPv6AllowlistSize == 0
	alert := (!in.CanaryPipelineOK && in.CanaryFailCount > 0) ||
		in.BPFHeartbeatFailures > 0 ||
		in.BPFMapIntegrityFailures > 0 ||
		(len(in.BPF) > 0 && !bpfOK) ||
		defendIPv6Bypass
	if alert {
		return "🚨"
	}
	// IPv6 egress is a ⚠️ when there's no Phase 2 enforcement to gate it
	// (detect mode — visibility-only). In defend mode with a populated
	// allowed_ipv6 trie the traffic was actually checked, so it's no
	// longer a review trigger on its own.
	ipv6Review := ipv6EgressObserved(in) > 0 && !ipv6DefendActive(in) && !isBlockingDigestMode(in.DefendMode)
	// H1: a runner that advertises IPv6 connectivity with no IPv6 hooks
	// loaded is a coverage gap on its own, even without observed events.
	// The agent could simply have missed unobserved IPv6 traffic; downgrade
	// ✅ to ⚠️ so the headline matches what was actually in scope.
	runnerIPv6Gap := in.RunnerHasIPv6 && !ipv6HooksLoaded(in)
	// H8: any TLS row that produced a partial or unknown SNI confidence tier
	// means at least one allow/deny decision on this run was driven by a
	// best-effort or absent SNI signal. Downgrade ✅ → ⚠️ so operators see
	// the gap in the headline rather than having to dig into the KPI row.
	// Gated on TLSTotal > 0 so a TLS-free run does not warn.
	tlsConfidenceGap := tlsKPIVisible(in) && in.TLSTotal > 0 &&
		(in.TLSConfidencePartial+in.TLSConfidenceUnknown) > 0
	review := totalDetectRingbufReserveFailures(in) > 0 ||
		in.UDPSendmsgMultiIovecObserved > 0 ||
		in.TLSWritevMultiIovecObserved > 0 ||
		in.SendmmsgMultiMessage > 0 ||
		in.SendmmsgUnobservedExtra > 0 ||
		partialEgressTotal(in) > 0 ||
		in.Connect4TupleUpdateFailures > 0 ||
		in.DefendDenyReserveFailures > 0 ||
		droppedTotal(in) > 0 ||
		in.IoUringSetupObserved > 0 ||
		ipv6Review ||
		runnerIPv6Gap ||
		tlsConfidenceGap
	if review {
		return "⚠️"
	}
	return "✅"
}

// verdictBadgeText returns the descriptive label rendered next to the
// emoji in the headline. H1 (digest honesty): the badge no longer reads
// "Clean run / Review / Alert" — each label calls out exactly what the
// verdict means so operators do not mistake ✅ for "every byte of egress
// observed".
func verdictBadgeText(emoji string) string {
	switch emoji {
	case "🚨":
		return "BPF failure or canary pipeline issue"
	case "⚠️":
		return "Partial observation or coverage gaps — review required"
	default:
		return "No anomalies detected (IPv4 TCP/UDP in scope)"
	}
}

// writeHeader renders the `## <emoji> coldstep — <mode>` heading and a
// descriptive verdict blockquote naming the scope of the verdict (H1).
// When partial-coverage signals fired (ringbuf drops or partial-observe
// counters), a secondary blockquote steers the reader to the Coverage
// block — the ✅ badge alone would otherwise imply complete observation.
func writeHeader(b *strings.Builder, in DigestInput) {
	mode := "detect"
	if isBlockingDigestMode(in.DefendMode) {
		mode = "defend"
	}
	emoji := verdictEmoji(in)
	fmt.Fprintf(b, "## %s coldstep — %s\n\n", emoji, mode)
	fmt.Fprintf(b, "> %s **%s**\n\n", emoji, verdictBadgeText(emoji))
	if hasPartialCoverageSignals(in) {
		b.WriteString("> ⚠️ Partial coverage — see Coverage block below.\n\n")
	}
}

// ipv6CoverageCell returns the IPv6 row text in the Coverage scope table.
// IPv6 state is per-run: defend with a populated allowed_ipv6 trie is "✓
// gated"; defend without is "✓ gated (block-all)"; detect mode is "✗ not
// observed" by default but flips to "⚠ observed (no enforcement)" when
// the cgroup/connect6+sendmsg6 hooks reported egress.
func ipv6CoverageCell(in DigestInput) string {
	switch {
	case ipv6DefendActive(in):
		return "✓ gated (defend allowed_ipv6 active)"
	case isBlockingDigestMode(in.DefendMode):
		return "✓ gated (defend block-all — empty allowed_ipv6)"
	case ipv6EgressObserved(in) > 0:
		return "⚠ observed (detect — no enforcement)"
	case in.RunnerHasIPv6:
		return "✗ not observed (runner has IPv6 — coverage gap)"
	default:
		return "✗ not observed"
	}
}

// quicCoverageCell returns the QUIC/HTTP3 row text. QUIC payloads are
// always encrypted at the transport layer so the row is structurally "✗
// not observed"; when port-443 UDP candidates were seen the cell flips to
// "⚠" so operators know flows fell into this gap on this run.
func quicCoverageCell(in DigestInput) string {
	if in.QUICCandidateCount > 0 {
		return "⚠ candidates observed (payload encrypted, not inspected)"
	}
	return "✗ not observed"
}

// ioUringCoverageCell returns the io_uring row text. The cell is "⚠
// partial" when the raw_tp/io_uring_submit_sqe probe loaded — coldstep
// observes the submission point but cannot extract HTTP/TLS payloads from
// the SQE alone. When the probe is absent or attach failed the cell reads
// "✗ not loaded".
func ioUringCoverageCell(in DigestInput) string {
	for _, row := range in.BPF {
		if row.Name == "raw_tp/io_uring_submit_sqe" {
			if !row.OK {
				return "✗ not loaded"
			}
			if strings.EqualFold(strings.TrimSpace(in.DetectProfile), "enhanced") {
				return "⚠ partial (SQE submission + TLS ClientHello peek)"
			}
			return "⚠ partial (SQE submission only)"
		}
	}
	return "✗ not loaded"
}

// ipv4TCPCoverageCell returns the IPv4 TCP row text. Cgroup connect4 is
// always loaded in detect+defend; if the shared raw_tp/sys_enter hook is
// degraded the row degrades with it because TCP attempts route through
// that path for syscall-side telemetry.
func ipv4TCPCoverageCell(in DigestInput) string {
	if in.TCPDegradedHook {
		return "✗ probe degraded"
	}
	return "✓ observed"
}

// ipv4UDPCoverageCell returns the IPv4 UDP row text — same shared
// raw_tp/sys_enter degradation rule as IPv4 TCP.
func ipv4UDPCoverageCell(in DigestInput) string {
	if in.UDPDegradedHook {
		return "✗ probe degraded"
	}
	return "✓ observed"
}

// writeCoverage emits the H1 Coverage scope table so operators see the
// observation envelope at a glance — what was in-scope, what was outside
// it. The table is rendered for every digest (detect + defend) so the
// verdict can be cross-referenced against the actually-observed traffic
// classes.
func writeCoverage(b *strings.Builder, in DigestInput) {
	b.WriteString("**Coverage scope**\n\n")
	b.WriteString("| Traffic class | Status |\n|:---|:---|\n")
	fmt.Fprintf(b, "| IPv4 TCP | %s |\n", ipv4TCPCoverageCell(in))
	fmt.Fprintf(b, "| IPv4 UDP (sendmsg) | %s |\n", ipv4UDPCoverageCell(in))
	fmt.Fprintf(b, "| IPv6 | %s |\n", ipv6CoverageCell(in))
	fmt.Fprintf(b, "| QUIC / HTTP3 | %s |\n", quicCoverageCell(in))
	fmt.Fprintf(b, "| io_uring (enhanced profile only) | %s |\n", ioUringCoverageCell(in))
	b.WriteString("| Unix sockets | ✗ not observed |\n")
	fmt.Fprintf(b, "| Payloads beyond iov[0] | %s |\n\n", coveragePayloadState(in))
}

// writeCompactKPI emits a single-row 5-column KPI table. The full per-channel
// KPI breakdown (ringbuf reserves, partial-observe counters, health rows) sits
// inside the Technical details fold instead.
func writeCompactKPI(b *strings.Builder, in DigestInput) {
	tlsCell := "—"
	if tlsKPIVisible(in) {
		tlsCell = fmt.Sprintf("%d", in.TLSTotal)
	}
	b.WriteString("| exec | tcp | udp | http | tls |\n")
	b.WriteString("|--:|--:|--:|--:|--:|\n")
	fmt.Fprintf(b, "| %d | %d | %d | %d | %s |\n\n",
		in.ExecTotal, in.TCPTotal, in.UDPTotal, in.HTTPTotal, tlsCell)
}

// writeTopDestinations emits the top-10 hot egress destinations. Hidden when
// no egress was observed.
func writeTopDestinations(b *strings.Builder, in DigestInput) {
	hot := buildHotEgressList(in)
	if len(hot) == 0 {
		return
	}
	if len(hot) > 10 {
		hot = hot[:10]
	}
	b.WriteString("### Top destinations\n\n")
	b.WriteString("| Rank | Entity | Rows | Channels |\n")
	b.WriteString("|--:|:--|--:|:--|\n")
	for i, e := range hot {
		tags := hotKindTags(e.kinds)
		if tags == "" {
			tags = "—"
		}
		fmt.Fprintf(b, "| %d | %s | %d | %s |\n",
			i+1, sanitizeCell(e.key), e.count, sanitizeCell(tags))
	}
	b.WriteString("\n")
}

// buildTriageRows returns (label, value) pairs for the compact Triage table.
// Empty rows are skipped — only signals that actually matter surface.
func buildTriageRows(in DigestInput) [][2]string {
	var rows [][2]string

	mode := "detect"
	if isBlockingDigestMode(in.DefendMode) {
		mode = "defend"
	}
	modeCell := fmt.Sprintf("`%s`", mode)
	if isBlockingDigestMode(in.DefendMode) {
		modeCell += fmt.Sprintf(" — **deny events:** %d", in.DefendDenyCount)
		if in.DefendDenyReserveFailures > 0 {
			modeCell += fmt.Sprintf(" (**+%d** deny reserve failures)", in.DefendDenyReserveFailures)
		}
	}
	rows = append(rows, [2]string{"**Mode**", modeCell})

	bpfOK := true
	var badBPF []string
	for _, row := range in.BPF {
		if !row.OK {
			bpfOK = false
			badBPF = append(badBPF, row.Name)
		}
	}
	switch {
	case len(in.BPF) == 0:
		rows = append(rows, [2]string{"**BPF hooks**", "*(no status rows)*"})
	case bpfOK:
		rows = append(rows, [2]string{"**BPF hooks**", "✅ All probes OK"})
	default:
		sort.Strings(badBPF)
		rows = append(rows, [2]string{"**BPF hooks**", fmt.Sprintf("🚨 **Review** — degraded: %s", sanitizeCell(strings.Join(badBPF, ", ")))})
	}

	if dt := droppedTotal(in); dt > 0 {
		rows = append(rows, [2]string{"**JSONL decode drops**", fmt.Sprintf("⚠️ **%d** total — see Technical details", dt)})
	}

	var gapParts []string
	gapAdd := func(label string, n int) {
		if n > 0 {
			gapParts = append(gapParts, fmt.Sprintf("%s=%d", label, n))
		}
	}
	gapAdd("connect4 map failures", in.Connect4TupleUpdateFailures)
	gapAdd("udp ringbuf reserve", in.UDPRingbufReserveFailures)
	gapAdd("dns ringbuf reserve", in.DNSRingbufReserveFailures)
	gapAdd("connect ringbuf reserve", in.ConnectRingbufReserveFailures)
	gapAdd("http ringbuf reserve", in.HTTPRingbufReserveFailures)
	gapAdd("tls ringbuf reserve", in.TLSRingbufReserveFailures)
	gapAdd("exec ringbuf reserve", in.ExecRingbufReserveFailures)
	gapAdd("fork ringbuf reserve", in.ForkRingbufReserveFailures)
	gapAdd("fs ringbuf reserve", in.FSRingbufReserveFailures)
	gapAdd("udp multi-iovec", in.UDPSendmsgMultiIovecObserved)
	gapAdd("sendmmsg multi-message", in.SendmmsgMultiMessage)
	gapAdd("sendmmsg unobserved-extra-msgs", in.SendmmsgUnobservedExtra)
	gapAdd("tls writev multi-iovec", in.TLSWritevMultiIovecObserved)
	gapAdd("sendfile partial-observe", in.SendfileObserved)
	gapAdd("splice partial-observe", in.SpliceObserved)
	gapAdd("sendmmsg first-message-only", in.SendmmsgFirstOnly)
	gapAdd("tcp dns short read", in.TCPDNSSkippedShortRead)
	gapAdd("bpf audit ringbuf reserve", in.BPFAuditRingbufReserveFailures)
	if in.IoUringSetupObserved > 0 {
		gapParts = append(gapParts, fmt.Sprintf("⚠️ io_uring_setup (syscall-hook bypass class)=%d", in.IoUringSetupObserved))
	}
	if in.IoUringSendTotal > 0 {
		gapParts = append(gapParts, fmt.Sprintf("io_uring writes=%d", in.IoUringSendTotal))
	}
	if in.IoUringTLSHelloObserved > 0 {
		gapParts = append(gapParts, fmt.Sprintf("🚨 io_uring TLS ClientHello=%d", in.IoUringTLSHelloObserved))
	}
	if !in.CanaryPipelineOK && in.CanaryFailCount > 0 {
		gapParts = append(gapParts, fmt.Sprintf("🚨 telemetry canary FAILED (failures=%d)", in.CanaryFailCount))
	}
	if len(gapParts) > 0 {
		rows = append(rows, [2]string{"**Capture gaps**", fmt.Sprintf("⚠️ %s", sanitizeCell(strings.Join(gapParts, "; ")))})
	}

	if interp := truthfulnessInterpretation(in); interp != "" {
		rows = append(rows, [2]string{"**Observability (partial / bypass-class)**", sanitizeCell(interp)})
	}

	// Gap 1+2 (sendfile/splice): when defend is on and lsm/socket_sendpage
	// fired, surface the gap-closed state explicitly so operators can see
	// that sendfile(2)/splice(2) were gated against the same IPv4 allowlist
	// even though the cgroup/sendmsg4 path missed them. In detect mode the
	// counter is informational only.
	if in.SendpageObserved > 0 {
		if isBlockingDigestMode(in.DefendMode) {
			rows = append(rows, [2]string{
				"**Sendfile/splice (sock_sendpage)**",
				fmt.Sprintf("✅ **%d** events gated by `lsm/socket_sendpage`", in.SendpageObserved),
			})
		} else {
			rows = append(rows, [2]string{
				"**Sendfile/splice (sock_sendpage)**",
				fmt.Sprintf("ℹ️ **%d** events observed via `lsm/socket_sendpage`", in.SendpageObserved),
			})
		}
	}

	// P2-1 Phase 2: surface IPv6 egress as a triage row. Three states:
	//   - detect mode: ⚠️ visibility-only (no enforcement, by design).
	//   - defend mode + allowed_ipv6 populated: ✅ gated by AAAA-resolved
	//     LPM trie; non-matches were denied with EPERM.
	//   - defend mode + allowed_ipv6 empty: 🚨 pure block-all posture —
	//     functional, but operator likely forgot to configure AAAA
	//     destinations for any service they want reachable over IPv6.
	if n := ipv6EgressObserved(in); n > 0 {
		var badge, suffix string
		switch {
		case ipv6DefendActive(in):
			badge = "✅"
			suffix = fmt.Sprintf("**gated by %d-entry allowed_ipv6 LPM trie (AAAA-resolved)**", in.DefendIPv6AllowlistSize)
		case isBlockingDigestMode(in.DefendMode):
			badge = "🚨"
			suffix = "**defend has no allowed_ipv6 entries — all non-loopback IPv6 denied (block-all). Add AAAA destinations to `allow:` if this was unintentional.**"
		default:
			badge = "⚠️"
			suffix = "detect mode — IPv6 visibility only, Phase 2 enforcement runs in defend"
		}
		rows = append(rows, [2]string{
			"**IPv6 egress detected**",
			fmt.Sprintf("%s **%d** non-loopback IPv6 destinations (connect=%d sendmsg=%d) — %s",
				badge, n, in.IPv6ConnectObserved, in.IPv6SendmsgObserved, suffix),
		})
	}

	if rb := totalDetectRingbufReserveFailures(in); rb > 0 {
		rows = append(rows, [2]string{"**Ringbuf reserve pressure (total)**", fmt.Sprintf("**%d** across detect-path channels", rb)})
	}

	return rows
}

func writeTriageTable(b *strings.Builder, in DigestInput) {
	rows := buildTriageRows(in)
	b.WriteString("### Triage\n\n")
	b.WriteString("| Signal | Detail |\n|:--|:--|\n")
	for _, r := range rows {
		fmt.Fprintf(b, "| %s | %s |\n", r[0], r[1])
	}
	b.WriteString("\n")
}

// writeFullKPITable emits the long-form per-channel KPI table that used to be
// in the main body. Now sits inside Technical details.
func writeFullKPITable(b *strings.Builder, in DigestInput) {
	b.WriteString("#### Full KPI\n\n")
	b.WriteString("| Signal | Count |\n|:--|--:|\n")
	writeDetectProfileKPI(b, in)

	// --- network ---
	fmt.Fprintf(b, "| **tcp** | %d |\n", in.TCPTotal)
	if breakdown := formatTCPResultBreakdown(in.TCPResultCounts); breakdown != "" {
		fmt.Fprintf(b, "| **TCP connections** | %s |\n", breakdown)
	}
	// P3-2b: state-machine view from tp/sock/inet_sock_set_state, complementary
	// to the P3-2 kretprobe-derived TCPResultCounts above. The state-machine
	// signal is the kernel's authoritative SYN_SENT→{ESTABLISHED, CLOSE}
	// transition; the kretprobe captures `tcp_v4_connect()`'s return value
	// (which can be 0 even when the SYN times out later). When both fire for
	// the same socket within a short window, the state-machine count wins.
	if in.TCPStateTotal > 0 {
		fmt.Fprintf(b, "| **TCP handshakes** (kernel-confirmed) | %d established / %d refused |\n",
			in.TCPStateConfirmed, in.TCPStateRefused)
	}
	if in.TCPStateRingbufReserveFailures > 0 {
		fmt.Fprintf(b, "| **tcp_state_events ringbuf reserve failures** | %d |\n", in.TCPStateRingbufReserveFailures)
	}
	if in.TCPStateReaderErrors > 0 {
		fmt.Fprintf(b, "| **tcp_state_events reader errors** | %d |\n", in.TCPStateReaderErrors)
	}
	if in.Connect4TupleUpdateFailures > 0 {
		fmt.Fprintf(b, "| **connect4 (tgid,fd)→tuple map update failures** | %d |\n", in.Connect4TupleUpdateFailures)
	}
	if in.ConnectRingbufReserveFailures > 0 {
		fmt.Fprintf(b, "| **connect_events ringbuf reserve failures** | %d |\n", in.ConnectRingbufReserveFailures)
	}
	if in.DNSRingbufReserveFailures > 0 {
		fmt.Fprintf(b, "| **dns_events ringbuf reserve failures** | %d |\n", in.DNSRingbufReserveFailures)
	}
	if in.TCPDNSResponsesObserved > 0 {
		fmt.Fprintf(b, "| **TCP DNS responses observed** | %d |\n", in.TCPDNSResponsesObserved)
	}
	if in.TCPDNSSkippedShortRead > 0 {
		fmt.Fprintf(b, "| **TCP DNS short reads (<6 B)** | %d |\n", in.TCPDNSSkippedShortRead)
	}

	fmt.Fprintf(b, "| **udp** | %d |\n", in.UDPTotal)
	if in.UDPRingbufReserveFailures > 0 {
		fmt.Fprintf(b, "| **udp_events ringbuf reserve failures** | %d |\n", in.UDPRingbufReserveFailures)
	}
	if in.UDPSendmsgMultiIovecObserved > 0 {
		fmt.Fprintf(b, "| **udp_sendmsg multi-iovec calls (iov[1..n] not captured)** | %d |\n", in.UDPSendmsgMultiIovecObserved)
	}
	if in.SendmmsgMultiMessage > 0 {
		fmt.Fprintf(b, "| **sendmmsg multi-message calls (msg[1..n] not introspected)** | %d |\n", in.SendmmsgMultiMessage)
	}
	if in.SendmmsgUnobservedExtra > 0 {
		fmt.Fprintf(b, "| **sendmmsg extra messages dropped past unroll bound (vlen>8)** | %d |\n", in.SendmmsgUnobservedExtra)
	}
	if in.QUICCandidateCount > 0 {
		fmt.Fprintf(b, "| **QUIC (port-443 UDP)** | %d flows · payload not inspected |\n", in.QUICCandidateCount)
	}

	fmt.Fprintf(b, "| **http** | %d |\n", in.HTTPTotal)
	if in.HTTPRingbufReserveFailures > 0 {
		fmt.Fprintf(b, "| **http_events ringbuf reserve failures** | %d |\n", in.HTTPRingbufReserveFailures)
	}

	if tlsKPIVisible(in) {
		fmt.Fprintf(b, "| **tls** | %d |\n", in.TLSTotal)
		if in.TLSTotal > 0 {
			fmt.Fprintf(b, "| **tls SNI confidence** | %s |\n", formatTLSConfidenceCell(in))
		}
		if in.TLSRingbufReserveFailures > 0 {
			fmt.Fprintf(b, "| **tls_events ringbuf reserve failures** | %d |\n", in.TLSRingbufReserveFailures)
		}
		if in.TLSWritevMultiIovecObserved > 0 {
			fmt.Fprintf(b, "| **tls writev multi-iovec calls (iov[1..n] not captured)** | %d |\n", in.TLSWritevMultiIovecObserved)
		}
	}

	if in.KTLSOffloadTotal > 0 {
		fmt.Fprintf(b, "| **KTLS offload** | %d sockets · SNI extraction not possible |\n", in.KTLSOffloadTotal)
	}
	if in.KTLSRingbufReserveFailures > 0 {
		fmt.Fprintf(b, "| **ktls_events ringbuf reserve failures** | %d |\n", in.KTLSRingbufReserveFailures)
	}

	if in.SendfileObserved > 0 {
		fmt.Fprintf(b, "| **sendfile partial-observe (dest+len, no payload sniff)** | %d |\n", in.SendfileObserved)
	}
	if in.SpliceObserved > 0 {
		fmt.Fprintf(b, "| **splice partial-observe (dest+len, no payload sniff)** | %d |\n", in.SpliceObserved)
	}
	if in.SendmmsgFirstOnly > 0 {
		fmt.Fprintf(b, "| **sendmmsg first-message-only (msgs 2..N not introspected)** | %d |\n", in.SendmmsgFirstOnly)
	}
	if in.SendpageObserved > 0 {
		label := "**lsm/socket_sendpage events (sendfile/splice path)**"
		if isBlockingDigestMode(in.DefendMode) {
			label = "**✅ lsm/socket_sendpage events gated (sendfile/splice closed)**"
		}
		fmt.Fprintf(b, "| %s | %d |\n", label, in.SendpageObserved)
	}
	if in.IoUringSetupObserved > 0 {
		fmt.Fprintf(b, "| **⚠️ io_uring_setup (syscall-hook bypass class)** | %d |\n", in.IoUringSetupObserved)
	}
	if in.IoUringSendTotal > 0 {
		fmt.Fprintf(b, "| **io_uring writes** | %d network sends observed (SNI extraction not possible) |\n", in.IoUringSendTotal)
	}
	if in.IoUringTLSHelloObserved > 0 {
		fmt.Fprintf(b, "| **🚨 io_uring TLS ClientHello prefixes** | %d submissions matched TLS 1.x record signature (enhanced profile peek) |\n", in.IoUringTLSHelloObserved)
	}
	if in.IoUringRingbufReserveFailures > 0 {
		fmt.Fprintf(b, "| **io_uring_events ringbuf reserve failures** | %d |\n", in.IoUringRingbufReserveFailures)
	}
	if in.IPv6ConnectObserved > 0 {
		label := "**⚠️ ipv6 connect6 observed (detect — no enforcement)**"
		if ipv6DefendActive(in) {
			label = "**✅ ipv6 connect6 gated by allowed_ipv6**"
		} else if isBlockingDigestMode(in.DefendMode) {
			label = "**🚨 ipv6 connect6 denied (defend has empty allowed_ipv6 — block-all)**"
		}
		fmt.Fprintf(b, "| %s | %d |\n", label, in.IPv6ConnectObserved)
	}
	if in.IPv6SendmsgObserved > 0 {
		label := "**⚠️ ipv6 sendmsg6 observed (detect — no enforcement)**"
		if ipv6DefendActive(in) {
			label = "**✅ ipv6 sendmsg6 gated by allowed_ipv6**"
		} else if isBlockingDigestMode(in.DefendMode) {
			label = "**🚨 ipv6 sendmsg6 denied (defend has empty allowed_ipv6 — block-all)**"
		}
		fmt.Fprintf(b, "| %s | %d |\n", label, in.IPv6SendmsgObserved)
	}

	// --- processes ---
	fmt.Fprintf(b, "| **exec** | %d |\n", in.ExecTotal)
	if in.ExecRingbufReserveFailures > 0 {
		fmt.Fprintf(b, "| **exec_events ringbuf reserve failures** | %d |\n", in.ExecRingbufReserveFailures)
	}
	if procForkKPIVisible(in) {
		fmt.Fprintf(b, "| **proc_fork** | %d |\n", in.ProcForkTotal)
		if in.ForkRingbufReserveFailures > 0 {
			fmt.Fprintf(b, "| **proc_fork_events ringbuf reserve failures** | %d |\n", in.ForkRingbufReserveFailures)
		}
	}
	if in.BPFAuditTotal > 0 {
		fmt.Fprintf(b, "| **bpf_audit** | %d |\n", in.BPFAuditTotal)
	}
	if in.BPFAuditRingbufReserveFailures > 0 {
		fmt.Fprintf(b, "| **bpf_audit_events ringbuf reserve failures** | %d |\n", in.BPFAuditRingbufReserveFailures)
	}

	// --- filesystem ---
	if fsKPIVisible(in) {
		fmt.Fprintf(b, "| **fs_event** | %d |\n", in.FSTotal)
		if in.FSRingbufReserveFailures > 0 {
			fmt.Fprintf(b, "| **fs_events ringbuf reserve failures** | %d |\n", in.FSRingbufReserveFailures)
		}
	}

	if dt := droppedTotal(in); dt > 0 {
		fmt.Fprintf(b, "| **dropped events (decode/jsonl)** | %d |\n", dt)
	}
	if rb := totalDetectRingbufReserveFailures(in); rb > 0 {
		fmt.Fprintf(b, "| **⚠️ Dropped events (ringbuf overflow)** | %d |\n", rb)
	}

	// --- health (last) ---
	if in.BPFMapIntegrityFailures > 0 {
		fmt.Fprintf(b, "| **bpf_map_integrity_failures** | **%d** |\n", in.BPFMapIntegrityFailures)
	}
	if in.CanaryFailCount > 0 {
		status := "✅ OK"
		if !in.CanaryPipelineOK {
			status = "🚨 FAILED"
		}
		fmt.Fprintf(b, "| **Telemetry integrity canary** | %s (failures=%d) |\n", status, in.CanaryFailCount)
	} else {
		b.WriteString("| **Telemetry integrity canary** | ✅ OK |\n")
	}
	if in.BPFHeartbeatFailures > 0 {
		fmt.Fprintf(b, "| **🚨 BPF Self-protection Heartbeat Failures** | %d |\n", in.BPFHeartbeatFailures)
	} else {
		b.WriteString("| **BPF Self-protection Heartbeat** | ✅ OK |\n")
	}
	b.WriteString("\n")
}

func writeDetectProfileKPI(b *strings.Builder, in DigestInput) {
	dp := strings.ToLower(strings.TrimSpace(in.DetectProfile))
	if dp == "" {
		dp = "standard"
	}
	if dp == "enhanced" {
		b.WriteString("| **detect profile** | **enhanced** — default gates `proc_tree` · `tls_sni` · `fs_events`; stricter report integrity |\n")
		return
	}
	b.WriteString("| **detect profile** | standard |\n")
}

// writeRollups emits the policy-classification and dropped-event rollup lines.
func writeRollups(b *strings.Builder, in DigestInput) {
	if len(in.PolicyCounts) > 0 {
		rollupLabel := "TCP / UDP / HTTP classification"
		if tlsKPIVisible(in) {
			rollupLabel = "TCP / UDP / HTTP / TLS classification"
		}
		b.WriteString("**Policy rollups** (" + rollupLabel + "): ")
		type kv struct {
			k string
			v int
		}
		var list []kv
		for k, v := range in.PolicyCounts {
			list = append(list, kv{k, v})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].v != list[j].v {
				return list[i].v > list[j].v
			}
			return list[i].k < list[j].k
		})
		parts := make([]string, 0, len(list))
		for _, e := range list {
			parts = append(parts, fmt.Sprintf("`%s`=%d", sanitizeCell(e.k), e.v))
		}
		b.WriteString(strings.Join(parts, " · "))
		b.WriteString("\n\n")
	}

	if dt := droppedTotal(in); dt > 0 {
		b.WriteString("**Dropped event counters**: ")
		type kv struct {
			k string
			v int
		}
		var list []kv
		for k, v := range in.DroppedCounts {
			if v <= 0 {
				continue
			}
			list = append(list, kv{k, v})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].v != list[j].v {
				return list[i].v > list[j].v
			}
			return list[i].k < list[j].k
		})
		parts := make([]string, 0, len(list))
		for _, e := range list {
			parts = append(parts, fmt.Sprintf("`%s`=%d", sanitizeCell(e.k), e.v))
		}
		b.WriteString(strings.Join(parts, " · "))
		b.WriteString("\n\n")
	}
}

// writeDefendDetails emits the defend section (allowlist size, deny count,
// first deny row) inside Technical details when defend was active.
func writeDefendDetails(b *strings.Builder, in DigestInput) {
	if in.DefendMode == "" && in.DefendAllowlistSize == 0 && in.DefendDenyCount == 0 &&
		in.DefendDenyReserveFailures == 0 && in.DefendFirstDeny == nil {
		return
	}
	b.WriteString("#### Defend\n\n")
	b.WriteString("| Field | Value |\n|:--|:--|\n")
	mode := digestModeCell(in.DefendMode)
	fmt.Fprintf(b, "| Mode | `%s` |\n", sanitizeCell(mode))
	fmt.Fprintf(b, "| Allowlist size | %d |\n", in.DefendAllowlistSize)
	fmt.Fprintf(b, "| Deny count | %d |\n", in.DefendDenyCount)
	if in.DefendDenyReserveFailures > 0 {
		fmt.Fprintf(b, "| Deny ringbuf reserve failures (blocked, no JSONL) | %d |\n", in.DefendDenyReserveFailures)
	}
	b.WriteString("\n")

	if in.DefendFirstDeny != nil {
		row := in.DefendFirstDeny
		b.WriteString("**First deny**\n\n")
		b.WriteString("| Time (UTC) | PID | Comm | Protocol | Remote | Reason |\n|:--|--:|:-|:-|:-|:-|\n")
		fmt.Fprintf(b, "| %s | `%d` | `%s` | `%s` | `%s:%d` | `%s` |\n\n",
			sanitizeCell(row.TS),
			row.PID,
			sanitizeCell(row.Comm),
			sanitizeCell(row.Protocol),
			sanitizeCell(row.Dst),
			row.Dport,
			sanitizeCell(row.Reason),
		)
	}
}

func writeRunInfo(b *strings.Builder, in DigestInput) {
	if in.JSONLPath == "" && (in.SeqFirst == 0 || in.SeqLast < in.SeqFirst) {
		return
	}
	b.WriteString("#### Run info\n\n")
	b.WriteString("| Field | Value |\n|:--|:--|\n")
	if in.JSONLPath != "" {
		fmt.Fprintf(b, "| **Canonical log (JSONL)** | `%s` |\n", sanitizeCell(in.JSONLPath))
	}
	if in.SeqFirst > 0 && in.SeqLast >= in.SeqFirst {
		fmt.Fprintf(b, "| **Event sequence range (userspace)** | %d–%d |\n", in.SeqFirst, in.SeqLast)
	}
	b.WriteString("\n")
}

// writeEventTables emits per-protocol row tables inside Technical details.
// Each protocol gets its own nested <details> so operators can drill in without
// scrolling past every event type when only one is interesting.
func writeEventTables(b *strings.Builder, in DigestInput, max int) {
	writeExecSection(b, in)
	writeBPFAuditSection(b, in)
	writeProcessTreeSection(b, in)
	writeTCPSection(b, in)
	writeUDPSection(b, in)
	writeHTTPSection(b, in)
	writeTLSSection(b, in)
	writeFSSection(b, in, max)
}

func writeExecSection(b *strings.Builder, in DigestInput) {
	b.WriteString("<details>\n<summary><strong>Exec (recent)</strong></summary>\n\n")
	b.WriteString("| Time (UTC) | PID (TGID) | TID | Comm | Executable (BPF-capped) |\n|:--|--:|--:|:-|:-|\n")
	for _, r := range in.ExecRows {
		fmt.Fprintf(b, "| %s | `%d` | `%d` | `%s` | `%s` |\n",
			sanitizeCell(r.TS), r.PID, r.ThreadID, sanitizeCell(r.Comm), sanitizeCell(r.Exe))
	}
	b.WriteString("\n</details>\n\n")
}

func writeProcessTreeSection(b *strings.Builder, in DigestInput) {
	if !procForkKPIVisible(in) {
		return
	}
	b.WriteString("<details>\n<summary><strong>Process tree (recent)</strong></summary>\n\n")
	b.WriteString("| Outline |\n|:-|\n")
	if len(in.ProcessTreeLines) == 0 {
		fmt.Fprintf(b, "| %s |\n", sanitizeCell(protocolEmptyReason(in.ProcForkDegraded, in.ProcForkReaderErrors)))
	} else {
		for _, line := range in.ProcessTreeLines {
			fmt.Fprintf(b, "| %s |\n", sanitizeCell(line))
		}
	}
	b.WriteString("\n</details>\n\n")
}

func writeTCPSection(b *strings.Builder, in DigestInput) {
	b.WriteString("<details>\n<summary><strong>TCP connect attempts (recent)</strong></summary>\n\n")
	b.WriteString("| Time (UTC) | PID | Comm | Remote | Notes | Policy |\n|:--|--:|:-|:-|:-|:-|\n")
	if len(in.TCPRows) == 0 {
		fmt.Fprintf(b, "| — | — | — | — | — | %s |\n", sanitizeCell(protocolEmptyReason(in.TCPDegradedHook, in.TCPReaderErrors)))
	} else {
		for _, r := range in.TCPRows {
			fmt.Fprintf(b, "| %s | `%d` | `%s` | %s | %s | %s |\n",
				sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm),
				sanitizeCell(r.Remote), sanitizeCell(r.Notes), sanitizeCell(r.Policy))
		}
	}
	b.WriteString("\n</details>\n\n")
}

func writeUDPSection(b *strings.Builder, in DigestInput) {
	b.WriteString("<details>\n<summary><strong>UDP sendto (recent)</strong></summary>\n\n")
	b.WriteString("| Time (UTC) | PID | Comm | Remote | Len | FQDN | Policy |\n|:--|--:|:-|:-|--:|:-|:-|\n")
	if len(in.UDPRows) == 0 {
		fmt.Fprintf(b, "| — | — | — | — | — | — | %s |\n", sanitizeCell(protocolEmptyReason(in.UDPDegradedHook, in.UDPReaderErrors)))
	} else {
		for _, r := range in.UDPRows {
			fq := r.FQDN
			if fq == "" {
				fq = "—"
			}
			fmt.Fprintf(b, "| %s | `%d` | `%s` | %s | %d | %s | %s |\n",
				sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm),
				sanitizeCell(r.Remote), r.DgramLen, sanitizeCell(fq), sanitizeCell(r.Policy))
		}
	}
	b.WriteString("\n</details>\n\n")
}

func writeHTTPSection(b *strings.Builder, in DigestInput) {
	b.WriteString("<details>\n<summary><strong>HTTP/1 cleartext (recent)</strong></summary>\n\n")
	b.WriteString("| Time (UTC) | PID | Comm | Method | Host | Path (summary) | Remote | Policy |\n|:--|--:|:-|:-|:-|:-|:-|:-|\n")
	if len(in.HTTPRows) == 0 {
		fmt.Fprintf(b, "| — | — | — | — | — | — | — | %s |\n", sanitizeCell(protocolEmptyReason(in.HTTPDegradedHook, in.HTTPReaderErrors)))
	} else {
		for _, r := range in.HTTPRows {
			fmt.Fprintf(b, "| %s | `%d` | `%s` | `%s` | `%s` | `%s` | %s | %s |\n",
				sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm),
				sanitizeCell(r.Method), sanitizeCell(r.Host), sanitizeCell(r.Path),
				sanitizeCell(r.Remote), sanitizeCell(r.Policy))
		}
	}
	b.WriteString("\n</details>\n\n")
}

func writeTLSSection(b *strings.Builder, in DigestInput) {
	if !tlsKPIVisible(in) {
		return
	}
	b.WriteString("<details>\n<summary><strong>TLS ClientHello / SNI (recent)</strong></summary>\n\n")
	b.WriteString("| Time (UTC) | PID | Comm | SNI | Remote | Policy | Confidence |\n|:--|--:|:-|:-|:-|:-|:-|\n")
	if len(in.TLSRows) == 0 {
		fmt.Fprintf(b, "| — | — | — | — | — | %s | — |\n", sanitizeCell(protocolEmptyReason(in.TLSDegradedHook, in.TLSReaderErrors)))
	} else {
		for _, r := range in.TLSRows {
			conf := string(r.Confidence)
			if conf == "" {
				conf = string(telemetry.TLSConfidenceUnknown)
			}
			if r.ConfidenceReason == "ktls" {
				// P4: keep the machine-readable confidence in backticks but tack on a
				// human "⚠ ktls" suffix so the per-row cell signals "unknown because
				// kernel-TLS structurally hides the SNI" rather than "unknown because
				// parse failed".
				conf = conf + " ⚠ ktls"
			}
			fmt.Fprintf(b, "| %s | `%d` | `%s` | `%s` | %s | %s | `%s` |\n",
				sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm),
				sanitizeCell(r.SNI), sanitizeCell(r.Remote), sanitizeCell(r.Policy),
				sanitizeCell(conf))
		}
	}
	b.WriteString("\n</details>\n\n")
}

func writeFSSection(b *strings.Builder, in DigestInput, _ int) {
	if !in.FSGate {
		return
	}
	b.WriteString("<details>\n<summary><strong>Filesystem (recent)</strong></summary>\n\n")
	b.WriteString("| Time | PID | Comm | Op | Path |\n|:--|--:|:--|:--|:--|\n")
	if len(in.FSRows) == 0 {
		reason := "no events"
		if in.FSDegradedHook {
			reason = "degraded hook"
		} else if in.FSReaderErrors > 0 {
			reason = fmt.Sprintf("reader errors (%d)", in.FSReaderErrors)
		}
		fmt.Fprintf(b, "| — | — | — | — | %s |\n", reason)
	} else {
		for _, r := range in.FSRows {
			fmt.Fprintf(b, "| `%s` | %d | `%s` | `%s` | `%s` |\n",
				sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm), sanitizeCell(r.Op), sanitizeCell(r.Path))
		}
		if in.TruncatedFS {
			fmt.Fprintf(b, "\n*Showing last %d of %d — full stream in JSONL.*\n",
				len(in.FSRows), in.FSTotal)
		}
	}
	b.WriteString("\n</details>\n\n")
}

func writeBPFAuditSection(b *strings.Builder, in DigestInput) {
	if in.BPFAuditTotal == 0 && !in.BPFAuditDegradedHook && in.BPFAuditReaderErrors == 0 {
		return
	}
	b.WriteString("<details>\n<summary><strong>BPF audit (recent)</strong></summary>\n\n")
	b.WriteString("| Time (UTC) | PID | Comm | Command |\n|:--|--:|:-|:-|\n")
	if len(in.BPFAuditRows) == 0 {
		reason := "no events"
		if in.BPFAuditDegradedHook {
			reason = "degraded hook"
		} else if in.BPFAuditReaderErrors > 0 {
			reason = fmt.Sprintf("reader errors (%d)", in.BPFAuditReaderErrors)
		}
		fmt.Fprintf(b, "| — | — | — | %s |\n", reason)
	} else {
		for _, r := range in.BPFAuditRows {
			fmt.Fprintf(b, "| %s | `%d` | `%s` | `%s` (%d) |\n",
				sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm), sanitizeCell(BPFCmdName(r.Cmd)), r.Cmd)
		}
		if in.TruncatedBPFAudit {
			fmt.Fprintf(b, "\n*Showing last %d of %d — full stream in JSONL.*\n",
				len(in.BPFAuditRows), in.BPFAuditTotal)
		}
	}
	b.WriteString("\n</details>\n\n")
}

// writeBPFHookStatusTable lists every BPF probe and its load status.
func writeBPFHookStatusTable(b *strings.Builder, in DigestInput) {
	if len(in.BPF) == 0 {
		return
	}
	b.WriteString("#### BPF hook status\n\n")
	b.WriteString("| BPF hook | Status |\n|:--|:--|\n")
	for _, row := range in.BPF {
		st := "ok"
		if !row.OK {
			st = "skipped/degraded"
		}
		detail := ""
		if row.Detail != "" {
			detail = " — " + sanitizeCell(row.Detail)
		}
		fmt.Fprintf(b, "| `%s` | %s%s |\n", sanitizeCell(row.Name), st, detail)
	}
	b.WriteString("\n")
}

// writeKPISemantics emits the long-form KPI prose (truncation note, TCP/TLS
// caveats, etc.) as a bulleted list.
func writeKPISemantics(b *strings.Builder, in DigestInput, max int) {
	b.WriteString("#### Notes\n\n")
	b.WriteString("- **UDP KPI** counts IPv4 `sendto` and `sendmsg` egress (first iovec length; destination from `msg_name` or connected-socket cache).\n")
	b.WriteString("- **HTTP KPI** counts cleartext HTTP/1 request bytes on `sendto` to destination port 80 only; HTTPS traffic appears as TCP connect events.\n")
	if tlsKPIVisible(in) {
		b.WriteString("- **tls KPI** counts ClientHello **SNI** parsed from the first cleartext handshake buffer on `write`/`writev`/`pwrite`/`pwritev`/`pwritev2`/`sendto` paths after an IPv4 `connect` when `COLDSTEP_FEATURE_GATES=tls_sni=1` (not decrypted TLS).\n")
		if in.TLSTotal > 0 {
			b.WriteString("- **tls SNI confidence** reason codes (rolled up in the KPI and shown per-row in the TLS table):\n")
			b.WriteString("    - `full` — complete ClientHello parsed in a single syscall buffer; SNI is below the RFC 1035 server-name boundary and not truncated.\n")
			b.WriteString("    - `partial` — SNI length hit the capture/RFC boundary (`TLSSNIMaxLen=255`); the captured name may be a prefix of the real server name (fragmented or truncated ClientHello).\n")
			b.WriteString("    - `inferred` — SNI inferred from prior DNS / connect correlation rather than parsed directly. Reserved for a future enricher and not currently emitted by the BPF path.\n")
			b.WriteString("    - `unknown` — TLS framing detected but no usable SNI signal was captured.\n")
			if in.TLSConfidenceUnknownKTLS > 0 {
				// P4: kernel-TLS offload is a structural reason the SNI sniffer cannot
				// resolve a server name. Surface it inside the technical-details fold
				// so operators reading the digest know why the `unknown` bucket grew
				// and where to cross-reference the affected sockets in the JSONL.
				fmt.Fprintf(b, "- **KTLS-offloaded sockets** (%d detected): kernel TLS offload was active on these sockets. After `setsockopt(SOL_TLS, TLS_TX/RX)`, write syscalls carry ciphertext; SNI extraction is structurally impossible. These connections appear in the `unknown` confidence bucket. The `ktls_offload` events in the JSONL record the exact socket `(pid, fd)` for cross-reference.\n", in.TLSConfidenceUnknownKTLS)
			}
		}
	}
	if in.KTLSOffloadTotal > 0 {
		b.WriteString("- **KTLS offload** counts sockets where the application called `setsockopt(SOL_TLS, TLS_TX|TLS_RX)` to hand TLS encryption to the kernel. After offload the application writes plaintext while the kernel encrypts on the wire, so the userspace ClientHello sniffer on `write`/`writev`/`sendto` paths only observes ciphertext record fragments and **cannot resolve SNI** on those sockets. Affected egress still appears as TCP connect events (destination IP + port) — only the SNI hint is lost.\n")
	}
	if in.TLSTotal > 0 {
		b.WriteString("\n> **TLS 1.3 Encrypted ClientHello (ECH):** When ECH is active, the real server name is encrypted in transit and only the outer (CDN/proxy) SNI is visible to network-layer observers, including this agent. Connections to ECH-enabled endpoints appear with the outer SNI (e.g., `cloudflare-ech.com`) rather than the true destination. This is a deliberate TLS privacy feature and cannot be resolved by BPF-level inspection. Cross-reference DNS HTTPS records or application-level logs for the true destination.\n\n")
	}
	if procForkKPIVisible(in) {
		b.WriteString("- **proc_fork** counts `sched_process_fork` events (best-effort parent/child lineage).\n")
	}
	if fsKPIVisible(in) {
		b.WriteString("- **fs_event KPI** counts high-signal filesystem operations (create, unlink, rename, chmod) observed via `openat`/`unlinkat`/`renameat2`/`fchmodat` syscalls when `COLDSTEP_FEATURE_GATES=fs_events=1`.\n")
	}
	if in.Connect4TupleUpdateFailures > 0 {
		b.WriteString("- **connect4 map failures** indicate BPF could not insert some `(tgid,fd)→tuple` entries (hash pressure); TCP connect ringbuf events are unchanged, but TLS ClientHello correlation may degrade.\n")
	}
	if in.UDPRingbufReserveFailures > 0 {
		b.WriteString("- **udp_events** reserve failures indicate ringbuf pressure; some UDP egress may be unobserved.\n")
	}
	if in.DNSRingbufReserveFailures > 0 {
		b.WriteString("- **dns_events** reserve failures indicate ringbuf pressure; some DNS reply telemetry may be missed.\n")
	}
	if in.ConnectRingbufReserveFailures > 0 {
		b.WriteString("- **connect_events** reserve failures indicate ringbuf pressure; some TCP connect telemetry may be missed.\n")
	}
	if in.HTTPRingbufReserveFailures > 0 {
		b.WriteString("- **http_events** reserve failures indicate ringbuf pressure; some cleartext HTTP telemetry may be missed.\n")
	}
	if in.TLSRingbufReserveFailures > 0 {
		b.WriteString("- **tls_events** reserve failures indicate ringbuf pressure; some TLS/SNI telemetry may be missed.\n")
	}
	if in.ExecRingbufReserveFailures > 0 {
		b.WriteString("- **exec_events** reserve failures indicate ringbuf pressure; some exec telemetry may be missed.\n")
	}
	if in.ForkRingbufReserveFailures > 0 {
		b.WriteString("- **proc_fork_events** reserve failures indicate ringbuf pressure; some fork/process-tree telemetry may be missed.\n")
	}
	if in.FSRingbufReserveFailures > 0 {
		b.WriteString("- **fs_events** reserve failures indicate ringbuf pressure; some filesystem telemetry may be missed.\n")
	}
	if in.UDPSendmsgMultiIovecObserved > 0 || in.TLSWritevMultiIovecObserved > 0 {
		b.WriteString("- **multi-iovec** counters surface scatter/gather syscalls (`sendmsg`/`writev` with `iovlen>1`); only the first iovec is captured by the BPF probe.\n")
	}
	if in.SendmmsgMultiMessage > 0 {
		b.WriteString("- **sendmmsg multi-message** counts `sendmmsg(2)` calls with `vlen>1` (multi-message batch); only the first `mmsghdr` is introspected today.\n")
	}
	if in.QUICCandidateCount > 0 {
		b.WriteString("- **QUIC (port-443 UDP)** counts UDP egress to non-loopback IPv4 on port 443 — a heuristic for QUIC/HTTP3 flows. Payload content is encrypted at the transport layer and **not inspected** by the BPF probes; the JSONL `quic_candidate` event records pid, comm, and destination only. Use this to gauge how much of the run is invisible to HTTP/TLS sniff paths.\n")
	}
	if in.SendfileObserved > 0 || in.SpliceObserved > 0 || in.SendmmsgFirstOnly > 0 {
		b.WriteString("- **sendfile / splice / sendmmsg partial-observe** counters (BG-01) name the IPv4-egress paths that emit destination/length telemetry but no HTTP/TLS payload sniff: `sendfile`/`splice` correlate destination via the cached `(tgid,fd)→tuple` map, and `sendmmsg` introspects only the first `mmsghdr` (messages 2..N are dropped). Per-path counts let operators see which arm drove the gap. Under **defend**, cgroup/LSM hooks may still apply to the underlying socket; under **detect**, this is visibility-only.\n")
	}
	if in.IoUringSetupObserved > 0 {
		b.WriteString("- **⚠️ io_uring_setup** was called on this runner — io_uring can bypass typical syscall tracepoints used for detect mode. If `io-uring-disable` is true (default), the setup call was blocked by sysctl; this counter still records the attempt. See SECURITY.md (Guarantees vs best-effort).\n")
	}
	if in.IoUringSendTotal > 0 {
		b.WriteString("- **io_uring writes** counts socket-class SQE submissions (`IORING_OP_SENDMSG`, `IORING_OP_SEND`) seen via `raw_tp/io_uring_submit_sqe`. SNI / HTTP payloads are not captured from the submission point alone.\n")
	}
	if in.IoUringTLSHelloObserved > 0 {
		b.WriteString("- **🚨 io_uring TLS ClientHello** counts SQE submissions whose user-space buffer prefix matched the TLS record signature (`0x16 0x03 <=0x04 _ _ 0x01`) via a bounded `bpf_probe_read_user` peek (P6 Phase 2, enhanced profile only). The 6-byte signature has effectively zero collision rate against random data — non-zero is strong evidence that the io_uring bypass path is being used to initiate outbound TLS handshakes that escape syscall-based hooks. SNI is still not captured; identifying the destination requires correlating the surrounding `connect`/`tcp_state` rows.\n")
	}
	if ipv6EgressObserved(in) > 0 {
		switch {
		case ipv6DefendActive(in):
			fmt.Fprintf(b, "- **✅ IPv6 egress** observed and gated by the `cgroup/connect6` + `cgroup/sendmsg6` defend hooks against the `allowed_ipv6` LPM trie (%d AAAA-resolved entries). `::1` (loopback) and `fe80::/10` (link-local) bypass the lookup.\n", in.DefendIPv6AllowlistSize)
		case isBlockingDigestMode(in.DefendMode):
			b.WriteString("- **🚨 IPv6 egress** observed under defend mode with an empty `allowed_ipv6` LPM trie — every non-loopback / non-link-local IPv6 destination was denied (block-all). If any of these were legitimate, add the relevant AAAA hostnames to `allow:` so the next run programs the LPM trie.\n")
		default:
			b.WriteString("- **⚠️ IPv6 egress** observed in detect mode. coldstep records the attempts here; switching to `mode: defend` activates the Phase 2 `cgroup/connect6` + `cgroup/sendmsg6` LPM-trie enforcement.\n")
		}
	}
	if in.TCPDNSSkippedShortRead > 0 {
		b.WriteString("- **TCP DNS short reads** counts TCP `read(2)` returns shorter than 6 bytes on the traced DNS path (cannot validate the RFC 1035 length prefix plus DNS header); segmented large replies may increment this without full stream reassembly.\n")
	}

	var trunc []string
	if in.TruncatedExec {
		trunc = append(trunc, "exec")
	}
	if in.TruncatedTCP {
		trunc = append(trunc, "tcp")
	}
	if in.TruncatedUDP {
		trunc = append(trunc, "udp")
	}
	if in.TruncatedHTTP {
		trunc = append(trunc, "http")
	}
	if in.TruncatedTLS {
		trunc = append(trunc, "tls")
	}
	if in.TruncatedProcessTree {
		trunc = append(trunc, "proc_fork")
	}
	if in.TruncatedFS {
		trunc = append(trunc, "fs_event")
	}
	if len(trunc) > 0 {
		fmt.Fprintf(b, "- **Truncated sections:** %s — showing up to **%d** newest rows per section; totals in KPI are full counts.\n",
			strings.Join(trunc, ", "), max)
	} else {
		fmt.Fprintf(b, "- **Row cap:** up to **%d** rows per section when activity exceeds the cap.\n", max)
	}
	if hasTCPResultBreakdown(in.TCPResultCounts) {
		b.WriteString("- **TCP semantics:** rows reflect `connect(2)` attempts at syscall enter; the **TCP connections** KPI splits them by `tcp_v4_connect` return code (paired kprobe/kretprobe), so established / refused / timeout / unreachable are distinguishable.\n")
	} else {
		b.WriteString("- **TCP semantics:** rows reflect `connect(2)` attempts at syscall enter, not confirmed established sockets (kretprobe on `tcp_v4_connect` failed to attach — see BPF hook status).\n")
	}
	if tlsKPIVisible(in) {
		b.WriteString("- **TLS / SNI:** rows come from the first ClientHello-shaped buffer on supported `write`/`writev`/`pwrite`/`pwritev`/`pwritev2`/connected or explicit-`sockaddr` `sendto` paths after an IPv4 `connect` on the same fd; fragmented ClientHello or `sendmsg`-only stacks may not produce a row.\n")
	} else {
		b.WriteString("- **HTTPS:** TLS payloads are not decrypted; enable `tls_sni=1` in `COLDSTEP_FEATURE_GATES` for optional ClientHello SNI hints.\n")
	}
	if procForkKPIVisible(in) {
		b.WriteString("- **Process tree:** parent/child IDs come from `sched_process_fork`; correlation with TGID/exec is best-effort on shared runners.\n")
	}
	b.WriteString("\n")
}

func writeTechnicalDetails(b *strings.Builder, in DigestInput, max int) {
	b.WriteString("<details>\n<summary>Technical details — full KPI, event rows, BPF status, notes</summary>\n\n")
	writeFullKPITable(b, in)
	writeRollups(b, in)
	writeDefendDetails(b, in)
	writeRunInfo(b, in)
	writeEventTables(b, in, max)
	writeBPFHookStatusTable(b, in)
	writeKPISemantics(b, in, max)
	b.WriteString("</details>\n\n")
}

func writeFooter(b *strings.Builder, in DigestInput) {
	path := in.JSONLPath
	if path == "" {
		path = ".coldstep-events.jsonl"
	}
	fmt.Fprintf(b, "> Full event log: `%s`\n", sanitizeCell(path))
}

// writeAllowlistTrust emits P1-1 / H9 (DNS Allowlist Trust Model hardening)
// surface: unresolved allowlist domains (defend-mode warning), high-risk
// wildcard CDN entries, a TTL-staleness warning when the compile is more than
// allowlistStaleThreshold old, and a fixed-at-startup entry-count note (H12).
// The section is skipped when there is nothing to show.
func writeAllowlistTrust(b *strings.Builder, in DigestInput) {
	hasUnresolved := isBlockingDigestMode(in.DefendMode) && len(in.UnresolvedAllowlistDomains) > 0
	hasWildcard := len(in.WildcardRiskDomains) > 0
	staleAge := time.Duration(0)
	if !in.AllowlistCompileTime.IsZero() {
		if age := time.Since(in.AllowlistCompileTime); age > allowlistStaleThreshold {
			staleAge = age
		}
	}
	hasStale := staleAge > 0
	hasEntryCount := in.AllowlistEntryCount > 0 && isBlockingDigestMode(in.DefendMode)
	if !hasUnresolved && !hasWildcard && !hasStale && !hasEntryCount {
		return
	}

	b.WriteString("### Allowlist trust model\n\n")

	if hasUnresolved {
		b.WriteString("> ⚠️ **Unresolved allowlist domains** — legitimate traffic to these domains may be blocked under defend.\n>\n")
		for _, d := range in.UnresolvedAllowlistDomains {
			b.WriteString(fmt.Sprintf("> - `%s`\n", sanitizeCell(d)))
		}
		b.WriteString("\n")
	}

	if hasWildcard {
		quoted := make([]string, 0, len(in.WildcardRiskDomains))
		for _, d := range in.WildcardRiskDomains {
			quoted = append(quoted, fmt.Sprintf("`%s`", sanitizeCell(d)))
		}
		b.WriteString(fmt.Sprintf(
			"> ⚠️ **High-risk wildcard domains in allowlist** — %s — may match unintended hosts.\n\n",
			strings.Join(quoted, ", ")))
	}

	if hasStale {
		b.WriteString(fmt.Sprintf(
			"> ⚠️ **DNS allowlist may be stale** — compiled %.0f minutes ago. DNS TTLs may have expired.\n\n",
			staleAge.Minutes()))
	}

	if hasEntryCount {
		b.WriteString(fmt.Sprintf(
			"> ℹ️ Allowlist: %d IPv4 entries loaded at startup (fixed until restart).\n\n",
			in.AllowlistEntryCount))
	}
}

// writeDomainContactCounts emits a collapsible section listing observed FQDNs
// across TCP + UDP egress sorted by count descending. Skipped when no FQDNs
// were observed.
func writeDomainContactCounts(b *strings.Builder, in DigestInput) {
	if len(in.DomainContactCounts) == 0 {
		return
	}
	type kv struct {
		k string
		v int
	}
	list := make([]kv, 0, len(in.DomainContactCounts))
	for k, v := range in.DomainContactCounts {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})

	b.WriteString("<details>\n<summary><strong>Domain contact counts</strong></summary>\n\n")
	b.WriteString("Observation counts per FQDN across TCP + UDP egress (correlated via DNS cache).\n\n")
	b.WriteString("| Domain | Count |\n|:--|--:|\n")
	for _, e := range list {
		b.WriteString(fmt.Sprintf("| `%s` | %d |\n", sanitizeCell(e.k), e.v))
	}
	b.WriteString("\n</details>\n\n")
}

// BuildDetectMarkdown returns GFM + the GFM HTML subset (<details>, <summary>,
// <br>, <hr>, <table>) for `.coldstep-detect.md` / GITHUB_STEP_SUMMARY. The
// visible portion (above the Technical details fold) is intentionally compact:
// header, one-row KPI, optional Top destinations, Triage, footer. Allowlist
// trust-model warnings (P1-1) surface above the fold when applicable.
func BuildDetectMarkdown(in DigestInput) string {
	max := in.MaxRowsPerSection
	if max <= 0 {
		max = DefaultMaxRowsPerSection
	}

	var b strings.Builder
	writeHeader(&b, in)
	writeCompactKPI(&b, in)
	writeCoverage(&b, in)
	writeTopDestinations(&b, in)
	writeTriageTable(&b, in)
	writeAllowlistTrust(&b, in)
	writeDomainContactCounts(&b, in)
	writeTechnicalDetails(&b, in, max)
	writeFooter(&b, in)

	s := b.String()
	if len(s) > summarySoftByteBudget {
		s = TruncateUTF8ToMaxBytes(s, summarySoftByteBudget) +
			"\n\n… **(digest truncated: GitHub Job Summary size budget)**\n"
	}
	return s
}

// WriteDetectDigest overwrites the detect markdown path used by the action post step.
func WriteDetectDigest(path string, in DigestInput) error {
	if path == "" {
		return fmt.Errorf("detect log path is empty")
	}
	return atomicwrite.Bytes(path, []byte(BuildDetectMarkdown(in)), 0o644)
}
