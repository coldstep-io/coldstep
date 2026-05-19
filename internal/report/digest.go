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

	"github.com/coldstep-io/coldstep/internal/atomicwrite"
)

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
// observed by the P0-1 Phase 1 cgroup/connect6 + cgroup/sendmsg6 hooks.
// Non-zero means traffic bypassed the IPv4-only defend enforcement; in
// detect mode that's a visibility gap (⚠️), in defend mode that's an
// outright bypass (🚨).
func ipv6EgressObserved(in DigestInput) uint32 {
	return in.IPv6ConnectObserved + in.IPv6SendmsgObserved
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
	// In defend mode, any observed IPv6 egress is a 🚨 — the IPv4-only
	// cgroup/connect4+sendmsg4 path could not gate it, so traffic
	// escaped enforcement entirely. In detect mode this is a ⚠️
	// limitation rather than an alert (handled in the review check
	// below).
	defendIPv6Bypass := isBlockingDigestMode(in.DefendMode) && ipv6EgressObserved(in) > 0
	alert := (!in.CanaryPipelineOK && in.CanaryFailCount > 0) ||
		in.BPFHeartbeatFailures > 0 ||
		in.BPFMapIntegrityFailures > 0 ||
		(len(in.BPF) > 0 && !bpfOK) ||
		defendIPv6Bypass
	if alert {
		return "🚨"
	}
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
		ipv6EgressObserved(in) > 0
	if review {
		return "⚠️"
	}
	return "✅"
}

// writeHeader renders the single-line `## <emoji> coldstep — <mode>` heading.
// When partial-coverage signals fired (ringbuf drops or partial-observe
// counters), a blockquote note steers the reader to the Coverage block — the ✅
// badge alone would otherwise imply complete observation.
func writeHeader(b *strings.Builder, in DigestInput) {
	mode := "detect"
	if isBlockingDigestMode(in.DefendMode) {
		mode = "defend"
	}
	fmt.Fprintf(b, "## %s coldstep — %s\n\n", verdictEmoji(in), mode)
	if hasPartialCoverageSignals(in) {
		b.WriteString("> ⚠️ Partial coverage — see Coverage block below.\n\n")
	}
}

// writeCoverage emits a one-line scope statement so users do not misread ✅ as
// "every byte of egress observed". IPv6 and QUIC/HTTP3 are statically out of
// scope today (no BPF coverage); the "Payloads beyond iov[0]" cell flips to
// ⚠️ partial when BG-01 partial-observe counters fired this run.
func writeCoverage(b *strings.Builder, in DigestInput) {
	fmt.Fprintf(b, "**Coverage this run:** IPv4 TCP/UDP ✓ observed | IPv6 ✗ not observed | QUIC/HTTP3 ✗ not observed | Payloads beyond iov[0]: %s\n\n",
		coveragePayloadState(in))
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
	if !in.CanaryPipelineOK && in.CanaryFailCount > 0 {
		gapParts = append(gapParts, fmt.Sprintf("🚨 telemetry canary FAILED (failures=%d)", in.CanaryFailCount))
	}
	if len(gapParts) > 0 {
		rows = append(rows, [2]string{"**Capture gaps**", fmt.Sprintf("⚠️ %s", sanitizeCell(strings.Join(gapParts, "; ")))})
	}

	if interp := truthfulnessInterpretation(in); interp != "" {
		rows = append(rows, [2]string{"**Observability (partial / bypass-class)**", sanitizeCell(interp)})
	}

	// P0-1 Phase 1: surface IPv6 egress as a top-level triage row. In
	// detect mode this is a ⚠️ limitation (IPv4-only visibility); in
	// defend mode it's 🚨 (the IPv4-only allowlist could not gate the
	// connection). Phase 2 will add IPv6 enforcement.
	if n := ipv6EgressObserved(in); n > 0 {
		badge := "⚠️"
		suffix := "IPv6 enforcement not yet supported"
		if isBlockingDigestMode(in.DefendMode) {
			badge = "🚨"
			suffix = "**defend allowlist is IPv4-only — traffic escaped enforcement**"
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

	fmt.Fprintf(b, "| **http** | %d |\n", in.HTTPTotal)
	if in.HTTPRingbufReserveFailures > 0 {
		fmt.Fprintf(b, "| **http_events ringbuf reserve failures** | %d |\n", in.HTTPRingbufReserveFailures)
	}

	if tlsKPIVisible(in) {
		fmt.Fprintf(b, "| **tls** | %d |\n", in.TLSTotal)
		if in.TLSRingbufReserveFailures > 0 {
			fmt.Fprintf(b, "| **tls_events ringbuf reserve failures** | %d |\n", in.TLSRingbufReserveFailures)
		}
		if in.TLSWritevMultiIovecObserved > 0 {
			fmt.Fprintf(b, "| **tls writev multi-iovec calls (iov[1..n] not captured)** | %d |\n", in.TLSWritevMultiIovecObserved)
		}
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
	if in.IoUringSetupObserved > 0 {
		fmt.Fprintf(b, "| **⚠️ io_uring_setup (syscall-hook bypass class)** | %d |\n", in.IoUringSetupObserved)
	}
	if in.IPv6ConnectObserved > 0 {
		fmt.Fprintf(b, "| **⚠️ ipv6 connect6 observed (defend is IPv4-only)** | %d |\n", in.IPv6ConnectObserved)
	}
	if in.IPv6SendmsgObserved > 0 {
		fmt.Fprintf(b, "| **⚠️ ipv6 sendmsg6 observed (defend is IPv4-only)** | %d |\n", in.IPv6SendmsgObserved)
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
		fmt.Fprintf(b, "| **⚠️ Ringbuf drops (detect-path total)** | %d events dropped |\n", rb)
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
	b.WriteString("| Time (UTC) | PID | Comm | SNI | Remote | Policy |\n|:--|--:|:-|:-|:-|:-|\n")
	if len(in.TLSRows) == 0 {
		fmt.Fprintf(b, "| — | — | — | — | — | %s |\n", sanitizeCell(protocolEmptyReason(in.TLSDegradedHook, in.TLSReaderErrors)))
	} else {
		for _, r := range in.TLSRows {
			fmt.Fprintf(b, "| %s | `%d` | `%s` | `%s` | %s | %s |\n",
				sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm),
				sanitizeCell(r.SNI), sanitizeCell(r.Remote), sanitizeCell(r.Policy))
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
	if in.SendfileObserved > 0 || in.SpliceObserved > 0 || in.SendmmsgFirstOnly > 0 {
		b.WriteString("- **sendfile / splice / sendmmsg partial-observe** counters (BG-01) name the IPv4-egress paths that emit destination/length telemetry but no HTTP/TLS payload sniff: `sendfile`/`splice` correlate destination via the cached `(tgid,fd)→tuple` map, and `sendmmsg` introspects only the first `mmsghdr` (messages 2..N are dropped). Per-path counts let operators see which arm drove the gap. Under **defend**, cgroup/LSM hooks may still apply to the underlying socket; under **detect**, this is visibility-only.\n")
	}
	if in.IoUringSetupObserved > 0 {
		b.WriteString("- **⚠️ io_uring_setup** was called on this runner — io_uring can bypass typical syscall tracepoints used for detect mode. If `io-uring-disable` is true (default), the setup call was blocked by sysctl; this counter still records the attempt. See SECURITY.md (Guarantees vs best-effort).\n")
	}
	if ipv6EgressObserved(in) > 0 {
		if isBlockingDigestMode(in.DefendMode) {
			b.WriteString("- **🚨 IPv6 egress** was observed by the `cgroup/connect6` and `cgroup/sendmsg6` observe-only hooks. coldstep defend currently enforces only IPv4 (`cgroup/connect4` and `cgroup/sendmsg4`), so these connections **escaped the allowlist entirely** — review which destinations were contacted and whether IPv4 fallbacks should be required.\n")
		} else {
			b.WriteString("- **⚠️ IPv6 egress** was observed by the `cgroup/connect6` and `cgroup/sendmsg6` observe-only hooks. coldstep is IPv4-only for now — Phase 1 (P0-1) records the attempts so visibility gaps are explicit; Phase 2 will add IPv6 enforcement.\n")
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
	b.WriteString("- **TCP semantics:** rows reflect `connect(2)` attempts at syscall enter, not confirmed established sockets.\n")
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

// BuildDetectMarkdown returns GFM + the GFM HTML subset (<details>, <summary>,
// <br>, <hr>, <table>) for `.coldstep-detect.md` / GITHUB_STEP_SUMMARY. The
// visible portion (above the Technical details fold) is intentionally compact:
// header, one-row KPI, optional Top destinations, Triage, footer.
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
