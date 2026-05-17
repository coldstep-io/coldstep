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
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/coldstep-io/coldstep/internal/atomicwrite"
)

func writeTriageRibbon(b *strings.Builder, in DigestInput) {
	b.WriteString("### Triage\n\n")
	b.WriteString("| Question | Answer |\n|:--|:--|\n")

	mode := "detect"
	if isBlockingDigestMode(in.DefendMode) {
		mode = "defend"
	}
	b.WriteString(fmt.Sprintf("| **Mode** | `%s`", sanitizeCell(mode)))
	if isBlockingDigestMode(in.DefendMode) {
		b.WriteString(fmt.Sprintf(" — **deny events:** %d", in.DefendDenyCount))
		if in.DefendDenyReserveFailures > 0 {
			b.WriteString(fmt.Sprintf(" (**+%d** deny reserve failures)", in.DefendDenyReserveFailures))
		}
	}
	b.WriteString(" |\n")

	bpfOK := true
	var badBPF []string
	for _, row := range in.BPF {
		if !row.OK {
			bpfOK = false
			badBPF = append(badBPF, row.Name)
		}
	}
	if len(in.BPF) == 0 {
		b.WriteString("| **BPF hooks** | *(no status rows)* |\n")
	} else if bpfOK {
		b.WriteString("| **BPF hooks** | **OK** — all reported probes loaded |\n")
	} else {
		sort.Strings(badBPF)
		b.WriteString(fmt.Sprintf("| **BPF hooks** | **Review** — degraded: %s |\n", sanitizeCell(strings.Join(badBPF, ", "))))
	}

	droppedTotal := 0
	for _, v := range in.DroppedCounts {
		droppedTotal += v
	}
	if droppedTotal == 0 {
		b.WriteString("| **JSONL decode drops** | **None** |\n")
	} else {
		b.WriteString(fmt.Sprintf("| **JSONL decode drops** | **%d** total — see rollups below |\n", droppedTotal))
	}

	var gapParts []string
	if in.Connect4TupleUpdateFailures > 0 {
		gapParts = append(gapParts, fmt.Sprintf("connect4 map failures=%d", in.Connect4TupleUpdateFailures))
	}
	if in.UDPRingbufReserveFailures > 0 {
		gapParts = append(gapParts, fmt.Sprintf("udp ringbuf reserve=%d", in.UDPRingbufReserveFailures))
	}
	if in.DNSRingbufReserveFailures > 0 {
		gapParts = append(gapParts, fmt.Sprintf("dns ringbuf reserve=%d", in.DNSRingbufReserveFailures))
	}
	if in.ConnectRingbufReserveFailures > 0 {
		gapParts = append(gapParts, fmt.Sprintf("connect ringbuf reserve=%d", in.ConnectRingbufReserveFailures))
	}
	if in.HTTPRingbufReserveFailures > 0 {
		gapParts = append(gapParts, fmt.Sprintf("http ringbuf reserve=%d", in.HTTPRingbufReserveFailures))
	}
	if in.TLSRingbufReserveFailures > 0 {
		gapParts = append(gapParts, fmt.Sprintf("tls ringbuf reserve=%d", in.TLSRingbufReserveFailures))
	}
	if in.ExecRingbufReserveFailures > 0 {
		gapParts = append(gapParts, fmt.Sprintf("exec ringbuf reserve=%d", in.ExecRingbufReserveFailures))
	}
	if in.ForkRingbufReserveFailures > 0 {
		gapParts = append(gapParts, fmt.Sprintf("fork ringbuf reserve=%d", in.ForkRingbufReserveFailures))
	}
	if in.FSRingbufReserveFailures > 0 {
		gapParts = append(gapParts, fmt.Sprintf("fs ringbuf reserve=%d", in.FSRingbufReserveFailures))
	}
	if in.UDPSendmsgMultiIovecObserved > 0 {
		gapParts = append(gapParts, fmt.Sprintf("udp multi-iovec=%d", in.UDPSendmsgMultiIovecObserved))
	}
	if in.TLSWritevMultiIovecObserved > 0 {
		gapParts = append(gapParts, fmt.Sprintf("tls writev multi-iovec=%d", in.TLSWritevMultiIovecObserved))
	}
	if in.UnobservedEgressSyscalls > 0 {
		gapParts = append(gapParts, fmt.Sprintf("unobserved egress syscalls=%d", in.UnobservedEgressSyscalls))
	}
	if in.TCPDNSSkippedShortRead > 0 {
		gapParts = append(gapParts, fmt.Sprintf("tcp dns short read=%d", in.TCPDNSSkippedShortRead))
	}
	if in.IoUringSetupObserved > 0 {
		gapParts = append(gapParts, fmt.Sprintf("⚠ io_uring_setup (syscall-hook bypass class)=%d", in.IoUringSetupObserved))
	}
	if in.BPFAuditRingbufReserveFailures > 0 {
		gapParts = append(gapParts, fmt.Sprintf("bpf audit ringbuf reserve=%d", in.BPFAuditRingbufReserveFailures))
	}
	if !in.CanaryPipelineOK && in.CanaryFailCount > 0 {
		gapParts = append(gapParts, fmt.Sprintf("🚨 telemetry canary FAILED (failures=%d)", in.CanaryFailCount))
	}
	if len(gapParts) == 0 {
		b.WriteString("| **Capture gaps** | **None reported** (see footnotes for semantics) |\n")
	} else {
		b.WriteString(fmt.Sprintf("| **Capture gaps** | **Review** — %s |\n", sanitizeCell(strings.Join(gapParts, "; "))))
	}

	if interp := truthfulnessInterpretation(in); interp != "" {
		b.WriteString(fmt.Sprintf("| **Observability (partial / bypass-class)** | %s |\n", sanitizeCell(interp)))
	}

	if rbTotal := totalDetectRingbufReserveFailures(in); rbTotal > 0 {
		b.WriteString(fmt.Sprintf("| **Ringbuf reserve pressure (total)** | **%d** across detect-path channels (per-channel KPI rows below) |\n", rbTotal))
	}

	b.WriteString("\n")
	b.WriteString("<sub>Triage is for fast decisions; row-level detail stays in collapsible sections below and in JSONL.</sub>\n\n")
}

func writeHotEgressTable(b *strings.Builder, in DigestInput) {
	hot := buildHotEgressList(in)
	if len(hot) == 0 {
		return
	}
	b.WriteString("### Hot egress destinations\n\n")
	b.WriteString("Ranked by **event rows in this digest window** (not global uniqueness across the full JSONL). ")
	b.WriteString("Prefer **Host** / **SNI** / **FQDN** columns when present.\n\n")
	b.WriteString("| Rank | Entity | Rows | Channels |\n")
	b.WriteString("|--:|:-|--:|:-|\n")
	for i, e := range hot {
		tags := hotKindTags(e.kinds)
		if tags == "" {
			tags = "—"
		}
		b.WriteString(fmt.Sprintf("| %d | %s | %d | %s |\n",
			i+1, sanitizeCell(e.key), e.count, sanitizeCell(tags)))
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

// BuildDetectMarkdown returns GFM + limited HTML for `.coldstep-detect.md`.
func BuildDetectMarkdown(in DigestInput) string {
	max := in.MaxRowsPerSection
	if max <= 0 {
		max = DefaultMaxRowsPerSection
	}

	var b strings.Builder
	if isBlockingDigestMode(in.DefendMode) {
		b.WriteString("## Coldstep · defend\n\n")
		b.WriteString("<p align=\"center\"><strong>eBPF runtime audit trail</strong><br/>\n")
		b.WriteString("<sub>Defend mode: cgroup-scoped IPv4 egress is allowlisted on GitHub-hosted ephemeral Linux runners (not a substitute for self-hosted hardening); denied connects and UDP sends are blocked and appear as <code>deny</code> JSONL. Cleartext HTTP/80 is still observed via syscall hooks where enabled. <code>comm</code> is the kernel task name (16 bytes), not argv. Executable path comes from the tracepoint (BPF-capped).</sub></p>\n\n")
	} else {
		b.WriteString("## Coldstep · detect\n\n")
		b.WriteString("<p align=\"center\"><strong>eBPF runtime audit trail</strong><br/>\n")
		b.WriteString("<sub>Detect-only: observe, do not block. <code>comm</code> is the kernel task name (16 bytes), not argv. Executable path comes from the tracepoint (BPF-capped).</sub></p>\n\n")
	}
	writeTriageRibbon(&b, in)
	writeHotEgressTable(&b, in)
	b.WriteString("### KPI\n\n")
	b.WriteString("| Signal | Count |\n|:--|--:|\n")
	writeDetectProfileKPI(&b, in)
	b.WriteString(fmt.Sprintf("| **exec** | %d |\n", in.ExecTotal))
	if in.BPFAuditTotal > 0 {
		b.WriteString(fmt.Sprintf("| **bpf_audit** | %d |\n", in.BPFAuditTotal))
	}
	if in.BPFMapIntegrityFailures > 0 {
		b.WriteString(fmt.Sprintf("| **bpf_map_integrity_failures** | <font color=\"red\">%d</font> |\n", in.BPFMapIntegrityFailures))
	}
	if procForkKPIVisible(in) {
		b.WriteString(fmt.Sprintf("| **proc_fork** | %d |\n", in.ProcForkTotal))
	}
	b.WriteString(fmt.Sprintf("| **tcp** | %d |\n", in.TCPTotal))
	if in.Connect4TupleUpdateFailures > 0 {
		b.WriteString(fmt.Sprintf("| **connect4 (tgid,fd)→tuple map update failures** | %d |\n", in.Connect4TupleUpdateFailures))
	}
	if in.UDPRingbufReserveFailures > 0 {
		b.WriteString(fmt.Sprintf("| **udp_events ringbuf reserve failures** | %d |\n", in.UDPRingbufReserveFailures))
	}
	if in.DNSRingbufReserveFailures > 0 {
		b.WriteString(fmt.Sprintf("| **dns_events ringbuf reserve failures** | %d |\n", in.DNSRingbufReserveFailures))
	}
	if in.ConnectRingbufReserveFailures > 0 {
		b.WriteString(fmt.Sprintf("| **connect_events ringbuf reserve failures** | %d |\n", in.ConnectRingbufReserveFailures))
	}
	if in.HTTPRingbufReserveFailures > 0 {
		b.WriteString(fmt.Sprintf("| **http_events ringbuf reserve failures** | %d |\n", in.HTTPRingbufReserveFailures))
	}
	if in.TLSRingbufReserveFailures > 0 {
		b.WriteString(fmt.Sprintf("| **tls_events ringbuf reserve failures** | %d |\n", in.TLSRingbufReserveFailures))
	}
	if in.ExecRingbufReserveFailures > 0 {
		b.WriteString(fmt.Sprintf("| **exec_events ringbuf reserve failures** | %d |\n", in.ExecRingbufReserveFailures))
	}
	if in.ForkRingbufReserveFailures > 0 {
		b.WriteString(fmt.Sprintf("| **proc_fork_events ringbuf reserve failures** | %d |\n", in.ForkRingbufReserveFailures))
	}
	if in.FSRingbufReserveFailures > 0 {
		b.WriteString(fmt.Sprintf("| **fs_events ringbuf reserve failures** | %d |\n", in.FSRingbufReserveFailures))
	}
	if in.UDPSendmsgMultiIovecObserved > 0 {
		b.WriteString(fmt.Sprintf("| **udp_sendmsg multi-iovec calls (iov[1..n] not captured)** | %d |\n", in.UDPSendmsgMultiIovecObserved))
	}
	if in.TLSWritevMultiIovecObserved > 0 {
		b.WriteString(fmt.Sprintf("| **tls writev multi-iovec calls (iov[1..n] not captured)** | %d |\n", in.TLSWritevMultiIovecObserved))
	}
	if in.UnobservedEgressSyscalls > 0 {
		b.WriteString(fmt.Sprintf("| **unobserved egress syscalls (sendmmsg/sendfile/splice)** | %d |\n", in.UnobservedEgressSyscalls))
	}
	if in.IoUringSetupObserved > 0 {
		b.WriteString(fmt.Sprintf("| **⚠ io_uring_setup (syscall-hook bypass class)** | %d |\n", in.IoUringSetupObserved))
	}
	if in.BPFAuditRingbufReserveFailures > 0 {
		b.WriteString(fmt.Sprintf("| **bpf_audit_events ringbuf reserve failures** | %d |\n", in.BPFAuditRingbufReserveFailures))
	}
	if in.CanaryFailCount > 0 {
		status := "✅ OK"
		if !in.CanaryPipelineOK {
			status = "🚨 FAILED"
		}
		b.WriteString(fmt.Sprintf("| **Telemetry integrity canary** | %s (failures=%d) |\n", status, in.CanaryFailCount))
	} else {
		b.WriteString("| **Telemetry integrity canary** | ✅ OK |\n")
	}
	if in.BPFHeartbeatFailures > 0 {
		b.WriteString(fmt.Sprintf("| **🚨 BPF Self-protection Heartbeat Failures** | %d |\n", in.BPFHeartbeatFailures))
	} else {
		b.WriteString("| **BPF Self-protection Heartbeat** | ✅ OK |\n")
	}
	if in.TCPDNSResponsesObserved > 0 {
		b.WriteString(fmt.Sprintf("| **TCP DNS responses observed** | %d |\n", in.TCPDNSResponsesObserved))
	}
	if in.TCPDNSSkippedShortRead > 0 {
		b.WriteString(fmt.Sprintf("| **TCP DNS short reads (<6 B)** | %d |\n", in.TCPDNSSkippedShortRead))
	}
	droppedTotal := 0
	for _, v := range in.DroppedCounts {
		droppedTotal += v
	}
	if droppedTotal > 0 {
		b.WriteString(fmt.Sprintf("| **dropped events (decode/jsonl)** | %d |\n", droppedTotal))
	}
	b.WriteString(fmt.Sprintf("| **udp** | %d |\n", in.UDPTotal))
	b.WriteString(fmt.Sprintf("| **http** | %d |\n", in.HTTPTotal))
	if tlsKPIVisible(in) {
		b.WriteString(fmt.Sprintf("| **tls** | %d |\n", in.TLSTotal))
	}
	if fsKPIVisible(in) {
		b.WriteString(fmt.Sprintf("| **fs_event** | %d |\n", in.FSTotal))
	}
	b.WriteString("<sub>UDP KPI counts IPv4 sendto and sendmsg egress (first iovec length; destination from msg_name or connected socket cache). HTTP KPI counts cleartext HTTP/1 request bytes on sendto to destination port 80 only; https traffic appears as tcp connect events.")
	if tlsKPIVisible(in) {
		b.WriteString(" **tls** KPI counts ClientHello **SNI** parsed from the first cleartext handshake buffer on `write`/`writev`/`pwrite`/`pwritev`/`pwritev2`/`sendto` paths after an IPv4 `connect` when `COLDSTEP_FEATURE_GATES=tls_sni=1` (not decrypted TLS).")
	}
	if procForkKPIVisible(in) {
		b.WriteString(" **proc_fork** counts `sched_process_fork` events (best-effort parent/child lineage).")
	}
	if fsKPIVisible(in) {
		b.WriteString(" **fs_event** KPI counts high-signal filesystem operations (create, unlink, rename, chmod) observed via `openat`/`unlinkat`/`renameat2`/`fchmodat` syscalls when `COLDSTEP_FEATURE_GATES=fs_events=1`.")
	}
	if in.Connect4TupleUpdateFailures > 0 {
		b.WriteString(" **connect4** row: BPF could not insert some `(tgid,fd)→tuple` entries (hash pressure); TCP connect ringbuf events are unchanged, but TLS ClientHello correlation may degrade.")
	}
	if in.UDPRingbufReserveFailures > 0 {
		b.WriteString(" **udp_events** reserve failures indicate ringbuf pressure; some UDP egress may be unobserved.")
	}
	if in.DNSRingbufReserveFailures > 0 {
		b.WriteString(" **dns_events** reserve failures indicate ringbuf pressure; some DNS reply telemetry may be missed.")
	}
	if in.ConnectRingbufReserveFailures > 0 {
		b.WriteString(" **connect_events** reserve failures indicate ringbuf pressure; some TCP connect telemetry may be missed.")
	}
	if in.HTTPRingbufReserveFailures > 0 {
		b.WriteString(" **http_events** reserve failures indicate ringbuf pressure; some cleartext HTTP telemetry may be missed.")
	}
	if in.TLSRingbufReserveFailures > 0 {
		b.WriteString(" **tls_events** reserve failures indicate ringbuf pressure; some TLS/SNI telemetry may be missed.")
	}
	if in.ExecRingbufReserveFailures > 0 {
		b.WriteString(" **exec_events** reserve failures indicate ringbuf pressure; some exec telemetry may be missed.")
	}
	if in.ForkRingbufReserveFailures > 0 {
		b.WriteString(" **proc_fork_events** reserve failures indicate ringbuf pressure; some fork/process-tree telemetry may be missed.")
	}
	if in.FSRingbufReserveFailures > 0 {
		b.WriteString(" **fs_events** reserve failures indicate ringbuf pressure; some filesystem telemetry may be missed.")
	}
	if in.UDPSendmsgMultiIovecObserved > 0 || in.TLSWritevMultiIovecObserved > 0 {
		b.WriteString(" **multi-iovec** counters surface scatter/gather syscalls (`sendmsg`/`writev` with vlen>1); only the first iovec is captured by the BPF probe.")
	}
	if in.UnobservedEgressSyscalls > 0 {
		b.WriteString(" **unobserved egress syscalls** counts IPv4 egress / fd-write paths (e.g. `sendmmsg`, `sendfile`, `splice`) that bypass Coldstep's HTTP/TLS sniff arms; non-zero means real traffic was missed by the sniff layer. Under **defend**, cgroup/LSM hooks may still apply to the underlying socket; under **detect**, this is visibility-only.")
	}
	if in.IoUringSetupObserved > 0 {
		b.WriteString(" **⚠ io_uring_setup** was called on this runner — io_uring can bypass typical syscall tracepoints used for detect mode (and may complicate observation). If `io-uring-disable` is true (default), the setup call was blocked by sysctl; this counter still records the attempt. See SECURITY.md (Guarantees vs best-effort).")
	}
	if in.TCPDNSSkippedShortRead > 0 {
		b.WriteString(" **TCP DNS short reads** counts TCP read(2) returns shorter than 6 bytes on the traced DNS path (cannot validate the RFC 1035 length prefix plus DNS header); segmented large replies may increment this without full stream reassembly.")
	}
	b.WriteString("</sub>\n\n")

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
	if droppedTotal > 0 {
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

	if len(in.BPF) > 0 {
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
			b.WriteString(fmt.Sprintf("| `%s` | %s%s |\n", sanitizeCell(row.Name), st, detail))
		}
		b.WriteString("\n")
	}

	if in.DefendMode != "" || in.DefendAllowlistSize > 0 || in.DefendDenyCount > 0 || in.DefendDenyReserveFailures > 0 || in.DefendFirstDeny != nil {
		b.WriteString("### Defend\n\n")
		b.WriteString("| Field | Value |\n|:--|:--|\n")
		mode := digestModeCell(in.DefendMode)
		b.WriteString(fmt.Sprintf("| Mode | `%s` |\n", sanitizeCell(mode)))
		b.WriteString(fmt.Sprintf("| Allowlist size | %d |\n", in.DefendAllowlistSize))
		b.WriteString(fmt.Sprintf("| Deny count | %d |\n", in.DefendDenyCount))
		if in.DefendDenyReserveFailures > 0 {
			b.WriteString(fmt.Sprintf("| Deny ringbuf reserve failures (blocked, no JSONL) | %d |\n", in.DefendDenyReserveFailures))
		}
		b.WriteString("\n")

		if in.DefendFirstDeny != nil {
			row := in.DefendFirstDeny
			b.WriteString("**First deny**\n\n")
			b.WriteString("| Time (UTC) | PID | Comm | Protocol | Remote | Reason |\n|:--|--:|:-|:-|:-|:-|\n")
			b.WriteString(fmt.Sprintf("| %s | `%d` | `%s` | `%s` | `%s:%d` | `%s` |\n\n",
				sanitizeCell(row.TS),
				row.PID,
				sanitizeCell(row.Comm),
				sanitizeCell(row.Protocol),
				sanitizeCell(row.Dst),
				row.Dport,
				sanitizeCell(row.Reason),
			))
		}
	}

	procTreeEmptyReason := func(in DigestInput) string {
		if in.ProcForkDegraded {
			return "degraded hook"
		}
		if in.ProcForkReaderErrors > 0 {
			return fmt.Sprintf("reader errors (%d)", in.ProcForkReaderErrors)
		}
		return "no events"
	}

	writeExec := func() {
		b.WriteString("<details>\n<summary><strong>Exec (recent)</strong></summary>\n\n")
		b.WriteString("| Time (UTC) | PID (TGID) | TID | Comm | Executable (BPF-capped) |\n|:--|--:|--:|:-|:-|\n")
		for _, r := range in.ExecRows {
			b.WriteString(fmt.Sprintf("| %s | `%d` | `%d` | `%s` | `%s` |\n",
				sanitizeCell(r.TS), r.PID, r.ThreadID, sanitizeCell(r.Comm), sanitizeCell(r.Exe)))
		}
		b.WriteString("\n</details>\n\n")
	}
	writeProcessTree := func() {
		if !procForkKPIVisible(in) {
			return
		}
		b.WriteString("<details>\n<summary><strong>Process tree (recent)</strong></summary>\n\n")
		b.WriteString("| Outline |\n|:-|\n")
		if len(in.ProcessTreeLines) == 0 {
			b.WriteString(fmt.Sprintf("| %s |\n", sanitizeCell(procTreeEmptyReason(in))))
		} else {
			for _, line := range in.ProcessTreeLines {
				b.WriteString(fmt.Sprintf("| %s |\n", sanitizeCell(line)))
			}
		}
		b.WriteString("\n</details>\n\n")
	}
	writeTCP := func() {
		b.WriteString("<details>\n<summary><strong>TCP connect attempts (recent)</strong></summary>\n\n")
		b.WriteString("| Time (UTC) | PID | Comm | Remote | Notes | Policy |\n|:--|--:|:-|:-|:-|:-|\n")
		if len(in.TCPRows) == 0 {
			b.WriteString(fmt.Sprintf("| — | — | — | — | — | %s |\n", sanitizeCell(tcpEmptyReason(in))))
		} else {
			for _, r := range in.TCPRows {
				b.WriteString(fmt.Sprintf("| %s | `%d` | `%s` | %s | %s | %s |\n",
					sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm),
					sanitizeCell(r.Remote), sanitizeCell(r.Notes), sanitizeCell(r.Policy)))
			}
		}
		b.WriteString("\n</details>\n\n")
	}
	writeUDP := func() {
		b.WriteString("<details>\n<summary><strong>UDP sendto (recent)</strong></summary>\n\n")
		b.WriteString("| Time (UTC) | PID | Comm | Remote | Len | FQDN | Policy |\n|:--|--:|:-|:-|--:|:-|:-|\n")
		if len(in.UDPRows) == 0 {
			b.WriteString(fmt.Sprintf("| — | — | — | — | — | — | %s |\n", sanitizeCell(udpEmptyReason(in))))
		} else {
			for _, r := range in.UDPRows {
				fq := r.FQDN
				if fq == "" {
					fq = "—"
				}
				b.WriteString(fmt.Sprintf("| %s | `%d` | `%s` | %s | %d | %s | %s |\n",
					sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm),
					sanitizeCell(r.Remote), r.DgramLen, sanitizeCell(fq), sanitizeCell(r.Policy)))
			}
		}
		b.WriteString("\n</details>\n\n")
	}
	writeHTTP := func() {
		b.WriteString("<details>\n<summary><strong>HTTP/1 cleartext (recent)</strong></summary>\n\n")
		b.WriteString("| Time (UTC) | PID | Comm | Method | Host | Path (summary) | Remote | Policy |\n|:--|--:|:-|:-|:-|:-|:-|:-|\n")
		if len(in.HTTPRows) == 0 {
			b.WriteString(fmt.Sprintf("| — | — | — | — | — | — | — | %s |\n", sanitizeCell(httpEmptyReason(in))))
		} else {
			for _, r := range in.HTTPRows {
				b.WriteString(fmt.Sprintf("| %s | `%d` | `%s` | `%s` | `%s` | `%s` | %s | %s |\n",
					sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm),
					sanitizeCell(r.Method), sanitizeCell(r.Host), sanitizeCell(r.Path),
					sanitizeCell(r.Remote), sanitizeCell(r.Policy)))
			}
		}
		b.WriteString("\n</details>\n\n")
	}
	writeTLS := func() {
		if !tlsKPIVisible(in) {
			return
		}
		b.WriteString("<details>\n<summary><strong>TLS ClientHello / SNI (recent)</strong></summary>\n\n")
		b.WriteString("| Time (UTC) | PID | Comm | SNI | Remote | Policy |\n|:--|--:|:-|:-|:-|:-|\n")
		if len(in.TLSRows) == 0 {
			b.WriteString(fmt.Sprintf("| — | — | — | — | — | %s |\n", sanitizeCell(tlsEmptyReason(in))))
		} else {
			for _, r := range in.TLSRows {
				b.WriteString(fmt.Sprintf("| %s | `%d` | `%s` | `%s` | %s | %s |\n",
					sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm),
					sanitizeCell(r.SNI), sanitizeCell(r.Remote), sanitizeCell(r.Policy)))
			}
		}
		b.WriteString("\n</details>\n\n")
	}
	writeFS := func() {
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
			b.WriteString(fmt.Sprintf("| — | — | — | — | %s |\n", reason))
		} else {
			for _, r := range in.FSRows {
				b.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | `%s` | `%s` |\n",
					sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm), sanitizeCell(r.Op), sanitizeCell(r.Path)))
			}
			if in.TruncatedFS {
				b.WriteString(fmt.Sprintf("\n*Showing last %d of %d — full stream in JSONL.*\n",
					len(in.FSRows), in.FSTotal))
			}
		}
		b.WriteString("\n</details>\n\n")
	}
	writeBPFAudit := func() {
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
			b.WriteString(fmt.Sprintf("| — | — | — | %s |\n", reason))
		} else {
			for _, r := range in.BPFAuditRows {
				b.WriteString(fmt.Sprintf("| %s | `%d` | `%s` | `%s` (%d) |\n",
					sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm), sanitizeCell(BPFCmdName(r.Cmd)), r.Cmd))
			}
			if in.TruncatedBPFAudit {
				b.WriteString(fmt.Sprintf("\n*Showing last %d of %d — full stream in JSONL.*\n",
					len(in.BPFAuditRows), in.BPFAuditTotal))
			}
		}
		b.WriteString("\n</details>\n\n")
	}

	writeExec()
	writeBPFAudit()
	writeProcessTree()
	writeTCP()
	writeUDP()
	writeHTTP()
	writeTLS()
	writeFS()

	b.WriteString("### Footnotes\n\n")
	if in.JSONLPath != "" {
		b.WriteString(fmt.Sprintf("- **Canonical log (JSONL):** `%s` — append-only source of truth; Job Summary is a capped digest.\n", sanitizeCell(in.JSONLPath)))
	}
	if in.SeqFirst > 0 && in.SeqLast >= in.SeqFirst {
		b.WriteString(fmt.Sprintf("- **Event sequence range (userspace):** %d–%d\n", in.SeqFirst, in.SeqLast))
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
		b.WriteString(fmt.Sprintf("- **Truncated sections:** %s — showing up to **%d** newest rows per section; totals in KPI are full counts.\n",
			strings.Join(trunc, ", "), max))
	} else {
		b.WriteString(fmt.Sprintf("- **Row cap:** up to **%d** rows per section when activity exceeds the cap.\n", max))
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
