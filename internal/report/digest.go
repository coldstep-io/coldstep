package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// DefaultMaxRowsPerSection caps each collapsible table in the Job Summary digest.
const DefaultMaxRowsPerSection = 120

const summarySoftByteBudget = 950_000

// ExecDigestRow is one exec line in the markdown digest.
type ExecDigestRow struct {
	TS       string
	PID      uint32 // process group / TGID (same as legacy "pid" in JSONL)
	ThreadID uint32 // kernel thread id for this exec
	Comm     string
	Exe      string // executable path (BPF-capped; digest may truncate further)
}

const execExeDigestMaxBytes = 120

// TruncateExeForDigest limits executable path width in markdown tables.
func TruncateExeForDigest(s string) string {
	return TruncateUTF8ToMaxBytes(s, execExeDigestMaxBytes)
}

// TCPDigestRow is one TCP line in the markdown digest.
type TCPDigestRow struct {
	TS     string
	PID    uint32
	Comm   string
	Remote string
	Notes  string
	Policy string
}

// UDPDigestRow is one UDP line in the markdown digest.
type UDPDigestRow struct {
	TS       string
	PID      uint32
	Comm     string
	Remote   string
	DgramLen uint32
	FQDN     string
	Policy   string
}

// HTTPDigestRow is one HTTP line in the markdown digest.
type HTTPDigestRow struct {
	TS     string
	PID    uint32
	Comm   string
	Method string
	Host   string
	Path   string
	Remote string
	Policy string
}

// TLSDigestRow is one TLS ClientHello / SNI line in the markdown digest.
type TLSDigestRow struct {
	TS     string
	PID    uint32
	Comm   string
	SNI    string
	Remote string
	Policy string
}

// FSDigestRow is one filesystem event line in the markdown digest.
type FSDigestRow struct {
	TS   string
	PID  uint32
	Comm string
	Op   string
	Path string
}

// DenyDigestRow is the first denied egress action shown in the enforcement section.
type DenyDigestRow struct {
	TS       string
	PID      uint32
	Comm     string
	Protocol string
	Dst      string
	Dport    uint16
	Reason   string
}

// DigestInput feeds the Job Summary–oriented detect markdown builder.
type DigestInput struct {
	BPF []telemetry.BPFStatus

	ExecTotal, TCPTotal, UDPTotal, HTTPTotal, TLSTotal int
	TLSSNIGate                                         bool
	PolicyCounts                                       map[string]int

	ExecRows  []ExecDigestRow
	TCPRows   []TCPDigestRow
	UDPRows   []UDPDigestRow
	HTTPRows  []HTTPDigestRow
	TLSRows   []TLSDigestRow
	JSONLPath string
	SeqFirst  uint64
	SeqLast   uint64

	MaxRowsPerSection    int
	TruncatedExec        bool
	TruncatedTCP         bool
	TruncatedUDP         bool
	TruncatedHTTP        bool
	TruncatedTLS         bool
	TruncatedProcessTree bool
	ProcForkTotal        int
	ProcessTreeLines     []string
	ProcForkDegraded     bool
	ProcForkReaderErrors int

	UDPDegradedHook  bool
	UDPReaderErrors  int
	HTTPDegradedHook bool
	HTTPReaderErrors int
	TLSDegradedHook  bool
	TLSReaderErrors  int

	FSGate         bool
	FSTotal        int
	FSRows         []FSDigestRow
	TruncatedFS    bool
	FSDegradedHook bool
	FSReaderErrors int

	EnforcementMode                string
	EnforcementAllowlistSize       int
	EnforcementDenyCount           int
	EnforcementDenyReserveFailures int
	EnforcementFirstDeny           *DenyDigestRow

	Connect4TupleUpdateFailures int
	UDPRingbufReserveFailures   int
	DNSRingbufReserveFailures   int
	DroppedCounts               map[string]int
}

// BuildDetectMarkdown returns GFM + limited HTML for `.coldstep-detect.md`.
func BuildDetectMarkdown(in DigestInput) string {
	max := in.MaxRowsPerSection
	if max <= 0 {
		max = DefaultMaxRowsPerSection
	}

	var b strings.Builder
	if strings.EqualFold(in.EnforcementMode, "enforce") {
		b.WriteString("## Coldstep · enforce\n\n")
		b.WriteString("<p align=\"center\"><strong>eBPF runtime audit trail</strong><br/>\n")
		b.WriteString("<sub>Enforce mode: cgroup-scoped IPv4 egress is allowlisted on GitHub-hosted ephemeral Linux runners (not a substitute for self-hosted hardening); denied connects and UDP sends are blocked and appear as <code>deny</code> JSONL. Cleartext HTTP/80 is still observed via syscall hooks where enabled. <code>comm</code> is the kernel task name (16 bytes), not argv. Executable path comes from the tracepoint (BPF-capped).</sub></p>\n\n")
	} else {
		b.WriteString("## Coldstep · detect\n\n")
		b.WriteString("<p align=\"center\"><strong>eBPF runtime audit trail</strong><br/>\n")
		b.WriteString("<sub>Detect-only: observe, do not block. <code>comm</code> is the kernel task name (16 bytes), not argv. Executable path comes from the tracepoint (BPF-capped).</sub></p>\n\n")
	}
	b.WriteString("### KPI\n\n")
	b.WriteString("| Signal | Count |\n|:--|--:|\n")
	b.WriteString(fmt.Sprintf("| **exec** | %d |\n", in.ExecTotal))
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
		b.WriteString(" **tls** KPI counts ClientHello **SNI** parsed from the first `write(2)` after an IPv4 `connect` when `COLDSTEP_FEATURE_GATES=tls_sni=1` (not decrypted TLS).")
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

	if in.EnforcementMode != "" || in.EnforcementAllowlistSize > 0 || in.EnforcementDenyCount > 0 || in.EnforcementDenyReserveFailures > 0 || in.EnforcementFirstDeny != nil {
		b.WriteString("### Enforcement\n\n")
		b.WriteString("| Field | Value |\n|:--|:--|\n")
		mode := in.EnforcementMode
		if mode == "" {
			mode = "detect"
		}
		b.WriteString(fmt.Sprintf("| Mode | `%s` |\n", sanitizeCell(mode)))
		b.WriteString(fmt.Sprintf("| Allowlist size | %d |\n", in.EnforcementAllowlistSize))
		b.WriteString(fmt.Sprintf("| Deny count | %d |\n", in.EnforcementDenyCount))
		if in.EnforcementDenyReserveFailures > 0 {
			b.WriteString(fmt.Sprintf("| Deny ringbuf reserve failures (blocked, no JSONL) | %d |\n", in.EnforcementDenyReserveFailures))
		}
		b.WriteString("\n")

		if in.EnforcementFirstDeny != nil {
			row := in.EnforcementFirstDeny
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
		b.WriteString("<details open>\n<summary><strong>Exec (recent)</strong></summary>\n\n")
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
		b.WriteString("<details open>\n<summary><strong>TCP connect attempts (recent)</strong></summary>\n\n")
		b.WriteString("| Time (UTC) | PID | Comm | Remote | Notes | Policy |\n|:--|--:|:-|:-|:-|:-|\n")
		for _, r := range in.TCPRows {
			b.WriteString(fmt.Sprintf("| %s | `%d` | `%s` | %s | %s | %s |\n",
				sanitizeCell(r.TS), r.PID, sanitizeCell(r.Comm),
				sanitizeCell(r.Remote), sanitizeCell(r.Notes), sanitizeCell(r.Policy)))
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

	writeExec()
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
		b.WriteString("- **TLS / SNI:** rows come from the first `write(2)` buffer after an IPv4 `connect` on the same fd; fragmented ClientHello or `sendmsg`-only stacks may not produce a row.\n")
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

func procForkKPIVisible(in DigestInput) bool {
	return in.ProcForkTotal > 0 || in.ProcForkDegraded || len(in.ProcessTreeLines) > 0 || in.ProcForkReaderErrors > 0
}

func tlsKPIVisible(in DigestInput) bool {
	return in.TLSSNIGate
}

func fsKPIVisible(in DigestInput) bool {
	return in.FSGate
}

func udpEmptyReason(in DigestInput) string {
	if in.UDPDegradedHook {
		return "degraded hook"
	}
	if in.UDPReaderErrors > 0 {
		return fmt.Sprintf("reader errors (%d)", in.UDPReaderErrors)
	}
	return "no events"
}

func httpEmptyReason(in DigestInput) string {
	if in.HTTPDegradedHook {
		return "degraded hook"
	}
	if in.HTTPReaderErrors > 0 {
		return fmt.Sprintf("reader errors (%d)", in.HTTPReaderErrors)
	}
	return "no events"
}

func tlsEmptyReason(in DigestInput) string {
	if in.TLSDegradedHook {
		return "degraded hook"
	}
	if in.TLSReaderErrors > 0 {
		return fmt.Sprintf("reader errors (%d)", in.TLSReaderErrors)
	}
	return "no events"
}

// TruncateUTF8ToMaxBytes cuts s so len(result) <= maxBytes without splitting a UTF-8 code point.
func TruncateUTF8ToMaxBytes(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	b := []byte(s[:maxBytes])
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return string(b)
}

// WriteDetectDigest overwrites the detect markdown path used by the action post step.
func WriteDetectDigest(path string, in DigestInput) error {
	if path == "" {
		return fmt.Errorf("detect log path is empty")
	}
	return os.WriteFile(path, []byte(BuildDetectMarkdown(in)), 0o644)
}
