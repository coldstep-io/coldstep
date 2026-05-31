package report

import (
	"time"
	"unicode/utf8"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// DefaultMaxRowsPerSection caps each collapsible table in the Job Summary digest.
const DefaultMaxRowsPerSection = 120

// maxHotEgressEntities caps the ranked "where did traffic go" triage table.
const maxHotEgressEntities = 15

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
// Confidence is the per-row tier classification produced by
// telemetry.ScoreTLSConfidence; it is rendered as its own column so operators
// can see at a glance whether a specific SNI match should be trusted (full /
// partial / inferred / unknown). The KPI row above aggregates these tiers,
// while this column attributes them to specific destinations.
type TLSDigestRow struct {
	TS         string
	PID        uint32
	Comm       string
	SNI        string
	Remote     string
	Policy     string
	Confidence telemetry.TLSConfidence
	// ConfidenceReason qualifies a non-default Confidence verdict. The only
	// value emitted today is "ktls" (P4): forced to TLSConfidenceUnknown
	// because trace_ktls observed setsockopt(SOL_TLS) on the socket and
	// userspace can no longer parse the ClientHello. Mirrors the JSONL field
	// of the same name on telemetry.TLSEvent.
	ConfidenceReason string
}

// FSDigestRow is one filesystem event line in the markdown digest.
type FSDigestRow struct {
	TS   string
	PID  uint32
	Comm string
	Op   string
	Path string
}

// DenyDigestRow is the first denied egress action shown in the defend section.
type DenyDigestRow struct {
	TS       string
	PID      uint32
	Comm     string
	Protocol string
	Dst      string
	Dport    uint16
	Reason   string
}

// BPFAuditDigestRow is one bpf() syscall audit line in the markdown digest.
type BPFAuditDigestRow struct {
	TS   string
	PID  uint32
	Comm string
	Cmd  uint32 // BPF_PROG_LOAD, etc.
}

// DigestInput feeds the Job Summary–oriented detect markdown builder.
type DigestInput struct {
	DetectProfile string // standard | enhanced (from COLDSTEP_DETECT_PROFILE)
	BPF           []telemetry.BPFStatus
	// RunnerHasIPv6 mirrors telemetry.MetaEvent.RunnerHasIPv6 — true when the
	// runner had at least one non-loopback / non-link-local IPv6 address at
	// agent startup (H1: digest honesty). Used by verdictEmoji to downgrade
	// ✅ to ⚠️ on runners with IPv6 connectivity when no IPv6 hooks are
	// loaded (today: detect mode), surfacing the partial observation in the
	// headline rather than hiding it behind an apparently clean run.
	RunnerHasIPv6 bool
	// RunnerEnv mirrors telemetry.MetaEvent.RunnerEnv — "dind", "unknown", or
	// "" (standard / unset). When "dind", the digest renders a ⚠️ box naming
	// the visibility gap: inner-container traffic from a Docker-in-Docker
	// sidecar is not observable from the outer runner cgroup namespace.
	// Detection runs in the agent (H13); the field is informational only and
	// does not feed the headline verdict.
	RunnerEnv string

	ExecTotal, TCPTotal, UDPTotal, HTTPTotal, TLSTotal int
	TLSSNIGate                                         bool
	// TLSConfidenceFull / Partial / Inferred / Unknown count TLS events by the
	// reliability of the captured SNI. The digest surfaces these as a
	// `full=N partial=M unknown=K` row when at least one TLS event exists, so
	// operators can weigh how trustworthy an SNI-based allow/deny match is on
	// this run.
	TLSConfidenceFull     int
	TLSConfidencePartial  int
	TLSConfidenceInferred int
	TLSConfidenceUnknown  int
	// TLSConfidenceUnknownKTLS is the subset of TLSConfidenceUnknown attributed
	// to the P4 KTLS override (ConfidenceReason=="ktls"). Surfaced in the KPI
	// cell as `(N ktls-offloaded)` and in the technical-details paragraph so
	// operators can separate "unknown because we could not parse it" from
	// "unknown because kernel-TLS structurally hides the SNI".
	TLSConfidenceUnknownKTLS int
	PolicyCounts             map[string]int

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

	TCPDegradedHook  bool
	TCPReaderErrors  int
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

	DefendMode                string
	DefendAllowlistSize       int
	DefendDenyCount           int
	DefendDenyCorroborated    int
	DefendDenyReserveFailures int
	DefendFirstDeny           *DenyDigestRow

	// AllowlistIPCount is the number of unique IPv4 addresses resolved from the
	// defend allowlist at policy-compile time (mirrors MetaEvent.AllowlistIPCount).
	AllowlistIPCount int

	Connect4TupleUpdateFailures   int
	UDPRingbufReserveFailures     int
	DNSRingbufReserveFailures     int
	ConnectRingbufReserveFailures int
	HTTPRingbufReserveFailures    int
	TLSRingbufReserveFailures     int
	ExecRingbufReserveFailures    int
	ForkRingbufReserveFailures    int
	FSRingbufReserveFailures      int
	// Multi-iovec visibility (PR-D). Counts BPF observations of scatter/gather
	// syscalls that we only capture iov[0] for; non-zero indicates payload past
	// the first iovec is invisible to the JSONL/digest. Operators can use this
	// to gauge how much UDP sendmsg / TLS writev traffic is partially observed.
	UDPSendmsgMultiIovecObserved int
	// SendmmsgMultiMessage counts NR_SENDMMSG calls with vlen>1 (mmsghdr vector
	// length, distinct from per-message msg_iovlen). Messages 2..N are not
	// introspected — non-zero quantifies the multi-message silent gap (BG-03).
	SendmmsgMultiMessage int
	// SendmmsgUnobservedExtra counts individual sendmmsg(2) extra messages
	// (beyond the unrolled SENDMMSG_EXTRA_MAX bound) that the BPF observation
	// loop could not reach. BG-03 Gap 3 introduced bounded per-message
	// observation for indices 1..7; this counter sums message slots from
	// index 8 onward that remain silent on vlen >= 9 calls.
	SendmmsgUnobservedExtra     int
	TLSWritevMultiIovecObserved int
	// SendfileObserved, SpliceObserved, SendmmsgFirstOnly are the BG-01
	// per-syscall partial-observe counters (supersedes the PR-E aggregate
	// `UnobservedEgressSyscalls`). Each counts a path that emits dest/length
	// telemetry but no HTTP/TLS payload sniff:
	//   - SendfileObserved:   sendfile(2) / sendfile64(2)
	//   - SpliceObserved:     splice(2)
	//   - SendmmsgFirstOnly:  sendmmsg(2) — only the first mmsghdr is inspected;
	//                         messages 2..N are not introspected.
	// Non-zero values mean the named syscall fired in the run; operators can
	// see which path drove the gap, not just a total.
	SendfileObserved  int
	SpliceObserved    int
	SendmmsgFirstOnly int
	// IPv6ConnectObserved / IPv6SendmsgObserved count non-loopback IPv6
	// egress attempts observed by the cgroup/connect6 and cgroup/sendmsg6
	// hooks. Under P2-1 Phase 2 these hooks enforce in defend mode (LPM
	// trie lookup against allowed_ipv6). In detect mode non-zero values
	// remain a visibility row (no enforcement); in defend mode the digest
	// pivots on DefendIPv6AllowlistSize — non-zero means traffic was gated
	// by an explicit AAAA-resolved allowlist, zero means defend is in a
	// pure block-all IPv6 posture.
	IPv6ConnectObserved uint32
	IPv6SendmsgObserved uint32
	// IPv6EventCount is the H7 detect-mode counter: one increment per
	// non-loopback, non-link-local IPv6 ringbuf record decoded by
	// readIPv6ObsRing. Always 0 in defend mode (the traceipv6 object is
	// not loaded there — defend's own IPv6 cgroup hooks attach instead and
	// surface via IPv6Connect/SendmsgObserved). When non-zero in detect
	// mode, the digest renders an `IPv6 egress detected (not enforced)`
	// warning so operators see the IPv4-only enforcement gap before
	// switching to defend.
	IPv6EventCount int
	// IPv6RingbufReserveFailures counts ringbuf reserve failures on the
	// H7 ipv6_obs_events channel — non-zero means at least one IPv6
	// connect/sendmsg fired with a full ringbuf, so the event count is a
	// lower bound. Detect-mode-only.
	IPv6RingbufReserveFailures int
	// DefendIPv6AllowlistSize is the number of /128 entries programmed
	// into the BPF allowed_ipv6 LPM trie at agent startup. Used by the
	// digest to distinguish two Phase 2 defend postures:
	//   - allowlist > 0: ✅ blocked (AAAA-resolved entries gating IPv6)
	//   - allowlist == 0: ⚠️ pure block-all (all non-loopback/non-link-local
	//     IPv6 denied — works, but operators should know their config has
	//     no AAAA destinations and may surprise users who expect IPv6
	//     services).
	DefendIPv6AllowlistSize int
	// SendpageObserved counts security_socket_sendpage invocations recorded
	// by the lsm/socket_sendpage hook. Non-zero means sendfile(2) or splice(2)
	// reached a socket via the sock_sendpage path — which cgroup/sendmsg4 and
	// lsm/socket_sendmsg cannot gate on kernels < 6.8. The KPI/coverage row
	// flips to reflect that sendfile/splice are observed (and, in defend
	// mode, gated) once this counter fires.
	SendpageObserved uint32
	// IoUringSetupObserved counts io_uring_setup(2) calls detected by the BPF
	// dispatch arm. Non-zero means some workload attempted async I/O setup;
	// io_uring traffic can bypass typical syscall tracepoints used for detect mode.
	// It is a syscall-hook bypass-class signal, not proof of exfiltration.
	IoUringSetupObserved int
	// IoUringSendTotal counts io_uring socket-class SQE submissions
	// (IORING_OP_SENDMSG, IORING_OP_SEND) seen via raw_tp/io_uring_submit_sqe.
	// Non-zero means the workload bypassed our syscall arms for network
	// sends — SNI / payload extraction is not possible from the SQE
	// submission point alone.
	IoUringSendTotal int
	// IoUringRingbufReserveFailures counts ringbuf reserve failures on the
	// io_uring_events channel — non-zero indicates io_uring telemetry pressure.
	IoUringRingbufReserveFailures int
	// IoUringTLSHelloObserved counts io_uring SQE submissions whose user-buffer
	// prefix matched the TLS ClientHello record signature (P6 Phase 2, enhanced
	// profile only). Always zero outside COLDSTEP_DETECT_PROFILE=enhanced; when
	// non-zero, the digest gains an evidence row showing that the io_uring
	// bypass path is being used to initiate TLS handshakes (the strongest
	// signal Phase 2 can produce from the submission point).
	IoUringTLSHelloObserved int
	// IOUringTLSSNIs lists distinct SNI hostnames extracted from io_uring
	// SEND/SENDMSG ClientHello submissions (P6 Phase 2.5, enhanced profile).
	// Sorted + deduplicated upstream. Destination IP is not resolvable from the
	// io_uring submission path, so these hosts carry no dst correlation. Empty
	// when no io_uring TLS SNI was observed; the digest row is then hidden.
	IOUringTLSSNIs []string
	// CanaryPipelineOK reflects telemetry integrity canary status. When false,
	// the BPF ringbuf pipeline may be compromised (suppression, exhaustion).
	CanaryPipelineOK bool
	CanaryFailCount  int
	// QUICCandidateCount counts UDP/443 egress to non-loopback IPv4 observed in
	// this run, classified as likely QUIC/HTTP3 flows. The payload is encrypted
	// and not inspected — non-zero surfaces the visibility gap in the KPI table.
	QUICCandidateCount int
	// QuicObservedCount mirrors telemetry.CoverageReport.QuicObserved — the
	// per-run total of UDPEvent records whose PossibleQUIC flag was set
	// (destination port 443). H19: surfaced in the coverage scope table as
	// the heuristic "QUIC/HTTP3 (UDP 443) — N events observed" cell and in
	// the technical-details "possible-quic" note when non-zero. Distinct
	// from QUICCandidateCount, which is the older non-loopback-IPv4-only
	// predicate.
	QuicObservedCount uint64
	// TCPDNSResponsesObserved counts TCP DNS length-framed replies where the BPF
	// path could inspect the QR bit (trace_dns.bpf.c read/recvfrom sys_exit).
	TCPDNSResponsesObserved int
	// TCPDNSSkippedShortRead counts read(2) returns shorter than 6 bytes on the
	// TCP DNS path (partial segment — cannot validate length prefix + header).
	TCPDNSSkippedShortRead int
	// TCPResultCounts holds the breakdown of tcp_v4_connect outcomes
	// captured by the P3-2 kretprobe pair, keyed by ConnectResultString
	// bucket (established / refused / timeout / unreachable /
	// in_progress / denied / other). When the kretprobe attach failed,
	// the map is empty and the digest falls back to the legacy
	// "TCP connect attempts" wording.
	TCPResultCounts      map[string]int
	BPFHeartbeatFailures int
	// TCPStateTotal counts kernel-confirmed TCP handshake state events from
	// the inet_sock_set_state tracepoint (P3-2b). It is filtered to
	// oldstate == SYN_SENT so it represents resolved outgoing connects.
	// TCPStateConfirmed counts the subset that transitioned to ESTABLISHED
	// (handshake succeeded); TCPStateRefused counts the subset that
	// transitioned to a terminal failure state (CLOSE / CLOSE_WAIT /
	// TIME_WAIT — RST, timeout, unreachable, or peer-initiated close).
	// Other intermediate transitions (e.g. SYN_RECV) are not counted in
	// either bucket. Non-zero TCPStateTotal adds a "TCP handshakes
	// (kernel-confirmed)" row to the Full KPI table — complementary to
	// the P3-2-derived TCPResultCounts, which is the kretprobe-captured
	// `tcp_v4_connect()` return value.
	TCPStateTotal                  int
	TCPStateConfirmed              int
	TCPStateRefused                int
	TCPStateReaderErrors           int
	TCPStateRingbufReserveFailures int
	BPFAuditTotal                  int
	BPFAuditRows                   []BPFAuditDigestRow
	TruncatedBPFAudit              bool
	BPFAuditDegradedHook           bool
	BPFAuditReaderErrors           int
	BPFMapIntegrityFailures        int
	BPFAuditRingbufReserveFailures int
	DroppedCounts                  map[string]int

	// KTLSOffloadTotal counts setsockopt(fd, SOL_TLS, TLS_TX|TLS_RX, ...) calls
	// observed by trace_ktls.bpf.c. Non-zero means SNI sniffing is structurally
	// impossible on those sockets — the kernel encrypts, the userspace probe
	// only sees ciphertext fragments. P3-1.
	KTLSOffloadTotal           int
	KTLSRingbufReserveFailures int

	// P1-1 DNS Allowlist Trust Model hardening surface.
	//
	// UnresolvedAllowlistDomains lists allowlist domains that did not yield any
	// IPv4 A-record at compile time. Empty when all domains resolved or no
	// allowlist was compiled.
	UnresolvedAllowlistDomains []string
	// WildcardRiskDomains lists allowlist entries that match a known multi-tenant
	// shared-infrastructure wildcard surface (e.g. `*.s3.amazonaws.com`). Empty
	// when no such entries are present.
	WildcardRiskDomains []string
	// AllowlistCompileTime is the wall-clock time CompileDomainAllowlist
	// finished resolving the defend allowlist (H9 DNS-6b). The digest renders a
	// staleness warning when time.Since(AllowlistCompileTime) exceeds 5 minutes
	// so operators of long-running jobs see that DNS TTLs may have expired
	// since the snapshot was programmed into the BPF map. Zero value means no
	// allowlist was compiled and the warning is suppressed.
	AllowlistCompileTime time.Time
	// DNSDriftCount is the number of times the H16 background re-resolution
	// goroutine observed IPv4 drift relative to the startup snapshot during
	// the run. Each non-empty policy.DriftReport bumps the counter by 1.
	// Non-zero values surface a "DNS drift detected" advisory in the
	// allowlist trust section — enforcement was intentionally not updated
	// mid-job, so operators see TOCTOU-safe staleness as a warning rather
	// than a silent gap.
	DNSDriftCount int
	// AllowlistEntryCount is the total number of /32 + CIDR entries programmed
	// into the BPF allowed_ipv4 LPM trie at startup (H12). Mirrors
	// MetaEvent.AllowlistEntryCount; rendered as a fixed-point reminder in the
	// digest's allowlist trust section.
	AllowlistEntryCount int
	// DomainContactCounts maps observed FQDN → observation count across TCP +
	// UDP egress. Sorted descending by count in the digest section.
	DomainContactCounts map[string]int
	// AllowlistDomains lists the FQDN entries compiled into the defend
	// allowlist at agent startup (P1-1 6e cross-reference). Used by the
	// digest to produce a per-allowlist-domain contact summary so operators
	// can spot allowlist entries that observed zero egress this run —
	// candidates for trimming. Empty in detect mode.
	AllowlistDomains []string
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

// BPFCmdName returns the human-readable name for a bpf(2) command number
// (matches kernel UAPI bpf_cmd enum). Used in the BPF audit digest table.
func BPFCmdName(cmd uint32) string {
	switch cmd {
	case 0:
		return "BPF_MAP_CREATE"
	case 1:
		return "BPF_MAP_LOOKUP_ELEM"
	case 2:
		return "BPF_MAP_UPDATE_ELEM"
	case 3:
		return "BPF_MAP_DELETE_ELEM"
	case 4:
		return "BPF_MAP_GET_NEXT_KEY"
	case 5:
		return "BPF_PROG_LOAD"
	case 6:
		return "BPF_OBJ_PIN"
	case 7:
		return "BPF_OBJ_GET"
	case 8:
		return "BPF_PROG_ATTACH"
	case 9:
		return "BPF_PROG_DETACH"
	case 10:
		return "BPF_PROG_TEST_RUN"
	case 11:
		return "BPF_PROG_GET_NEXT_ID"
	case 12:
		return "BPF_MAP_GET_NEXT_ID"
	case 13:
		return "BPF_PROG_GET_FD_BY_ID"
	case 14:
		return "BPF_MAP_GET_FD_BY_ID"
	case 15:
		return "BPF_OBJ_GET_INFO_BY_FD"
	case 16:
		return "BPF_PROG_QUERY"
	case 17:
		return "BPF_RAW_TRACEPOINT_OPEN"
	case 18:
		return "BPF_BTF_LOAD"
	case 19:
		return "BPF_BTF_GET_FD_BY_ID"
	case 20:
		return "BPF_TASK_FD_QUERY"
	case 21:
		return "BPF_MAP_LOOKUP_AND_DELETE_ELEM"
	case 22:
		return "BPF_MAP_FREEZE"
	case 23:
		return "BPF_BTF_GET_NEXT_ID"
	case 24:
		return "BPF_MAP_LOOKUP_BATCH"
	case 25:
		return "BPF_MAP_LOOKUP_AND_DELETE_BATCH"
	case 26:
		return "BPF_MAP_UPDATE_BATCH"
	case 27:
		return "BPF_MAP_DELETE_BATCH"
	case 28:
		return "BPF_LINK_CREATE"
	case 29:
		return "BPF_LINK_UPDATE"
	case 30:
		return "BPF_LINK_GET_FD_BY_ID"
	case 31:
		return "BPF_LINK_GET_NEXT_ID"
	case 32:
		return "BPF_ENABLE_STATS"
	case 33:
		return "BPF_ITER_CREATE"
	case 34:
		return "BPF_LINK_DETACH"
	case 35:
		return "BPF_PROG_BIND_MAP"
	default:
		return "unknown"
	}
}
