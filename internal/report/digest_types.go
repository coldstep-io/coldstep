package report

import (
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
	DefendDenyReserveFailures int
	DefendFirstDeny           *DenyDigestRow

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
	// egress attempts observed by the P0-1 Phase 1 cgroup/connect6 and
	// cgroup/sendmsg6 hooks. coldstep defend mode is IPv4-only — non-zero
	// values mean traffic escaped enforcement entirely; the triage table
	// surfaces this as ⚠️ in detect mode and 🚨 in defend mode.
	IPv6ConnectObserved uint32
	IPv6SendmsgObserved uint32
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
	// CanaryPipelineOK reflects telemetry integrity canary status. When false,
	// the BPF ringbuf pipeline may be compromised (suppression, exhaustion).
	CanaryPipelineOK bool
	CanaryFailCount  int
	// TCPDNSResponsesObserved counts TCP DNS length-framed replies where the BPF
	// path could inspect the QR bit (trace_dns.bpf.c read/recvfrom sys_exit).
	TCPDNSResponsesObserved int
	// TCPDNSSkippedShortRead counts read(2) returns shorter than 6 bytes on the
	// TCP DNS path (partial segment — cannot validate length prefix + header).
	TCPDNSSkippedShortRead         int
	BPFHeartbeatFailures           int
	BPFAuditTotal                  int
	BPFAuditRows                   []BPFAuditDigestRow
	TruncatedBPFAudit              bool
	BPFAuditDegradedHook           bool
	BPFAuditReaderErrors           int
	BPFMapIntegrityFailures        int
	BPFAuditRingbufReserveFailures int
	DroppedCounts                  map[string]int

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
	// AllowlistAgeMinutes is minutes between allowlist compile time and digest
	// build time. Surfaces a TTL re-validation hint for long jobs; zero when no
	// allowlist was compiled.
	AllowlistAgeMinutes float64
	// DomainContactCounts maps observed FQDN → observation count across TCP +
	// UDP egress. Sorted descending by count in the digest section.
	DomainContactCounts map[string]int
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
