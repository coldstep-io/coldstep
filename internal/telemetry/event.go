package telemetry

import (
	"encoding/json"
	"sync"
)

// SchemaVersion is bumped when JSONL field shapes change incompatibly.
const SchemaVersion = 2

// EventTypeQUICCandidate is the JSONL "type" value for synthetic QUIC/HTTP3
// candidate events derived from UDP egress on port 443 to non-loopback IPv4.
const EventTypeQUICCandidate = "quic_candidate"

// BPFStatus records attach outcome for forensics (meta + shutdown summary).
type BPFStatus struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	// BTFAvailable, when set, records the result of the early kernel BTF
	// availability probe (see internal/agent.probeBTF). It is populated on
	// the synthetic "btf" status row so .coldstep-telemetry.json carries
	// an explicit signal that all CO-RE-relocated programs had a kernel
	// BTF spec to bind against.
	BTFAvailable bool `json:"btf_available,omitempty"`
}

// CompatWarning is a non-fatal runner-compatibility signal emitted at agent
// startup. Detect mode always proceeds even when warnings fire — these are
// observations for operators about runner environments (DinD, BuildKit,
// service containers) that may interfere with cgroup BPF attachment.
type CompatWarning struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// MetaEvent is the recommended first JSONL line (run context, no secrets).
type MetaEvent struct {
	Type          string          `json:"type"` // "meta"
	SchemaVersion int             `json:"schema_version"`
	TS            string          `json:"ts"`
	AgentVersion  string          `json:"agent_version"`
	KernelRelease string          `json:"kernel_release"`
	GitHub        MetaGitHub      `json:"github"`
	BPF           []BPFStatus     `json:"bpf"`
	Capabilities  map[string]bool `json:"capabilities,omitempty"`
	DetectProfile string          `json:"detect_profile,omitempty"` // "standard" | "enhanced" (from COLDSTEP_DETECT_PROFILE)
	// AllowlistIPCount snapshots the number of unique IPv4 addresses produced by
	// compiling the domain allowlist (P1-1 6a). Zero when not in defend mode.
	AllowlistIPCount int `json:"allowlist_ip_count,omitempty"`
	// AllowlistEntryCount snapshots the total number of /32 + CIDR entries
	// programmed into the BPF allowed_ipv4 LPM trie at startup (H12). Distinct
	// from AllowlistIPCount, which counts domain-resolved IPv4 addresses only;
	// AllowlistEntryCount also includes literal `allowed-ips` entries (single
	// IPs and CIDR ranges) merged into the trie. Surfaced in the digest as a
	// reminder that the allowlist is fixed at startup until the next agent
	// restart.
	AllowlistEntryCount int `json:"allowlist_entry_count,omitempty"`
	// WildcardRiskDomains lists allowlist entries (e.g. `*.s3.amazonaws.com`)
	// whose wildcard suffix matches a known multi-tenant shared-infrastructure
	// surface (P1-1 6c). Operators can review and tighten if desired.
	WildcardRiskDomains []string `json:"wildcard_risk_domains,omitempty"`
	// UnresolvedDomains lists allowlist domain entries that produced no IPv4
	// A-records at startup. Empty in detect mode. Surfaced in the digest as a
	// warning so operators can see fail-open risk at run start.
	UnresolvedDomains []string `json:"unresolved_domains,omitempty"`
	// RunnerHasIPv6 is true when the runner had at least one non-loopback,
	// non-link-local IPv6 address at agent startup (H1: digest honesty).
	// Used by the digest to downgrade the ✅ verdict to ⚠️ when the runner
	// has IPv6 but no IPv6 hooks are loaded — observation is incomplete on
	// that environment. Population is the action layer's job; the field is
	// pre-wired here so consumers can rely on it before that lands.
	RunnerHasIPv6 bool `json:"runner_has_ipv6,omitempty"`
	// DroppedEvents counts ringbuffer reserve failures per event type at shutdown.
	// Non-zero values indicate silent event loss during the run. Keys are the BPF
	// counter names minus the `_ringbuf_reserve_failures` suffix (e.g. "connect",
	// "udp", "http", "tls", "deny", "io_uring"). Only emitted on the shutdown
	// MetaEvent; the startup MetaEvent leaves this nil (omitted). The map is set
	// to nil when all counters are zero so omitempty hides it entirely.
	DroppedEvents map[string]uint64 `json:"dropped_events,omitempty"`
	// Coverage is the H5 v0.2.9 telemetry stub — structured per-run summary
	// of which traffic classes coldstep observed. It is the machine-readable
	// twin of the digest's "Coverage scope" table; the digest already
	// renders this information via H1 (PR #193).
	Coverage *CoverageReport `json:"coverage,omitempty"`
	Sig      string          `json:"sig,omitempty"`
}

// CoverageReport summarizes which traffic classes coldstep observed on this
// run. H5 v0.2.9 telemetry stub: emitted in the MetaEvent so downstream
// consumers can reason about the observation envelope without re-deriving it
// from individual probe-attach rows.
//
// IPv6 and QUICHTTP3 are wired as `false` for v0.2.9 because the underlying
// probes are not yet implemented in the agent. They ship as explicit fields
// (not omitempty) so consumers can rely on the shape being stable as those
// probes land.
type CoverageReport struct {
	IPv4TCP        bool `json:"ipv4_tcp"`
	IPv4UDPSendmsg bool `json:"ipv4_udp_sendmsg"`
	IPv6           bool `json:"ipv6"`
	QUICHTTP3      bool `json:"quic_http3"`
	// TLSSNI is "full" when the TLS ClientHello sniff probe attached and the
	// tls_sni feature gate is on, "none" otherwise. "partial" is reserved for
	// future probe variants that capture some-but-not-all SNI sources.
	TLSSNI  string `json:"tls_sni_full"`
	IoUring bool   `json:"io_uring"`
}

// MetaGitHub holds non-secret GitHub Actions context.
type MetaGitHub struct {
	Repository string `json:"repository,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	RunAttempt string `json:"run_attempt,omitempty"`
	Job        string `json:"job,omitempty"`
	SHA        string `json:"sha,omitempty"`
	Ref        string `json:"ref,omitempty"`
	Actor      string `json:"actor,omitempty"`
}

// ExecEvent is one JSONL record for sched_process_exec.
type ExecEvent struct {
	Type     string `json:"type"` // "exec"
	TS       string `json:"ts"`
	Seq      uint64 `json:"seq"`
	PID      uint32 `json:"pid"` // TGID (compat field name, matches other event types)
	TGID     uint32 `json:"tgid"`
	ThreadID uint32 `json:"thread_id"`
	Comm     string `json:"comm"`
	// Exe is the executable path from the tracepoint (BPF-capped; may be truncated vs kernel path).
	Exe string `json:"exe,omitempty"`
	Sig string `json:"sig,omitempty"`
}

// ProcForkEvent is one JSONL record for sched_process_fork (parent/child ids are kernel-reported; best-effort TGID on typical kernels).
type ProcForkEvent struct {
	Type          string `json:"type"` // "proc_fork"
	TS            string `json:"ts"`
	Seq           uint64 `json:"seq"`
	ParentPID     uint32 `json:"parent_pid"`
	ChildPID      uint32 `json:"child_pid"`
	ParentComm    string `json:"parent_comm"`
	ChildComm     string `json:"child_comm"`
	ChildSID      uint32 `json:"child_sid,omitempty"`        // v0.3: session leader PID
	ChildPidnsNum uint32 `json:"child_pidns_inum,omitempty"` // v0.3: PID namespace inode
	Note          string `json:"note,omitempty"`
	Sig           string `json:"sig,omitempty"`
}

// EventTypeTCPState is the JSONL `type` discriminator for kernel-confirmed
// TCP handshake state transitions emitted by the inet_sock_set_state
// tracepoint (P3-2b). It is separate from `tcp`, which records the
// best-effort syscall-enter connect attempt before the handshake resolves.
const EventTypeTCPState = "tcp_state"

// TCP state strings used in TCPStateEvent.OldState / NewState. These mirror
// the kernel `enum sk_state` values (include/net/tcp_states.h) — we only emit
// a small subset because the BPF filter restricts events to oldstate ==
// SYN_SENT, so newstate is realistically ESTABLISHED, CLOSE, or one of the
// fast-failure transitions.
const (
	TCPStateSynSent     = "SYN_SENT"
	TCPStateEstablished = "ESTABLISHED"
	TCPStateClose       = "CLOSE"
	TCPStateCloseWait   = "CLOSE_WAIT"
	TCPStateFinWait1    = "FIN_WAIT1"
	TCPStateFinWait2    = "FIN_WAIT2"
	TCPStateTimeWait    = "TIME_WAIT"
	TCPStateLastAck     = "LAST_ACK"
	TCPStateListen      = "LISTEN"
	TCPStateClosing     = "CLOSING"
	TCPStateSynRecv     = "SYN_RECV"
	TCPStateNewSynRecv  = "NEW_SYN_RECV"
)

// TCPStateName returns the canonical state string for a kernel TCP state
// integer (1..12, matching enum sk_state). Returns "UNKNOWN" for values
// outside that range.
func TCPStateName(s int32) string {
	switch s {
	case 1:
		return TCPStateEstablished
	case 2:
		return TCPStateSynSent
	case 3:
		return TCPStateSynRecv
	case 4:
		return TCPStateFinWait1
	case 5:
		return TCPStateFinWait2
	case 6:
		return TCPStateTimeWait
	case 7:
		return TCPStateClose
	case 8:
		return TCPStateCloseWait
	case 9:
		return TCPStateLastAck
	case 10:
		return TCPStateListen
	case 11:
		return TCPStateClosing
	case 12:
		return TCPStateNewSynRecv
	default:
		return "UNKNOWN"
	}
}

// TCPStateEvent is one JSONL record for a kernel-confirmed TCP handshake
// state transition observed via `tp/sock/inet_sock_set_state`. The BPF
// program filters to outgoing IPv4 TCP connects (oldstate == SYN_SENT), so
// NewState tells you whether the handshake succeeded (ESTABLISHED) or
// failed (CLOSE — RST / unreachable / timeout).
//
// PID and Comm are best-effort: the tracepoint fires in softirq context
// when the SYN-ACK arrives, so the running task may be a softirq, not the
// original connecting process. Tuple correlation with a preceding `tcp`
// event (same dst_ip:dst_port within a short window) is more reliable.
type TCPStateEvent struct {
	Type        string `json:"type"` // "tcp_state"
	TS          string `json:"ts"`
	Seq         uint64 `json:"seq"`
	TimestampNS uint64 `json:"timestamp_ns,omitempty"`
	PID         uint32 `json:"pid"`
	Comm        string `json:"comm,omitempty"`
	SrcIP       string `json:"src_ip,omitempty"`
	SrcPort     uint16 `json:"src_port,omitempty"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	OldState    string `json:"old_state"`
	NewState    string `json:"new_state"`
	Sig         string `json:"sig,omitempty"`
}

// TCPEvent is one JSONL record for an observed IPv4 connect attempt.
type TCPEvent struct {
	Type           string `json:"type"` // "tcp"
	TS             string `json:"ts"`
	Seq            uint64 `json:"seq"`
	PID            uint32 `json:"pid"` // tgid (compat field name)
	TGID           uint32 `json:"tgid"`
	ThreadID       uint32 `json:"thread_id"`
	Comm           string `json:"comm"`
	Dst            string `json:"dst"`
	Dport          uint16 `json:"dport"`
	FQDN           string `json:"fqdn,omitempty"`
	FQDNProvenance string `json:"fqdn_provenance,omitempty"`
	Direction      string `json:"direction"`
	Policy         string `json:"policy"`
	Sig            string `json:"sig,omitempty"`
}

// TCPResultEvent records the tcp_v4_connect return code captured by the
// paired kprobe/kretprobe (P3-2). It is correlated with the entry-side
// TCPEvent by (PID, TGID, ThreadID, comm) — the kretprobe runs in the
// caller's task context, so thread_id matches the connect(2) caller.
// Result is 0 on success or a negative errno; ResultStr is a coarse
// classification ("established", "refused", "timeout", "unreachable",
// "in_progress", "other") suitable for KPI rollups.
type TCPResultEvent struct {
	Type      string `json:"type"` // "tcp_result"
	TS        string `json:"ts"`
	Seq       uint64 `json:"seq"`
	PID       uint32 `json:"pid"` // tgid (compat field name)
	TGID      uint32 `json:"tgid"`
	ThreadID  uint32 `json:"thread_id"`
	Comm      string `json:"comm"`
	Result    int32  `json:"result"`     // 0 = success, otherwise negative errno
	ResultStr string `json:"result_str"` // "established" | "refused" | "timeout" | "unreachable" | "in_progress" | "other"
	Sig       string `json:"sig,omitempty"`
}

// UDPEvent is one JSONL record for IPv4 sendto egress.
type UDPEvent struct {
	Type           string `json:"type"` // "udp"
	TS             string `json:"ts"`
	Seq            uint64 `json:"seq"`
	PID            uint32 `json:"pid"`
	TGID           uint32 `json:"tgid"`
	ThreadID       uint32 `json:"thread_id"`
	Comm           string `json:"comm"`
	Dst            string `json:"dst"`
	Dport          uint16 `json:"dport"`
	DatagramLen    uint32 `json:"datagram_len,omitempty"`
	FQDN           string `json:"fqdn,omitempty"`
	FQDNProvenance string `json:"fqdn_provenance,omitempty"`
	Direction      string `json:"direction"`
	Policy         string `json:"policy"`
	Sig            string `json:"sig,omitempty"`
}

// HTTPEvent is one JSONL record for cleartext HTTP/1.x request prefix (BPF-capped).
type HTTPEvent struct {
	Type     string `json:"type"` // "http"
	TS       string `json:"ts"`
	Seq      uint64 `json:"seq"`
	PID      uint32 `json:"pid"`
	TGID     uint32 `json:"tgid"`
	ThreadID uint32 `json:"thread_id"`
	Comm     string `json:"comm"`
	Method   string `json:"method"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	Dst      string `json:"dst"`
	Dport    uint16 `json:"dport"`
	Policy   string `json:"policy"`
	Sig      string `json:"sig,omitempty"`
}

// TLSConfidence indicates how reliably the SNI on a TLSEvent was captured.
//
//   - "full":     SNI present in ClientHello, length below the RFC 1035
//     server-name boundary — best-effort but not truncated.
//   - "partial":  SNI length hit the BPF/RFC capture boundary (TLSSNIMaxLen);
//     the captured value may be a prefix of the real server name.
//   - "inferred": SNI was inferred from rDNS or prior connection state
//     (reserved for future enrichers; not yet emitted by the BPF path).
//   - "unknown":  no usable SNI signal was captured.
//
// Operators reading the JSONL / digest can use the field to weigh how much to
// trust an SNI-based allow/deny match.
type TLSConfidence string

const (
	TLSConfidenceFull     TLSConfidence = "full"
	TLSConfidencePartial  TLSConfidence = "partial"
	TLSConfidenceInferred TLSConfidence = "inferred"
	TLSConfidenceUnknown  TLSConfidence = "unknown"
)

// TLSSNIMaxLen is the maximum SNI host_name length the SNI parser accepts
// (RFC 1035 §2.3.4 — labels add to 255 octets max). When the captured SNI
// length is exactly TLSSNIMaxLen we cannot tell whether the real server name
// was longer, so confidence drops to TLSConfidencePartial.
const TLSSNIMaxLen = 255

// ScoreTLSConfidence classifies the SNI captured for a TLS ClientHello event
// using only the parsed SNI string. The function is intentionally a pure
// helper so it is straightforward to unit-test and reuse from non-Linux
// callers (replay, fuzz tooling).
//
// Inputs:
//
//   - sni: the host_name parsed out of the ClientHello (lower-cased,
//     trimmed). Empty when no SNI was usable.
//
// The function does not consult rDNS or any prior connection state today;
// TLSConfidenceInferred is reserved for a future enricher.
func ScoreTLSConfidence(sni string) TLSConfidence {
	if sni == "" {
		return TLSConfidenceUnknown
	}
	if len(sni) >= TLSSNIMaxLen {
		return TLSConfidencePartial
	}
	return TLSConfidenceFull
}

// TLSEvent is one JSONL record for TLS ClientHello SNI observed on egress (detect).
// Dst holds either a dotted-quad IPv4 (e.g. "1.2.3.4") or a plain IPv6 string
// (e.g. "2001:db8::1") with no brackets — IsIPv6 distinguishes the two. The
// markdown digest applies "[…]:port" bracket notation when rendering IPv6.
type TLSEvent struct {
	Type       string        `json:"type"` // "tls"
	TS         string        `json:"ts"`
	Seq        uint64        `json:"seq"`
	PID        uint32        `json:"pid"`
	TGID       uint32        `json:"tgid"`
	ThreadID   uint32        `json:"thread_id"`
	Comm       string        `json:"comm"`
	SNI        string        `json:"sni"`
	Confidence TLSConfidence `json:"confidence,omitempty"`
	// ConfidenceReason is an open-string tag explaining a non-default
	// Confidence verdict. Current values:
	//   - "ktls" — Confidence forced to "unknown" because trace_ktls observed
	//     setsockopt(SOL_TLS) on this socket; the captured SNI (if any) is a
	//     pre-offload artifact and the in-kernel TLS encryption blinds the
	//     userspace ClientHello sniffer for the rest of the connection (P4).
	//   - "" — Confidence speaks for itself; no extra qualifier required.
	// Kept as a free-form string (not an enum) so future enrichers can
	// add their own reasons without churning the event schema.
	ConfidenceReason string `json:"confidence_reason,omitempty"`
	// ReassembledSNI is true when the SNI was recovered by stitching multiple
	// write/writev/sendto syscall buffers together (P3-3 inter-syscall
	// reassembly) rather than parsed from a single capture. It is independent
	// of Confidence (which scores the SNI string itself); a reassembled SNI
	// can still be Confidence="full" if its length is well under the RFC
	// boundary.
	ReassembledSNI bool   `json:"reassembled_sni,omitempty"`
	Dst            string `json:"dst"`
	Dport          uint16 `json:"dport"`
	IsIPv6         bool   `json:"ipv6,omitempty"`
	Policy         string `json:"policy"`
	Note           string `json:"note,omitempty"`
	Sig            string `json:"sig,omitempty"`
}

// QUICCandidateEvent is emitted when a UDP egress to port 443 on a non-loopback
// IPv4 address is observed. QUIC payloads are encrypted at the transport layer
// and cannot be inspected by the BPF probes — this event signals a *likely*
// QUIC/HTTP3 flow so operators can see the visibility gap without scanning
// raw UDP JSONL. It is a userspace-derived heuristic emitted alongside the
// underlying UDPEvent, not a separate BPF ringbuf source.
type QUICCandidateEvent struct {
	Type    string `json:"type"` // "quic_candidate"
	TS      string `json:"ts"`
	Seq     uint64 `json:"seq"`
	PID     uint32 `json:"pid"` // tgid (compat field name)
	TGID    uint32 `json:"tgid"`
	Comm    string `json:"comm"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"` // always 443
	Note    string `json:"note,omitempty"`
	Sig     string `json:"sig,omitempty"`
}

// EventTypeIPv6TCP and EventTypeIPv6UDP are JSONL `type` discriminators for
// observe-only IPv6 egress events emitted by the H7 traceipv6 BPF object.
// The cgroup/connect6 hook produces "tcp6" records; cgroup/sendmsg6 produces
// "udp6". These are detect-mode-only — defend mode loads its own IPv6
// cgroup hooks from the defend object instead.
const (
	EventTypeIPv6TCP = "tcp6"
	EventTypeIPv6UDP = "udp6"
)

// IPv6NotEnforcedNote is the canonical value of IPv6Event.Note. The defend
// allowlist surface is IPv4-only when the H7 hook fires (detect mode), so
// the event is purely informational — surfaced in the digest as a warning
// that switching to defend would still allow IPv6 unless the P2-1 Phase 2
// IPv6 LPM trie was populated.
const IPv6NotEnforcedNote = "ipv6-not-enforced"

// IPv6Event is one JSONL record for an observe-only IPv6 egress attempt
// captured by the H7 traceipv6 BPF object (cgroup/connect6 +
// cgroup/sendmsg6). Loopback (::1) and link-local (fe80::/10) destinations
// are filtered out in BPF so they never reach userspace; everything that
// does reach this struct is a non-trivial IPv6 destination the IPv4-only
// defend allowlist would not gate.
//
// Type is "tcp6" when emitted from cgroup/connect6 and "udp6" from
// cgroup/sendmsg6. Dst is the plain IPv6 string (no brackets, no zone id);
// the digest applies "[…]:port" notation when rendering. Note is always
// IPv6NotEnforcedNote so downstream filters can locate these events
// without parsing the type discriminator.
type IPv6Event struct {
	Type  string `json:"type"` // "tcp6" | "udp6"
	TS    string `json:"ts"`
	Seq   uint64 `json:"seq"`
	PID   uint32 `json:"pid"`
	Comm  string `json:"comm"`
	Dst   string `json:"dst"`
	Dport uint16 `json:"dport"`
	Note  string `json:"note,omitempty"`
	Sig   string `json:"sig,omitempty"`
}

// FSEvent is one JSONL record for a high-signal filesystem operation (detect, feature-gated).
type FSEvent struct {
	Type     string `json:"type"` // "fs_event"
	TS       string `json:"ts"`
	Seq      uint64 `json:"seq"`
	PID      uint32 `json:"pid"` // tgid alias – compat field name shared across event types
	TGID     uint32 `json:"tgid"`
	ThreadID uint32 `json:"thread_id"`
	Comm     string `json:"comm"`
	Op       string `json:"op"`   // "create" | "unlink" | "rename" | "chmod"
	Path     string `json:"path"` // from userspace buffer (BPF-capped 256 bytes)
	Note     string `json:"note,omitempty"`
	Sig      string `json:"sig,omitempty"`
}

// DenyEvent is one JSONL record for a defend-mode blocked egress attempt.
type DenyEvent struct {
	Type     string `json:"type"` // "deny"
	TS       string `json:"ts"`
	Seq      uint64 `json:"seq"`
	PID      uint32 `json:"pid"`
	TGID     uint32 `json:"tgid"`
	ThreadID uint32 `json:"thread_id"`
	Comm     string `json:"comm"`
	Protocol string `json:"protocol"` // "tcp" | "udp"
	Dst      string `json:"dst"`
	Dport    uint16 `json:"dport"`
	Reason   string `json:"reason"`
	Mode     string `json:"mode"` // "defend" (blocking)
	// HookFamily is "lsm" or "cgroup" when known (which deny ring handled the event).
	HookFamily string `json:"hook_family,omitempty"`
	// MatchKind is "dns_cache" if Dst had a cached DNS owner name at emission time, else "unknown".
	MatchKind string `json:"match_kind,omitempty"`
	Sig       string `json:"sig,omitempty"`
}

// KTLSEvent is one JSONL record for a setsockopt(SOL_TLS, TLS_TX|TLS_RX)
// call — the moment a process hands TLS encryption off to the kernel. After
// this point the application writes plaintext while the kernel encrypts on the
// wire, so the userspace ClientHello SNI sniffer in trace_tls_write.inc only
// observes raw record fragments and cannot resolve SNI. The event lets the
// digest call out KTLS-offloaded sockets as deliberately invisible to SNI
// capture rather than silently producing low-confidence rows.
type KTLSEvent struct {
	Type      string `json:"type"` // "ktls_offload"
	TS        string `json:"ts"`
	Seq       uint64 `json:"seq"`
	PID       uint32 `json:"pid"` // tgid (compat field name)
	TGID      uint32 `json:"tgid"`
	ThreadID  uint32 `json:"thread_id"`
	Comm      string `json:"comm"`
	FD        uint32 `json:"fd"`
	Direction string `json:"direction"` // "tx" | "rx"
	Sig       string `json:"sig,omitempty"`
}

// EventTypeKTLS is the JSONL discriminator for KTLSEvent.
const EventTypeKTLS = "ktls_offload"

// IOUringSendEvent is one JSONL record for an io_uring socket-class SQE
// submission observed via SEC("raw_tp/io_uring_submit_sqe"). The probe
// emits for IORING_OP_SENDMSG (9) and IORING_OP_SEND (26) only — both
// unambiguous network sends. The event surfaces io_uring egress that would
// otherwise bypass syscall-based hooks; SNI / payload extraction is not
// possible from the SQE submission point alone. dst_ip / dst_port are
// reserved for a future fd→socket resolution arm; current revisions leave
// them empty.
//
// HasTLSHello is the Phase 2 enhanced-profile signal: when
// COLDSTEP_DETECT_PROFILE=enhanced, the BPF program performs a best-effort
// bpf_probe_read_user on the SQE's user-buffer pointer and matches the
// first 6 bytes against the TLS ClientHello record signature. The flag is
// always false outside the enhanced profile.
type IOUringSendEvent struct {
	Type        string `json:"type"` // "io_uring_send"
	TS          string `json:"ts"`
	Seq         uint64 `json:"seq"`
	PID         uint32 `json:"pid"`
	Comm        string `json:"comm"`
	FD          uint32 `json:"fd"`
	Op          string `json:"op"` // "WRITEV" | "SENDMSG" | "WRITE" | "SEND" | "UNKNOWN"
	DstIP       string `json:"dst_ip,omitempty"`
	DstPort     uint16 `json:"dst_port,omitempty"`
	HasTLSHello bool   `json:"has_tls_hello,omitempty"`
	Sig         string `json:"sig,omitempty"`
}

// BPFAuditEvent is one JSONL record for a bpf(2) syscall audit event.
type BPFAuditEvent struct {
	Type     string `json:"type"` // "bpf_audit"
	TS       string `json:"ts"`
	Seq      uint64 `json:"seq"`
	PID      uint32 `json:"pid"`
	TGID     uint32 `json:"tgid"`
	ThreadID uint32 `json:"thread_id"`
	Comm     string `json:"comm"`
	Cmd      uint32 `json:"cmd"` // BPF_PROG_LOAD, BPF_MAP_CREATE, etc.
	Sig      string `json:"sig,omitempty"`
}

// BPFTamperEvent is one JSONL record for a detected BPF map or program tampering event.
type BPFTamperEvent struct {
	Type     string `json:"type"` // "bpf_tamper"
	TS       string `json:"ts"`
	Seq      uint64 `json:"seq"`
	Asset    string `json:"asset"` // e.g. "map:defend_cfg"
	Error    string `json:"error"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Sig      string `json:"sig,omitempty"`
}

// SeqGen assigns monotonic per-run sequence numbers in userspace.
type SeqGen struct {
	mu   sync.Mutex
	next uint64
}

func (s *SeqGen) Next() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return s.next
}

// Last returns the highest assigned sequence (0 if none).
func (s *SeqGen) Last() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}

// RedactPathForSummary masks secrets and auth-related query parameters (and common token patterns)
// in a request path or URI for Job Summary / digest tables. Non-credential query keys are kept.
func RedactPathForSummary(path string) string {
	return SanitizeRequestURI(path)
}

// EventType returns the discriminated type field for a JSONL line, or "" if missing.
func EventType(line []byte) string {
	var head struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(line, &head) != nil {
		return ""
	}
	return head.Type
}
