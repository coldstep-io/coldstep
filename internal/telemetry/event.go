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
	// WildcardRiskDomains lists allowlist entries (e.g. `*.s3.amazonaws.com`)
	// whose wildcard suffix matches a known multi-tenant shared-infrastructure
	// surface (P1-1 6c). Operators can review and tighten if desired.
	WildcardRiskDomains []string `json:"wildcard_risk_domains,omitempty"`
	Sig                 string   `json:"sig,omitempty"`
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
	// ReassembledSNI is true when the SNI was recovered by stitching multiple
	// write/writev/sendto syscall buffers together (P3-3 inter-syscall
	// reassembly) rather than parsed from a single capture. It is independent
	// of Confidence (which scores the SNI string itself); a reassembled SNI
	// can still be Confidence="full" if its length is well under the RFC
	// boundary.
	ReassembledSNI bool   `json:"reassembled_sni,omitempty"`
	Dst            string `json:"dst"`
	Dport          uint16 `json:"dport"`
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
