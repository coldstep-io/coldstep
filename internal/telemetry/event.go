package telemetry

import (
	"encoding/json"
	"sync"
)

// SchemaVersion is bumped when JSONL field shapes change incompatibly.
const SchemaVersion = 2

// BPFStatus records attach outcome for forensics (meta + shutdown summary).
type BPFStatus struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
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
}

// ProcForkEvent is one JSONL record for sched_process_fork (parent/child ids are kernel-reported; best-effort TGID on typical kernels).
type ProcForkEvent struct {
	Type       string `json:"type"` // "proc_fork"
	TS         string `json:"ts"`
	Seq        uint64 `json:"seq"`
	ParentPID  uint32 `json:"parent_pid"`
	ChildPID   uint32 `json:"child_pid"`
	ParentComm string `json:"parent_comm"`
	ChildComm  string `json:"child_comm"`
	Note       string `json:"note,omitempty"`
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
}

// TLSEvent is one JSONL record for TLS ClientHello SNI observed on egress (detect).
type TLSEvent struct {
	Type     string `json:"type"` // "tls"
	TS       string `json:"ts"`
	Seq      uint64 `json:"seq"`
	PID      uint32 `json:"pid"`
	TGID     uint32 `json:"tgid"`
	ThreadID uint32 `json:"thread_id"`
	Comm     string `json:"comm"`
	SNI      string `json:"sni"`
	Dst      string `json:"dst"`
	Dport    uint16 `json:"dport"`
	Policy   string `json:"policy"`
	Note     string `json:"note,omitempty"`
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
}

// DenyEvent is one JSONL record for an enforcement-mode blocked egress attempt.
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
	Mode     string `json:"mode"` // "enforce"
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
