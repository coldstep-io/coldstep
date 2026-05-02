package telemetry

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"time"

	"github.com/coldstep-io/coldstep/internal/atomicwrite"
)

// AppendJSONL appends one JSON object line to path (create if missing).
// If s is non-nil, it signs the object and adds a "sig" field before writing.
func AppendJSONL(path string, v any, s *Signer) error {
	if path == "" {
		return nil
	}
	if s != nil {
		// We need to inject the signature. Since v is any, we can't easily set a field.
		// We'll marshal to map, sign, inject, and re-marshal.
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		sig := ed25519.Sign(s.priv, b)
		m["sig"] = base64.StdEncoding.EncodeToString(sig)
		b, err = json.Marshal(m)
		if err != nil {
			return err
		}
		return appendLine(path, b)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return appendLine(path, b)
}

func appendLine(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	line := append(append([]byte(nil), b...), '\n')
	_, werr := f.Write(line)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// Summary is written once at agent shutdown.
type Summary struct {
	Version                        int            `json:"version"`
	SchemaVersion                  int            `json:"schema_version"`
	Finished                       string         `json:"finished"`
	KernelRelease                  string         `json:"kernel_release,omitempty"`
	ExecEvents                     int            `json:"exec_events"`
	TCPEvents                      int            `json:"tcp_events"`
	UDPEvents                      int            `json:"udp_events"`
	HTTPEvents                     int            `json:"http_events"`
	TLSEvents                      int            `json:"tls_events,omitempty"`
	ProcForkEvents                 int            `json:"proc_fork_events,omitempty"`
	Connect4TupleUpdateFailures    int            `json:"connect4_tuple_update_failures,omitempty"`
	UDPRingbufReserveFailures      int            `json:"udp_ringbuf_reserve_failures,omitempty"`
	DNSRingbufReserveFailures      int            `json:"dns_ringbuf_reserve_failures,omitempty"`
	ConnectRingbufReserveFailures  int            `json:"connect_ringbuf_reserve_failures,omitempty"`
	HTTPRingbufReserveFailures     int            `json:"http_ringbuf_reserve_failures,omitempty"`
	TLSRingbufReserveFailures      int            `json:"tls_ringbuf_reserve_failures,omitempty"`
	ExecRingbufReserveFailures     int            `json:"exec_ringbuf_reserve_failures,omitempty"`
	ForkRingbufReserveFailures     int            `json:"fork_ringbuf_reserve_failures,omitempty"`
	FSRingbufReserveFailures       int            `json:"fs_ringbuf_reserve_failures,omitempty"`
	UDPSendmsgMultiIovecObserved   int            `json:"udp_sendmsg_multi_iovec_observed,omitempty"`
	TLSWritevMultiIovecObserved    int            `json:"tls_writev_multi_iovec_observed,omitempty"`
	UnobservedEgressSyscalls       int            `json:"unobserved_egress_syscalls_observed,omitempty"`
	IoUringSetupObserved           int            `json:"io_uring_setup_observed,omitempty"`
	TCPDNSResponsesObserved        int            `json:"tcp_dns_responses_observed,omitempty"`
	BPFAuditEvents                 int            `json:"bpf_audit_events,omitempty"`
	BPFHeartbeatFailures           int            `json:"bpf_heartbeat_failures,omitempty"`
	BPFMapIntegrityFailures        int            `json:"bpf_map_integrity_failures,omitempty"`
	BPFDNSCacheUpdateFailures      int            `json:"bpf_dns_cache_update_failures,omitempty"`
	BPFAuditRingbufReserveFailures int            `json:"bpf_audit_ringbuf_reserve_failures,omitempty"`
	DroppedCounts                  map[string]int `json:"dropped_counts,omitempty"`
	PolicyCounts                   map[string]int `json:"policy_counts"`
	BPF                            []BPFStatus    `json:"bpf,omitempty"`
	Signature                      string         `json:"signature,omitempty"`
	PublicKey                      string         `json:"public_key,omitempty"`
}

// WriteSummary writes telemetry summary JSON (overwrites).
// If s is non-nil, it signs the summary and embeds the signature.
func WriteSummary(path string, s Summary, signer *Signer) error {
	if path == "" {
		return nil
	}
	if s.Version == 0 {
		s.Version = 2
	}
	if s.SchemaVersion == 0 {
		s.SchemaVersion = SchemaVersion
	}
	if s.Finished == "" {
		s.Finished = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if s.PolicyCounts == nil {
		s.PolicyCounts = map[string]int{}
	}
	if signer != nil {
		s.PublicKey = signer.PublicKey()
		// Clear signature for hashing
		s.Signature = ""
		b, err := json.Marshal(s)
		if err != nil {
			return err
		}
		sig := ed25519.Sign(signer.priv, b)
		s.Signature = base64.StdEncoding.EncodeToString(sig)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicwrite.Bytes(path, b, 0o644)
}
