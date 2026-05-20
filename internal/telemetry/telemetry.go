package telemetry

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
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
		// Marshal to map, then sign the canonical map JSON (sorted keys). Signing the
		// struct-marshaled bytes and writing map-marshaled bytes made signatures
		// unverifiable — struct field order ≠ alphabetical map key order.
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		bCanon, err := json.Marshal(m)
		if err != nil {
			return err
		}
		sig := ed25519.Sign(s.priv, bCanon)
		m["sig"] = base64.StdEncoding.EncodeToString(sig)
		bFinal, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return appendLine(path, bFinal)
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
		return errors.Join(werr, cerr)
	}
	return cerr
}

// SumRingbufReserveFailuresDetectPath sums the nine per-channel ringbuf reserve failure
// counters on the detect telemetry path. Defend deny-event ring reserves are separate.
//
// Callers: internal/agent snapshotSummary (RingbufReserveFailuresTotal) and
// internal/report digest totals — keep parameter order stable when adding channels.
func SumRingbufReserveFailuresDetectPath(
	udp, dns, connect, http, tlsRingbuf, execRingbuf, forkRingbuf, fsRingbuf, bpfAuditRingbuf int,
) int {
	return udp + dns + connect + http + tlsRingbuf + execRingbuf + forkRingbuf + fsRingbuf + bpfAuditRingbuf
}

// Summary is written once at agent shutdown. Non-zero partial-visibility counters
// (unobserved syscalls, io_uring_setup, ringbuf reserves) need SECURITY.md context to interpret.
type Summary struct {
	Version       int    `json:"version"`
	SchemaVersion int    `json:"schema_version"`
	Finished      string `json:"finished"`
	KernelRelease string `json:"kernel_release,omitempty"`
	ExecEvents    int    `json:"exec_events"`
	TCPEvents     int    `json:"tcp_events"`
	UDPEvents     int    `json:"udp_events"`
	HTTPEvents    int    `json:"http_events"`
	TLSEvents     int    `json:"tls_events,omitempty"`
	// KTLSOffloadEvents counts setsockopt(fd, SOL_TLS, TLS_TX|TLS_RX, ...) calls
	// observed during the run. Non-zero means at least one socket handed TLS
	// encryption to the kernel; the userspace ClientHello SNI sniffer cannot
	// resolve SNI on KTLS-offloaded sockets (kernel writes ciphertext while the
	// app writes plaintext). See SECURITY.md (TLS / SNI capture caveats).
	KTLSOffloadEvents          int `json:"ktls_offload_events,omitempty"`
	KTLSRingbufReserveFailures int `json:"ktls_ringbuf_reserve_failures,omitempty"`
	// TLSConfidenceFull / Partial / Inferred / Unknown count TLS events by the
	// reliability of the captured SNI (H8). They are the public twin of the
	// runStats.tlsConfidence*N counters that already feed the digest KPI row;
	// surfacing them in .coldstep-telemetry.json lets downstream consumers
	// (the report tooling, dashboards) read a confidence breakdown without
	// re-parsing the JSONL stream.
	//
	// Tier semantics (mirrors telemetry.TLSConfidence):
	//   - full:     ClientHello parsed, SNI extracted below the RFC boundary.
	//   - partial:  SNI parsed but at the capture/RFC boundary (truncated).
	//   - inferred: SNI carried over from prior connect/DNS correlation
	//     (reserved; not emitted today).
	//   - unknown:  no usable SNI signal — includes the P4 KTLS override
	//     (see TLSConfidenceUnknownKTLS in the digest input for the subset
	//     attributed specifically to kernel-TLS offload).
	TLSConfidenceFull             uint64 `json:"tls_confidence_full,omitempty"`
	TLSConfidencePartial          uint64 `json:"tls_confidence_partial,omitempty"`
	TLSConfidenceInferred         uint64 `json:"tls_confidence_inferred,omitempty"`
	TLSConfidenceUnknown          uint64 `json:"tls_confidence_unknown,omitempty"`
	ProcForkEvents                int    `json:"proc_fork_events,omitempty"`
	Connect4TupleUpdateFailures   int    `json:"connect4_tuple_update_failures,omitempty"`
	UDPRingbufReserveFailures     int    `json:"udp_ringbuf_reserve_failures,omitempty"`
	DNSRingbufReserveFailures     int    `json:"dns_ringbuf_reserve_failures,omitempty"`
	ConnectRingbufReserveFailures int    `json:"connect_ringbuf_reserve_failures,omitempty"`
	HTTPRingbufReserveFailures    int    `json:"http_ringbuf_reserve_failures,omitempty"`
	TLSRingbufReserveFailures     int    `json:"tls_ringbuf_reserve_failures,omitempty"`
	ExecRingbufReserveFailures    int    `json:"exec_ringbuf_reserve_failures,omitempty"`
	ForkRingbufReserveFailures    int    `json:"fork_ringbuf_reserve_failures,omitempty"`
	FSRingbufReserveFailures      int    `json:"fs_ringbuf_reserve_failures,omitempty"`
	UDPSendmsgMultiIovecObserved  int    `json:"udp_sendmsg_multi_iovec_observed,omitempty"`
	// SendmmsgMultiMessage counts NR_SENDMMSG calls with vlen>1 (mmsghdr vector
	// length, distinct from per-message msg_iovlen). Messages 2..N are not
	// introspected — non-zero quantifies the multi-message silent gap (BG-03).
	SendmmsgMultiMessage int `json:"sendmmsg_multi_message_observed,omitempty"`
	// SendmmsgUnobservedExtra counts individual sendmmsg(2) extra messages
	// (beyond the unrolled SENDMMSG_EXTRA_MAX bound) that the BPF observation
	// loop could not reach. The loop walks messages 1..7 inline; this counter
	// quantifies how many message slots remain silent on vlen >= 9 calls
	// (BG-03 Gap 3 follow-up).
	SendmmsgUnobservedExtra     int `json:"sendmmsg_unobserved_extra,omitempty"`
	TLSWritevMultiIovecObserved int `json:"tls_writev_multi_iovec_observed,omitempty"`
	// SendfileObserved, SpliceObserved, SendmmsgFirstOnly are the BG-01
	// per-syscall partial-observe counters that supersede the previous aggregate
	// `unobserved_egress_syscalls_observed` field. Slots:
	//   - sendfile_observed:     sendfile(2) / sendfile64(2)
	//   - splice_observed:       splice(2)
	//   - sendmmsg_first_only:   sendmmsg(2) — only the first mmsghdr inspected
	SendfileObserved  int `json:"sendfile_observed,omitempty"`
	SpliceObserved    int `json:"splice_observed,omitempty"`
	SendmmsgFirstOnly int `json:"sendmmsg_first_only,omitempty"`
	// IPv6ConnectObserved / IPv6SendmsgObserved count non-loopback IPv6
	// egress attempts observed by the P0-1 Phase 1 cgroup/connect6 and
	// cgroup/sendmsg6 hooks. Phase 1 is observe-only — IPv6 enforcement
	// is not yet implemented, so non-zero values mean traffic escaped
	// the IPv4-only defend allowlist. The digest surfaces this gap.
	IPv6ConnectObserved uint32 `json:"ipv6_connect_observed,omitempty"`
	IPv6SendmsgObserved uint32 `json:"ipv6_sendmsg_observed,omitempty"`
	// SendpageObserved counts security_socket_sendpage() invocations recorded
	// by the lsm/socket_sendpage hook. Non-zero values mean sendfile(2) or
	// splice(2) reached a socket via the sock_sendpage path that
	// cgroup/sendmsg4 and lsm/socket_sendmsg cannot gate (kernel ≤ 6.7).
	// In defend mode the hook also enforces; in detect mode it's
	// visibility-only.
	SendpageObserved     uint32 `json:"sendpage_observed,omitempty"`
	IoUringSetupObserved int    `json:"io_uring_setup_observed,omitempty"`
	// IoUringSendTotal counts io_uring write-class SQE submissions observed
	// via SEC("raw_tp/io_uring_submit_sqe") on tracked sockets (P6 Phase 1).
	IoUringSendTotal int `json:"io_uring_send_total,omitempty"`
	// IoUringRingbufReserveFailures counts ringbuf reserve failures on the
	// io_uring_events channel (telemetry pressure on the io_uring probe).
	IoUringRingbufReserveFailures int `json:"io_uring_ringbuf_reserve_failures,omitempty"`
	// IoUringTLSHelloObserved counts io_uring SQE submissions whose user
	// buffer prefix matched the TLS ClientHello record signature (P6 Phase 2,
	// enhanced profile only). Always 0 outside COLDSTEP_DETECT_PROFILE=enhanced.
	IoUringTLSHelloObserved        int `json:"io_uring_tls_hello_observed,omitempty"`
	TCPDNSResponsesObserved        int `json:"tcp_dns_responses_observed,omitempty"`
	TCPDNSSkippedShortRead         int `json:"tcp_dns_skipped_short_read,omitempty"`
	BPFAuditEvents                 int `json:"bpf_audit_events,omitempty"`
	BPFHeartbeatFailures           int `json:"bpf_heartbeat_failures,omitempty"`
	BPFMapIntegrityFailures        int `json:"bpf_map_integrity_failures,omitempty"`
	BPFDNSCacheUpdateFailures      int `json:"bpf_dns_cache_update_failures,omitempty"`
	BPFAuditRingbufReserveFailures int `json:"bpf_audit_ringbuf_reserve_failures,omitempty"`
	// RingbufReserveFailuresTotal is the sum of per-channel ringbuf reserve failure
	// counters (detect-path telemetry only; excludes defend deny-event reserves).
	RingbufReserveFailuresTotal int            `json:"ringbuf_reserve_failures_total,omitempty"`
	DroppedCounts               map[string]int `json:"dropped_counts,omitempty"`
	PolicyCounts                map[string]int `json:"policy_counts"`
	BPF                         []BPFStatus    `json:"bpf,omitempty"`
	// CompatWarnings carries non-fatal runner-compatibility signals
	// captured at agent startup (cgroup-v1 detection, container-namespace
	// delegation, deep cgroup nesting). Empty when the runner looks normal.
	CompatWarnings []CompatWarning `json:"compat_warnings,omitempty"`
	Signature      string          `json:"signature,omitempty"`
	PublicKey      string          `json:"public_key,omitempty"`
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
