//go:build linux

package agent

import (
	"encoding/binary"

	"github.com/coldstep-io/coldstep/internal/report"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

type execEvent struct {
	TGID    uint32
	TID     uint32
	Comm    [16]byte
	ExePath [256]byte
}

func decodeConnectEvent(raw []byte) (tgid, tid uint32, comm [16]byte, daddr [4]byte, dport uint16, ok bool) {
	if len(raw) < connectEventWireSize {
		return 0, 0, [16]byte{}, [4]byte{}, 0, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	copy(comm[:], raw[8:24])
	copy(daddr[:], raw[24:28])
	dport = binary.BigEndian.Uint16(raw[28:30])
	return tgid, tid, comm, daddr, dport, true
}

// decodeConnectResultEvent parses connect_result_event emitted by the
// kretprobe on tcp_v4_connect (P3-2). The first 4 bytes are
// connectResultMagic; the caller is expected to have already matched the
// magic before invoking this decoder.
func decodeConnectResultEvent(raw []byte) (tgid, tid uint32, comm [16]byte, result int32, ok bool) {
	if len(raw) < connectResultEventWireSize {
		return 0, 0, [16]byte{}, 0, false
	}
	// BPF stores the signed kernel return value (0 or negative errno) as
	// raw u32 bits via `(__u32)PT_REGS_RC(ctx)` in trace_tcp_connect_kprobe.inc.
	// Re-interpreting those bits as int32 here is the intended round-trip.
	// `// #nosec` is the gosec-native annotation (also honored by golangci-lint).
	result = int32(binary.LittleEndian.Uint32(raw[4:8])) // #nosec G115 -- intentional reinterpret-cast of BPF wire bits to int32 (signed errno).
	tgid = binary.LittleEndian.Uint32(raw[8:12])
	tid = binary.LittleEndian.Uint32(raw[12:16])
	copy(comm[:], raw[16:32])
	return tgid, tid, comm, result, true
}

// decodeUDPSendEvent parses udp_send_event. datagram_len lives at offset 32
// because of the explicit `__u8 _pad[2]` (offsets 30..32) added in
// trace_connect_obs.h. Reading from offset 30 like the prior implementation
// did yields garbage bytes from the implicit alignment pad.
func decodeUDPSendEvent(raw []byte) (tgid, tid uint32, comm [16]byte, daddr [4]byte, dport uint16, dgramLen uint32, ok bool) {
	if len(raw) < udpSendEventWireSize {
		return 0, 0, [16]byte{}, [4]byte{}, 0, 0, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	copy(comm[:], raw[8:24])
	copy(daddr[:], raw[24:28])
	dport = binary.BigEndian.Uint16(raw[28:30])
	dgramLen = binary.LittleEndian.Uint32(raw[32:36])
	return tgid, tid, comm, daddr, dport, dgramLen, true
}

const httpPayloadMax = 192

// decodeHTTPSniffEvent parses http_sniff_event (228 bytes with HTTP_PAYLOAD_MAX=192).
func decodeHTTPSniffEvent(raw []byte) (tgid, tid uint32, comm [16]byte, daddr [4]byte, dport uint16, payload []byte, ok bool) {
	if len(raw) < httpSniffEventWireSize {
		return 0, 0, [16]byte{}, [4]byte{}, 0, nil, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	copy(comm[:], raw[8:24])
	copy(daddr[:], raw[24:28])
	dport = binary.BigEndian.Uint16(raw[28:30])
	capLen := int(binary.LittleEndian.Uint16(raw[32:34]))
	// capLen is derived from Uint16 and cast to int on a 64-bit system;
	// it is always in [0, 65535]. Only the upper bound needs checking.
	if capLen > httpPayloadMax {
		return 0, 0, [16]byte{}, [4]byte{}, 0, nil, false
	}
	payload = make([]byte, capLen)
	copy(payload, raw[httpSniffEventHeaderSize:httpSniffEventHeaderSize+capLen])
	return tgid, tid, comm, daddr, dport, payload, true
}

const tlsPayloadMax = 256

// decodeTLSSniffEvent parses tls_sniff_event (header + payload[256] + IPv6 trailer).
// IPv4 path: isIPv6=false, daddr6 zeroed. IPv6 path: isIPv6=true, daddr zeroed
// in BPF and the v6 address is carried in daddr6. The wire layout preserves
// pre-P5 IPv4 byte positions; the IPv6 trailer is appended after payload.
func decodeTLSSniffEvent(raw []byte) (tgid, tid uint32, comm [16]byte, daddr [4]byte, dport uint16, payload []byte, daddr6 [16]byte, isIPv6 bool, ok bool) {
	if len(raw) < tlsSniffEventWireSize {
		return 0, 0, [16]byte{}, [4]byte{}, 0, nil, [16]byte{}, false, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	copy(comm[:], raw[8:24])
	copy(daddr[:], raw[24:28])
	dport = binary.BigEndian.Uint16(raw[28:30])
	capLen := int(binary.LittleEndian.Uint16(raw[32:34]))
	// capLen is derived from Uint16 and cast to int on a 64-bit system;
	// it is always in [0, 65535]. Only the upper bound needs checking.
	if capLen > tlsPayloadMax {
		return 0, 0, [16]byte{}, [4]byte{}, 0, nil, [16]byte{}, false, false
	}
	payload = make([]byte, capLen)
	copy(payload, raw[tlsSniffEventHeaderSize:tlsSniffEventHeaderSize+capLen])
	copy(daddr6[:], raw[tlsSniffEventIPv6Offset:tlsSniffEventIPv6Offset+16])
	isIPv6 = raw[tlsSniffEventIPv6Offset+16] != 0
	return tgid, tid, comm, daddr, dport, payload, daddr6, isIPv6, true
}

// decodeDNSSniffSample parses dns_sniff_event (trace_dns.bpf.c): len, is_tcp, pad, payload.
// Legacy ringbuf records are dnsSniffEventWireSizeLegacy (len + data only).
func decodeDNSSniffSample(raw []byte) (pkt []byte, isTCP bool, ok bool) {
	if len(raw) < 4 {
		return nil, false, false
	}
	n := binary.LittleEndian.Uint32(raw[0:4])
	if n > dnsSniffMaxPayload {
		return nil, false, false
	}
	if len(raw) == dnsSniffEventWireSizeLegacy {
		if int(n)+4 > len(raw) {
			return nil, false, false
		}
		return raw[4 : 4+int(n)], false, true
	}
	if len(raw) < dnsSniffEventWireSize {
		return nil, false, false
	}
	isTCP = raw[4] != 0
	if int(n)+8 > len(raw) {
		return nil, false, false
	}
	return raw[8 : 8+int(n)], isTCP, true
}

// decodeBPFAuditEvent parses trace_bpf_audit.bpf.c bpf_audit_event (tgid, tid, cmd, comm).
// BPF struct layout: tgid(0-3) tid(4-7) cmd(8-11) comm[16](12-27).
func decodeBPFAuditEvent(raw []byte) (tgid, tid uint32, comm [16]byte, cmd uint32, ok bool) {
	if len(raw) < bpfAuditEventWireSize {
		return 0, 0, [16]byte{}, 0, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	cmd = binary.LittleEndian.Uint32(raw[8:12])
	copy(comm[:], raw[12:28])
	return tgid, tid, comm, cmd, true
}

// decodeKTLSEvent parses struct ktls_event { __u32 tgid; __u32 tid; __u8 comm[16];
// __u32 fd; __u8 direction; __u8 _pad[3]; } from trace_ktls.bpf.c. Layout:
//
//	tgid(0-3) tid(4-7) comm[16](8-23) fd(24-27) direction(28) _pad[3](29-31)
func decodeKTLSEvent(raw []byte) (tgid, tid, fd uint32, comm [16]byte, direction uint8, ok bool) {
	if len(raw) < ktlsEventWireSize {
		return 0, 0, 0, [16]byte{}, 0, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	copy(comm[:], raw[8:24])
	fd = binary.LittleEndian.Uint32(raw[24:28])
	direction = raw[28]
	return tgid, tid, fd, comm, direction, true
}

func ktlsDirectionLabel(d uint8) string {
	switch d {
	case 1:
		return "tx"
	case 2:
		return "rx"
	default:
		return "unknown"
	}
}

// decodeTCPStateEvent parses tcp_state_event (P3-2b). Layout:
//
//	offset 0:  __u64 timestamp_ns
//	offset 8:  __u32 pid
//	offset 12: __u32 saddr (network byte order)
//	offset 16: __u32 daddr (network byte order)
//	offset 20: __u16 sport (host order)
//	offset 22: __u16 dport (host order)
//	offset 24: __s32 old_state
//	offset 28: __s32 new_state
//	offset 32: __u8  comm[16]
//
// Total: 48 bytes. saddr/daddr are returned as [4]byte slices in network
// byte order (same convention as connectEvent.daddr).
func decodeTCPStateEvent(raw []byte) (timestampNS uint64, pid uint32, saddr, daddr [4]byte,
	sport, dport uint16, oldState, newState int32, comm [16]byte, ok bool) {
	if len(raw) < tcpStateEventWireSize {
		return 0, 0, [4]byte{}, [4]byte{}, 0, 0, 0, 0, [16]byte{}, false
	}
	timestampNS = binary.LittleEndian.Uint64(raw[0:8])
	pid = binary.LittleEndian.Uint32(raw[8:12])
	copy(saddr[:], raw[12:16])
	copy(daddr[:], raw[16:20])
	sport = binary.LittleEndian.Uint16(raw[20:22])
	dport = binary.LittleEndian.Uint16(raw[22:24])
	oldState = int32(binary.LittleEndian.Uint32(raw[24:28])) // #nosec G115 -- intentional reinterpret-cast of BPF wire bits to int32 (kernel sk_state enum is C `int`).
	newState = int32(binary.LittleEndian.Uint32(raw[28:32])) // #nosec G115 -- intentional reinterpret-cast of BPF wire bits to int32 (kernel sk_state enum is C `int`).
	copy(comm[:], raw[32:48])
	return timestampNS, pid, saddr, daddr, sport, dport, oldState, newState, comm, true
}

// decodeIOUringSendEvent parses io_uring_send_event (40 bytes, see
// bpf/trace_connect_obs.h). Layout: ts(8) pid(4) fd(4) daddr(4) dport(2)
// op(1) has_tls_hello(1) comm(16). dport is stored in network byte order
// (mirrors the connect4_tuple cache), daddr is raw 4-byte big-endian.
// has_tls_hello is the Phase 2 enhanced-profile flag; 0 on standard profile
// kernels regardless of payload.
func decodeIOUringSendEvent(raw []byte) (ts uint64, pid uint32, fd uint32, daddr [4]byte, dport uint16, op uint8, hasTLSHello bool, comm [16]byte, ok bool) {
	if len(raw) < ioUringSendEventWireSize {
		return 0, 0, 0, [4]byte{}, 0, 0, false, [16]byte{}, false
	}
	ts = binary.LittleEndian.Uint64(raw[0:8])
	pid = binary.LittleEndian.Uint32(raw[8:12])
	fd = binary.LittleEndian.Uint32(raw[12:16])
	copy(daddr[:], raw[16:20])
	dport = binary.BigEndian.Uint16(raw[20:22])
	op = raw[22]
	hasTLSHello = raw[23] != 0
	copy(comm[:], raw[24:40])
	return ts, pid, fd, daddr, dport, op, hasTLSHello, comm, true
}

// decodeEgressBackstopEvent parses egress_backstop_event (56 bytes, see
// bpf/egress_backstop_event.h). daddr is the raw 16-byte address (IPv4 in the
// first 4 bytes when af==AF_INET); the caller renders it by af. dport is
// network byte order on the wire and returned host-order.
func decodeEgressBackstopEvent(raw []byte) (ts uint64, pid uint32, af uint8, ipproto uint8, daddr [16]byte, dport uint16, comm [16]byte, ok bool) {
	if len(raw) < egressBackstopEventWireSize {
		return 0, 0, 0, 0, [16]byte{}, 0, [16]byte{}, false
	}
	ts = binary.LittleEndian.Uint64(raw[0:8])
	pid = binary.LittleEndian.Uint32(raw[8:12])
	copy(comm[:], raw[12:28])
	af = raw[28]
	ipproto = raw[29]
	copy(daddr[:], raw[32:48])
	dport = binary.BigEndian.Uint16(raw[48:50])
	return ts, pid, af, ipproto, daddr, dport, comm, true
}

// decodeBpfSelfDefenseEvent parses bpf_self_defense_event (40 bytes, see
// bpf/bpf_self_defense_event.h). Layout: ts(8) comm(16) tgid(4) target_id(4)
// cmd(4, signed) target_kind(1) _pad(3). All multi-byte fields little-endian.
func decodeBpfSelfDefenseEvent(raw []byte) (ts uint64, comm [16]byte, tgid, targetID uint32, cmd int32, kind uint8, ok bool) {
	if len(raw) < bpfSelfDefenseEventWireSize {
		return 0, [16]byte{}, 0, 0, 0, 0, false
	}
	ts = binary.LittleEndian.Uint64(raw[0:8])
	copy(comm[:], raw[8:24])
	tgid = binary.LittleEndian.Uint32(raw[24:28])
	targetID = binary.LittleEndian.Uint32(raw[28:32])
	cmd = int32(binary.LittleEndian.Uint32(raw[32:36])) // #nosec G115 -- bpf cmd enum reinterpret of the BPF-side __s32; round-trip is intentional //nolint:gosec
	kind = raw[36]
	return ts, comm, tgid, targetID, cmd, kind, true
}

// decodeIOUringTLSEvent parses io_uring_tls_event (296 bytes, see
// bpf/trace_connect_obs.h). Layout: ts(8) pid(4) comm(16) op(1) _pad(3)
// capture_len(2, LE) payload(256) _pad2(6). capture_len is clamped to the
// payload window so a corrupt length can never slice out of bounds; payload
// is a sub-slice of raw (caller must not retain it past the ringbuf record).
func decodeIOUringTLSEvent(raw []byte) (ts uint64, pid uint32, op uint8, payload []byte, comm [16]byte, ok bool) {
	if len(raw) < ioUringTLSEventWireSize {
		return 0, 0, 0, nil, [16]byte{}, false
	}
	ts = binary.LittleEndian.Uint64(raw[0:8])
	pid = binary.LittleEndian.Uint32(raw[8:12])
	copy(comm[:], raw[12:28])
	op = raw[28]
	capLen := int(binary.LittleEndian.Uint16(raw[32:34]))
	if capLen > ioUringTLSPayloadMax {
		capLen = ioUringTLSPayloadMax
	}
	const payloadOff = 34
	payload = raw[payloadOff : payloadOff+capLen]
	return ts, pid, op, payload, comm, true
}

// ioUringOpName maps the raw IORING_OP_ byte to the JSONL op string. Values
// from include/uapi/linux/io_uring.h (`enum io_uring_op`, stable since 5.1).
func ioUringOpName(op uint8) string {
	switch op {
	case 2:
		return "WRITEV"
	case 9:
		return "SENDMSG"
	case 23:
		return "WRITE"
	case 26:
		return "SEND"
	default:
		return "UNKNOWN"
	}
}

func decodeDenyEvent(raw []byte) (tgid, tid uint32, comm [16]byte, protocol uint8, reason uint8, af uint8,
	daddr16 [16]byte, dport uint16, ok bool) {
	if len(raw) < denyEventWireSize {
		return 0, 0, [16]byte{}, 0, 0, 0, [16]byte{}, 0, false
	}
	tgid = binary.LittleEndian.Uint32(raw[0:4])
	tid = binary.LittleEndian.Uint32(raw[4:8])
	copy(comm[:], raw[8:24])
	protocol = raw[24]
	reason = raw[25]
	af = raw[26]
	copy(daddr16[:], raw[28:44])
	dport = binary.BigEndian.Uint16(raw[44:46])
	return tgid, tid, comm, protocol, reason, af, daddr16, dport, true
}

func denyProtocolLabel(protocol uint8) string {
	switch protocol {
	case denyProtoTCP:
		return "tcp"
	case denyProtoUDP:
		return "udp"
	default:
		return "unknown"
	}
}

func denyReasonLabel(reason uint8) string {
	switch reason {
	case denyReasonDstNotAllowlisted:
		return "dst_not_allowlisted"
	default:
		return "unknown"
	}
}

func denyDigestRowFromEvent(ev telemetry.DenyEvent) report.DenyDigestRow {
	return report.DenyDigestRow{
		TS:       ev.TS,
		PID:      ev.PID,
		Comm:     ev.Comm,
		Protocol: ev.Protocol,
		Dst:      ev.Dst,
		Dport:    ev.Dport,
		Reason:   ev.Reason,
	}
}
