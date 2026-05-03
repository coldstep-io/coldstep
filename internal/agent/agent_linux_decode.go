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

// decodeTLSSniffEvent parses tls_sniff_event (same wire layout as http_sniff_event with TLS_PAYLOAD_MAX).
func decodeTLSSniffEvent(raw []byte) (tgid, tid uint32, comm [16]byte, daddr [4]byte, dport uint16, payload []byte, ok bool) {
	if len(raw) < tlsSniffEventWireSize {
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
	if capLen > tlsPayloadMax {
		return 0, 0, [16]byte{}, [4]byte{}, 0, nil, false
	}
	payload = make([]byte, capLen)
	copy(payload, raw[tlsSniffEventHeaderSize:tlsSniffEventHeaderSize+capLen])
	return tgid, tid, comm, daddr, dport, payload, true
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
