//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// runRingReader drives the ringbuf read loop shared by every reader: exponential
// backoff on transient read errors, a clean return on ringbuf.ErrClosed (the
// shutdown closer Close()s each reader), ctx-cancel -> ctx.Err(), and a backoff
// reset on each good record. onRecord handles the per-reader decode + emit for
// one raw sample; a decode failure returns early from onRecord (the loop
// continues to the next record). Extracted from the readers that duplicated this
// scaffolding (Phase 6.2). Behavior is identical to the prior inline loops.
func runRingReader(ctx context.Context, name string, rd *ringbuf.Reader, onRecord func(raw []byte)) error {
	backoff := newRingReadRetryBackoff()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			delay := backoff.sleep()
			slog.Warn("ringbuf read", "reader", name, "err", err, "backoff", delay)
			continue
		}
		backoff.reset()
		onRecord(record.RawSample)
	}
}

func readExecRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	return runRingReader(ctx, "exec", rd, func(raw []byte) {
		var ev execEvent
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
			stats.addDropped("exec_decode")
			slog.Warn("decode exec", "err", err)
			return
		}

		// P1-5: sanitize attacker-controlled strings at the decode point so
		// every downstream consumer (digest rows + JSONL writer) sees the same
		// safe value. Stripping C0/C1 controls here is what prevents JSONL
		// injection — a process whose argv[0] embeds `\n{"type":"meta"...}`
		// could otherwise forge a record into the append-only event log.
		comm := telemetry.SanitizeField(nullTermStr(ev.Comm[:]), 16)
		exe := telemetry.SanitizeField(nullTermStr(ev.ExePath[:]), 4096)
		stats.addExec()
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			evOut := telemetry.ExecEvent{
				Type: "exec", TS: ts, Seq: n,
				PID: ev.TGID, TGID: ev.TGID, ThreadID: ev.TID, Comm: comm,
				Exe: exe,
			}
			err := telemetry.AppendJSONL(cfg.EventsLogPath, evOut, signer)
			jsonlMu.Unlock()
			if err != nil {
				stats.addDropped("exec_jsonl")
				slog.Warn("events jsonl", "err", err)
			}
		}
	})
}

type forkEventWire struct {
	ParentPID     uint32
	ChildPID      uint32
	ParentComm    [16]byte
	ChildComm     [16]byte
	ChildSID      uint32 // v0.3: session leader PID
	ChildPidnsNum uint32 // v0.3: PID namespace inode number
}

func readForkRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	return runRingReader(ctx, "fork", rd, func(raw []byte) {
		var ev forkEventWire
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
			stats.addDropped("proc_fork_decode")
			slog.Warn("decode fork", "err", err)
			return
		}

		pcomm := telemetry.SanitizeField(nullTermStr(ev.ParentComm[:]), 16)
		ccomm := telemetry.SanitizeField(nullTermStr(ev.ChildComm[:]), 16)
		stats.addProcFork()
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			evOut := telemetry.ProcForkEvent{
				Type: "proc_fork", TS: ts, Seq: n,
				ParentPID: ev.ParentPID, ChildPID: ev.ChildPID,
				ParentComm: pcomm, ChildComm: ccomm,
				ChildSID:      ev.ChildSID,
				ChildPidnsNum: ev.ChildPidnsNum,
				Note:          "best-effort pid namespace; parent/child are kernel fork trace ids",
			}
			werr := telemetry.AppendJSONL(cfg.EventsLogPath, evOut, signer)
			jsonlMu.Unlock()
			if werr != nil {
				stats.addDropped("proc_fork_jsonl")
				slog.Warn("events jsonl", "err", werr)
			}
		}
	})
}

func nullTermStr(b []byte) string {
	return string(bytes.TrimRight(b, "\x00"))
}

// classifyTCPStateTransition turns a kernel tcp_state newstate string (the
// destination of a SYN_SENT→X transition) into the two counters surfaced in
// the digest: `confirmed` for a completed handshake and `refused` for a
// terminal failure state. Intermediate or non-failure states (SYN_RECV,
// FIN_WAIT*, etc.) are intentionally counted in neither bucket — they
// represent the kernel still working the handshake or peer-initiated close
// flows that have nothing to do with policy-relevant failure.
func classifyTCPStateTransition(newStr string) (confirmed, refused bool) {
	if newStr == telemetry.TCPStateEstablished {
		return true, false
	}
	switch newStr {
	case telemetry.TCPStateClose, telemetry.TCPStateCloseWait, telemetry.TCPStateTimeWait:
		return false, true
	}
	return false, false
}

// connectRingRecordKind classifies one connect_events ringbuf record by its
// 4-byte magic at offset 0. The connect_events ringbuf is multiplexed: the
// entry-side connect(2) tracepoint, the P3-2 kretprobe on tcp_v4_connect, and
// the telemetry-integrity canary all share it. Real connect_event records
// begin with __u32 tgid which is bounded by PID_MAX_LIMIT (4194304), so the
// 0xCA1A1210 and 0xC0EE0001 magics cannot collide with a real tgid.
type connectRingRecordKind int

const (
	// connectRingKindConnectEvent is the default — an entry-side connect(2)
	// event (struct connect_event). Records shorter than 4 bytes also route
	// here so the downstream decoder can reject them as too-short.
	connectRingKindConnectEvent connectRingRecordKind = iota
	connectRingKindCanary
	connectRingKindConnectResult
)

// classifyConnectRingRecord is the pure-Go magic-prefix dispatcher used by
// readConnectRing. It exists as a free function so the routing logic is
// table-testable independent of *ringbuf.Reader (which requires a live BPF
// program to feed records).
func classifyConnectRingRecord(raw []byte) connectRingRecordKind {
	if len(raw) < 4 {
		return connectRingKindConnectEvent
	}
	switch binary.LittleEndian.Uint32(raw[0:4]) {
	case canaryMagic:
		return connectRingKindCanary
	case connectResultMagic:
		return connectRingKindConnectResult
	default:
		return connectRingKindConnectEvent
	}
}

// fsOpName maps BPF op byte to JSONL op string.
func fsOpName(op uint8) string {
	switch op {
	case 1:
		return "create"
	case 2:
		return "unlink"
	case 3:
		return "rename"
	case 4:
		return "chmod"
	default:
		return "unknown"
	}
}

type fsEventWire struct {
	TGID uint32
	TID  uint32
	Comm [16]byte
	Op   uint8
	Path [256]byte
	Pad  [3]byte
}

const maxFSEventsTotal = 5000

func readFSRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	count := 0 // persists across records (closure captures by reference) for the rate cap
	return runRingReader(ctx, "fs", rd, func(raw []byte) {
		var ev fsEventWire
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
			stats.addDropped("fs_decode")
			slog.Warn("decode fs event", "err", err)
			return
		}

		count++
		stats.addFS() // count all events even when rate-capped
		if count > maxFSEventsTotal {
			stats.addDropped("fs_cap")
			if count == maxFSEventsTotal+1 {
				slog.Warn("fs event cap reached; further events counted but not written to JSONL or rows", "cap", maxFSEventsTotal)
			}
			return
		}

		comm := telemetry.SanitizeField(nullTermStr(ev.Comm[:]), 16)
		path := telemetry.SanitizeField(nullTermStr(ev.Path[:]), 4096)
		op := fsOpName(ev.Op)
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			evOut := telemetry.FSEvent{
				Type: "fs_event", TS: ts, Seq: n,
				PID: ev.TGID, TGID: ev.TGID, ThreadID: ev.TID,
				Comm: comm, Op: op, Path: path,
			}
			werr := telemetry.AppendJSONL(cfg.EventsLogPath, evOut, signer)
			jsonlMu.Unlock()
			if werr != nil {
				stats.addDropped("fs_jsonl")
				slog.Warn("events jsonl", "err", werr)
			}
		}
	})
}

func readConnectRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, dns *DNSCache,
	pol *policy.Policy, stats *runStats, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, canary *canaryState, signer *telemetry.Signer) error {
	return runRingReader(ctx, "tcp", rd, func(raw []byte) {
		// Magic-prefix dispatch on the shared connect_events ringbuf:
		//   CANARY_MAGIC (0xCA1A1210)        → telemetry integrity canary
		//   CONNECT_RESULT_MAGIC (0xC0EE0001) → P3-2 kretprobe tcp_v4_connect result
		//   else                              → connect_event (entry-side connect(2))
		// Real connect_event records begin with __u32 tgid (bounded by
		// PID_MAX_LIMIT), so neither magic can collide with a real tgid.
		switch classifyConnectRingRecord(raw) {
		case connectRingKindCanary:
			if len(raw) >= canaryEventWireSize {
				seqNr := binary.LittleEndian.Uint64(raw[8:16])
				if canary != nil {
					canary.noteReceived(seqNr)
				}
				slog.Debug("canary received", "seq", seqNr)
			}
			return
		case connectRingKindConnectResult:
			rtgid, rtid, rcommb, rresult, rok := decodeConnectResultEvent(raw)
			if !rok {
				stats.addDropped("tcp_result_decode")
				slog.Warn("decode tcp_result", "len", len(raw))
				return
			}
			rcomm := telemetry.SanitizeField(nullTermStr(rcommb[:]), 16)
			bucket := telemetry.ConnectResultString(rresult)
			stats.addTCPResult(bucket)
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			if cfg.EventsLogPath != "" {
				jsonlMu.Lock()
				n := seq.Next()
				ev := telemetry.TCPResultEvent{
					Type: "tcp_result", TS: ts, Seq: n,
					PID: rtgid, TGID: rtgid, ThreadID: rtid,
					Comm: rcomm, Result: rresult, ResultStr: bucket,
				}
				werr := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
				jsonlMu.Unlock()
				if werr != nil {
					stats.addDropped("tcp_result_jsonl")
					slog.Warn("events jsonl (tcp_result)", "err", werr)
				}
			}
			slog.Debug("tcp_result", "tgid", rtgid, "tid", rtid, "comm", rcomm, "result", rresult, "bucket", bucket)
			return
		}

		tgid, tid, commb, daddr, port, decOK := decodeConnectEvent(raw)
		if !decOK {
			stats.addDropped("tcp_decode")
			slog.Warn("decode tcp", "len", len(raw))
			return
		}

		ip := net.IP(daddr[:]).To4()
		if ip == nil {
			return
		}
		comm := telemetry.SanitizeField(nullTermStr(commb[:]), 16)
		fqdn, fqdnProv := "", "unknown"
		if dns != nil {
			fqdn, fqdnProv = dns.LookupProvenance(ip)
		}
		// FQDN ultimately derives from on-wire DNS labels captured in BPF — sanitize
		// before any use (digest row, classifier display, JSONL).
		fqdn = telemetry.SanitizeField(fqdn, 253)
		cl := pol.Classify(fqdn, ip)
		stats.addTCP(cl)
		stats.incDomainCount(fqdn)

		ts := time.Now().UTC().Format(time.RFC3339Nano)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.TCPEvent{
				Type: "tcp", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, Dst: ip.String(), Dport: port,
				FQDN: fqdn, FQDNProvenance: fqdnProv,
				Direction: "egress",
				Policy:    string(cl),
			}
			err := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if err != nil {
				stats.addDropped("tcp_jsonl")
				slog.Warn("events jsonl", "err", err)
			}
		}

		slog.Debug("tcp", "tgid", tgid, "comm", comm, "dst", ip.String(), "dport", port, "policy", string(cl))
	})
}

func readTLSRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, pol *policy.Policy,
	stats *runStats, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer, ktlsTr *ktlsTracker) error {
	reasm := newTLSReassembler()
	return runRingReader(ctx, "tls", rd, func(raw []byte) {
		// Capture the userspace ringbuf arrival time as close to rd.Read() as
		// possible. Threaded into ktlsTr.IsKTLS so that a KTLS Mark observed
		// later does not retroactively clobber THIS TLS event's confidence —
		// only TLS events whose arrival time is >= the Mark's markedAt are
		// flipped to unknown/ktls (Bug-1 fix).
		tlsRecvAtNs := time.Now().UnixNano()

		tgid, tid, commb, daddr, port, rawPay, daddr6, isIPv6, ok := decodeTLSSniffEvent(raw)
		if !ok {
			stats.addDropped("tls_decode")
			slog.Warn("decode tls sniff", "len", len(raw))
			return
		}
		var ip net.IP
		if isIPv6 {
			ip = net.IP(daddr6[:])
			if len(ip) != net.IPv6len {
				return
			}
		} else {
			ip = net.IP(daddr[:]).To4()
			if ip == nil {
				return
			}
		}
		comm := telemetry.SanitizeField(nullTermStr(commb[:]), 16)
		sni, parsed := telemetry.ParseClientHelloSNI(rawPay)
		reassembled := false
		if !parsed {
			// Fall back to userspace inter-syscall reassembly: stitch this
			// payload onto any buffered prefix for the same (pid, dst, dport)
			// and retry. This recovers the Go crypto/tls and rustls header/body
			// split where the 5-byte record header lands in one write() and the
			// handshake body lands in the next.
			//
			// tlsReassemblyKey keys on a v4 daddr ([4]byte). Native IPv6
			// streams have no usable v4 key (they would all collapse to
			// {0,0,0,0} and collide), so they fall through to the
			// tls_sni_parse drop. IPv4-mapped IPv6 (::ffff:0:0/96) is the
			// exception: dual-stack sockets carry real IPv4 wire traffic, and
			// tlsReassemblyKeyForEvent extracts the embedded v4 to route those
			// onto the same reassembly path as native IPv4 (H21 fix).
			key, ok := tlsReassemblyKeyForEvent(tgid, daddr, daddr6, isIPv6, port)
			if !ok {
				stats.addDropped("tls_sni_parse")
				return
			}
			res := reasm.appendAndParse(key, rawPay)
			if !res.parsed {
				stats.addDropped("tls_sni_parse")
				return
			}
			sni = res.sni
			reassembled = res.reassembly
		}
		// SNI is parsed from an attacker-controlled TLS ClientHello buffer.
		sni = telemetry.SanitizeField(sni, 253)
		cl := pol.Classify(sni, ip)
		conf := telemetry.ScoreTLSConfidence(sni)
		// P4: if trace_ktls observed setsockopt(SOL_TLS) for this pid within the
		// tracker TTL AND that Mark landed BEFORE this TLS event arrived in
		// userspace, the SNI we just parsed (if any) is a pre-offload artifact —
		// kernel-TLS will encrypt every subsequent write on the socket and any
		// "full"/"partial" verdict is misleading. Force unknown with reason="ktls"
		// before the row lands in the digest or the JSONL. tls_sniff_event has no
		// fd field today, so we query the tracker with the wildcard form (fd=0).
		// The tlsRecvAtNs argument gates the override on event ordering — see
		// internal/agent/agent_linux_ktls_tracker.go for the contract.
		confReason := ""
		if ktlsTr != nil && ktlsTr.IsKTLS(tgid, 0, tlsRecvAtNs) {
			slog.Debug("ktls override applied", "pid", tgid, "sni", sni)
			conf = telemetry.TLSConfidenceUnknown
			confReason = "ktls"
		}
		stats.addTLS(cl, conf, confReason == "ktls")
		stats.incDomainCount(sni)

		ts := time.Now().UTC().Format(time.RFC3339Nano)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			note := "ClientHello SNI from first write/writev/sendto buffer (best-effort); fragmented handshakes may be missed"
			if reassembled {
				note = "ClientHello SNI recovered via inter-syscall reassembly (header/body split across writes)"
			}
			ev := telemetry.TLSEvent{
				Type: "tls", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, SNI: sni,
				Confidence:       conf,
				ConfidenceReason: confReason,
				ReassembledSNI:   reassembled,
				Dst:              ip.String(), Dport: port,
				IsIPv6: isIPv6,
				Policy: string(cl),
				Note:   note,
			}
			err := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if err != nil {
				stats.addDropped("tls_jsonl")
				slog.Warn("events jsonl", "err", err)
			}
		}
	})
}

func readUDPRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, dns *DNSCache,
	pol *policy.Policy, stats *runStats, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	return runRingReader(ctx, "udp", rd, func(raw []byte) {
		tgid, tid, commb, daddr, port, dgramLen, ok := decodeUDPSendEvent(raw)
		if !ok {
			stats.addDropped("udp_decode")
			slog.Warn("decode udp", "len", len(raw))
			return
		}
		ip := net.IP(daddr[:]).To4()
		if ip == nil {
			return
		}
		comm := telemetry.SanitizeField(nullTermStr(commb[:]), 16)
		fqdn, fqdnProv := "", "unknown"
		if dns != nil {
			fqdn, fqdnProv = dns.LookupProvenance(ip)
		}
		fqdn = telemetry.SanitizeField(fqdn, 253)
		cl := pol.Classify(fqdn, ip)
		stats.addUDP(cl)
		stats.incDomainCount(fqdn)

		ts := time.Now().UTC().Format(time.RFC3339Nano)

		ipStr := ip.String()
		possibleQUIC := port == 443
		if possibleQUIC {
			stats.addQUICObserved()
		}
		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.UDPEvent{
				Type: "udp", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, Dst: ipStr, Dport: port,
				DatagramLen: dgramLen, FQDN: fqdn, FQDNProvenance: fqdnProv,
				Direction:    "egress",
				Policy:       string(cl),
				PossibleQUIC: possibleQUIC,
			}
			err := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if err != nil {
				stats.addDropped("udp_jsonl")
				slog.Warn("events jsonl", "err", err)
			}
		}

		// QUIC/HTTP3 visibility-gap event (P2-2). Emitted alongside the UDP row
		// when the egress is a likely QUIC flow; payload content is not inspected.
		if IsQUICCandidate(ipStr, port) {
			stats.addQUICCandidate()
			if cfg.EventsLogPath != "" {
				jsonlMu.Lock()
				n := seq.Next()
				qev := telemetry.QUICCandidateEvent{
					Type: telemetry.EventTypeQUICCandidate, TS: ts, Seq: n,
					PID: tgid, TGID: tgid, Comm: comm,
					DstIP: ipStr, DstPort: port,
					Note: "UDP/443 to non-loopback IPv4; payload encrypted (QUIC) — not inspected",
				}
				err := telemetry.AppendJSONL(cfg.EventsLogPath, qev, signer)
				jsonlMu.Unlock()
				if err != nil {
					stats.addDropped("quic_candidate_jsonl")
					slog.Warn("events jsonl (quic_candidate)", "err", err)
				}
			}
		}
	})
}

func readHTTPRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, pol *policy.Policy,
	stats *runStats, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	return runRingReader(ctx, "http", rd, func(raw []byte) {
		tgid, tid, commb, daddr, port, rawPay, ok := decodeHTTPSniffEvent(raw)
		if !ok {
			stats.addDropped("http_decode")
			slog.Warn("decode http sniff", "len", len(raw))
			return
		}
		ip := net.IP(daddr[:]).To4()
		if ip == nil {
			return
		}
		comm := telemetry.SanitizeField(nullTermStr(commb[:]), 16)
		method, host, path, parsed := telemetry.ParseHTTPRequestPrefix(rawPay)
		if !parsed {
			stats.addDropped("http_prefix_parse")
			return
		}
		// HTTP request prefix is parsed from a kernel-captured first-write buffer.
		method = telemetry.SanitizeField(method, 16)
		host = telemetry.SanitizeField(host, 253)
		path = telemetry.SanitizeField(path, 4096)
		cl := pol.Classify(host, ip)
		stats.addHTTP(cl)
		stats.incDomainCount(host)

		ts := time.Now().UTC().Format(time.RFC3339Nano)
		sumPath := telemetry.RedactPathForSummary(path)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.HTTPEvent{
				Type: "http", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, Method: method, Host: host, Path: sumPath,
				Dst: ip.String(), Dport: port,
				Policy: string(cl),
			}
			err := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if err != nil {
				stats.addDropped("http_jsonl")
				slog.Warn("events jsonl", "err", err)
			}
		}
	})
}

func readDNSRing(ctx context.Context, rd *ringbuf.Reader, cache *DNSCache, stats *runStats) error {
	return runRingReader(ctx, "dns", rd, func(raw []byte) {
		pkt, isTCP, ok := decodeDNSSniffSample(raw)
		if !ok || len(pkt) < 12 {
			stats.addDropped("dns_decode")
			return
		}
		if isTCP {
			// Strip RFC 1035 TCP framing 2-byte length prefix before the DNS header.
			if len(pkt) < 14 {
				stats.addDropped("dns_decode_tcp_short")
				return
			}
			pkt = pkt[2:]
		}
		if len(pkt) < 12 {
			stats.addDropped("dns_decode")
			return
		}
		cache.AddFromPacket(pkt)
	})
}

// readKTLSRing drains setsockopt(SOL_TLS, TLS_TX|TLS_RX) ringbuf events from
// trace_ktls.bpf.c. Each event names one socket that handed TLS encryption to
// the kernel — meaning the userspace SNI sniffer in trace_tls_write.inc will
// observe ciphertext on that fd and cannot resolve SNI. Counted in runStats
// for the digest KPI; appended to JSONL when EventsLogPath is set.
func readKTLSRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer, ktlsTr *ktlsTracker) error {
	return runRingReader(ctx, "ktls", rd, func(raw []byte) {
		// Capture the userspace ringbuf arrival time as close to rd.Read() as
		// possible. The ktlsTracker uses this as `markedAt` so a later
		// IsKTLS query from readTLSRing only flips confidence when the TLS
		// event arrived AFTER this Mark — pre-offload TLS events with an
		// earlier tlsTimestampNs are preserved (Bug-1 fix).
		recvAtNs := time.Now().UnixNano()

		tgid, tid, fd, commb, dirByte, ok := decodeKTLSEvent(raw)
		if !ok {
			stats.addDropped("ktls_decode")
			slog.Warn("decode ktls", "len", len(raw))
			return
		}
		stats.addKTLS()
		// P4: record (pid, fd, markedAt) so any TLS event for the same pid
		// that flows through readTLSRing within ktlsTrackerTTL AND arrives at
		// or after markedAt gets reclassified to Confidence=unknown /
		// ConfidenceReason="ktls". The arrival-time gate replaces the prior
		// blanket wildcard which clobbered every same-pid TLS event for 60s,
		// including ones whose payload was captured before the offload was
		// observed (plan p4-ktls-sni-confidence-integration.md).
		if ktlsTr != nil {
			ktlsTr.Mark(tgid, fd, recvAtNs)
		}
		comm := telemetry.SanitizeField(nullTermStr(commb[:]), 16)
		direction := ktlsDirectionLabel(dirByte)
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		slog.Debug("ktls offload", "tgid", tgid, "comm", comm, "fd", fd, "direction", direction)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.KTLSEvent{
				Type: telemetry.EventTypeKTLS, TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, FD: fd, Direction: direction,
			}
			werr := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if werr != nil {
				stats.addDropped("ktls_jsonl")
				slog.Warn("events jsonl (ktls)", "err", werr)
			}
		}
	})
}

// readTCPStateRing drains the tcp_state_events ringbuf (P3-2b). The BPF
// program filters to outgoing IPv4 TCP connects (oldstate == SYN_SENT), so
// every event seen here is one resolved 3-way handshake — newstate ==
// ESTABLISHED means success, newstate == CLOSE means RST/timeout/unreach.
// PID and Comm are best-effort because the tracepoint fires in softirq
// context; downstream tooling correlates by tuple (saddr:sport→daddr:dport)
// with the preceding `tcp` connect_event when reliable attribution is needed.
func readTCPStateRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader,
	stats *runStats, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	return runRingReader(ctx, "tcp_state", rd, func(raw []byte) {
		timestampNS, pid, saddr, daddr, sport, dport, oldState, newState, commb, ok := decodeTCPStateEvent(raw)
		if !ok {
			stats.addDropped("tcp_state_decode")
			slog.Warn("decode tcp_state", "len", len(raw))
			return
		}

		oldStr := telemetry.TCPStateName(oldState)
		newStr := telemetry.TCPStateName(newState)
		confirmed, refused := classifyTCPStateTransition(newStr)
		stats.addTCPState(confirmed, refused)

		dstIP := net.IP(daddr[:]).To4()
		if dstIP == nil {
			return
		}
		srcIP := net.IP(saddr[:]).To4()
		comm := telemetry.SanitizeField(nullTermStr(commb[:]), 16)

		ts := time.Now().UTC().Format(time.RFC3339Nano)
		slog.Debug("tcp_state", "pid", pid, "comm", comm,
			"src", srcIP.String(), "sport", sport,
			"dst", dstIP.String(), "dport", dport,
			"old", oldStr, "new", newStr)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.TCPStateEvent{
				Type:        telemetry.EventTypeTCPState,
				TS:          ts,
				Seq:         n,
				TimestampNS: timestampNS,
				PID:         pid,
				Comm:        comm,
				SrcIP:       srcIP.String(),
				SrcPort:     sport,
				DstIP:       dstIP.String(),
				DstPort:     dport,
				OldState:    oldStr,
				NewState:    newStr,
			}
			werr := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if werr != nil {
				stats.addDropped("tcp_state_jsonl")
				slog.Warn("events jsonl (tcp_state)", "err", werr)
			}
		}
	})
}

// readIoUringRing drains io_uring_events from the BPF ringbuf into JSONL and
// runStats. The BPF side already filters to write-class opcodes (SENDMSG=9,
// SEND=26), so this loop only sanitizes the wire bytes and maps the raw
// IORING_OP_ byte to its string label. The Phase 2 has_tls_hello flag rides
// alongside each event when COLDSTEP_DETECT_PROFILE=enhanced and the
// best-effort SQE buffer peek matched a TLS ClientHello prefix.
func readIoUringRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	return runRingReader(ctx, "io_uring", rd, func(raw []byte) {
		_, pid, fd, daddr, dport, op, hasTLSHello, commb, ok := decodeIOUringSendEvent(raw)
		if !ok {
			stats.addDropped("io_uring_decode")
			slog.Warn("decode io_uring send", "len", len(raw))
			return
		}
		stats.addIoUringSend()

		comm := telemetry.SanitizeField(nullTermStr(commb[:]), 16)
		opName := ioUringOpName(op)
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		var dstIP string
		var dstPort uint16
		if ip := net.IP(daddr[:]).To4(); ip != nil {
			// daddr=0 means the BPF probe could not resolve the SQE's fd to a
			// cached connect tuple. Leave dst_ip/dst_port empty in that case
			// so the JSONL reader can distinguish "unresolved" from "0.0.0.0".
			if !(daddr == [4]byte{0, 0, 0, 0} && dport == 0) {
				dstIP = ip.String()
				dstPort = dport
			}
		}

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.IOUringSendEvent{
				Type:        "io_uring_send",
				TS:          ts,
				Seq:         n,
				PID:         pid,
				Comm:        comm,
				FD:          fd,
				Op:          opName,
				DstIP:       dstIP,
				DstPort:     dstPort,
				HasTLSHello: hasTLSHello,
			}
			werr := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if werr != nil {
				stats.addDropped("io_uring_jsonl")
				slog.Warn("events jsonl (io_uring)", "err", werr)
			}
		}
	})
}

// egressBackstopProtoName maps the raw IP-header protocol byte to a JSONL
// proto string.
func egressBackstopProtoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	case 255:
		return "raw"
	default:
		return "other"
	}
}

// egressBackstopEventFromRaw decodes a tc/clsact egress backstop sample.
// seq may be 0; the reader assigns the real sequence under jsonlMu on emit.
func egressBackstopEventFromRaw(raw []byte, ts string, seq uint64) (telemetry.EgressBackstopEvent, bool) {
	_, pid, af, ipproto, daddr, dport, commb, ok := decodeEgressBackstopEvent(raw)
	if !ok {
		return telemetry.EgressBackstopEvent{}, false
	}
	var ip net.IP
	afStr := "ipv4"
	if af == 10 { // AF_INET6
		afStr = "ipv6"
		ip = net.IP(daddr[:16])
	} else {
		ip = net.IP(daddr[:4])
	}
	return telemetry.EgressBackstopEvent{
		Type:  telemetry.EventTypeEgressBackstop,
		TS:    ts,
		Seq:   seq,
		PID:   pid,
		Comm:  telemetry.SanitizeField(nullTermStr(commb[:]), 16),
		AF:    afStr,
		Proto: egressBackstopProtoName(ipproto),
		Dst:   ip.String(),
		Dport: dport,
		Note:  "egress to non-allowlisted IP reached the egress qdisc without a connect4/sendmsg4 decision (raw-socket or post-connect bypass)",
	}, true
}

// readEgressBackstopRing drains skb_backstop_events (sub-project A). seq is
// allocated under jsonlMu only on emit (matches every other ring reader).
func readEgressBackstopRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	return runRingReader(ctx, "egress_backstop", rd, func(raw []byte) {
		ts := time.Now().UTC().Format(time.RFC3339Nano)
		ev, emit := egressBackstopEventFromRaw(raw, ts, 0)
		if !emit {
			return
		}
		stats.addEgressBackstop(ev.Dst)
		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			ev.Seq = seq.Next()
			werr := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if werr != nil {
				stats.addDropped("egress_backstop_jsonl")
				slog.Warn("events jsonl (egress_backstop)", "err", werr)
			}
		}
	})
}

// bpfSelfDefenseKindName maps the wire target_kind byte to a JSONL string.
func bpfSelfDefenseKindName(k uint8) string {
	switch k {
	case 1:
		return "prog"
	case 2:
		return "map"
	case 3:
		return "pin"
	default:
		return "other"
	}
}

// bpfSelfDefenseEventFromRaw decodes a denied self-object tamper attempt
// (sub-project B). seq may be 0; the reader assigns the real sequence under
// jsonlMu on emit.
func bpfSelfDefenseEventFromRaw(raw []byte, ts string, seq uint64) (telemetry.BpfSelfDefenseEvent, bool) {
	_, commb, tgid, targetID, cmd, kind, ok := decodeBpfSelfDefenseEvent(raw)
	if !ok {
		return telemetry.BpfSelfDefenseEvent{}, false
	}
	return telemetry.BpfSelfDefenseEvent{
		Type:       telemetry.EventTypeBpfSelfDefense,
		TS:         ts,
		Seq:        seq,
		TGID:       tgid,
		Comm:       telemetry.SanitizeField(nullTermStr(commb[:]), 16),
		Cmd:        cmd,
		TargetKind: bpfSelfDefenseKindName(kind),
		TargetID:   targetID,
		Action:     "denied",
	}, true
}

// readBpfSelfDefenseRing drains bpf_self_defense_events (sub-project B). seq is
// allocated under jsonlMu only on emit (matches every other ring reader).
func readBpfSelfDefenseRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	return runRingReader(ctx, "bpf_self_defense", rd, func(raw []byte) {
		ts := time.Now().UTC().Format(time.RFC3339Nano)
		ev, emit := bpfSelfDefenseEventFromRaw(raw, ts, 0)
		if !emit {
			return
		}
		stats.addBpfSelfDefense()
		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			ev.Seq = seq.Next()
			werr := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if werr != nil {
				stats.addDropped("bpf_self_defense_jsonl")
				slog.Warn("events jsonl (bpf_self_defense)", "err", werr)
			}
		}
	})
}

// ioUringTLSEventFromRaw decodes a captured io_uring ClientHello and parses its
// SNI via the same parser the syscall TLS sniffer uses (telemetry.ParseClientHelloSNI).
// Returns emit=false when the payload does not parse as a ClientHello with a
// server_name — the lightweight io_uring_send event already recorded the
// has_tls_hello signal, so a parse miss is not a silent drop. ORDER 1 (BG-5):
// Dst is the connected IPv4 peer resolved in kernel from the submission's socket
// (req->file), or "unknown" when the socket peer was not resolvable.
// seq may be 0 when the caller assigns the real sequence number later (the
// reader allocates it under jsonlMu only after emit is known, so parse misses
// do not burn JSONL sequence numbers).
func ioUringTLSEventFromRaw(raw []byte, ts string, seq uint64) (telemetry.IOUringTLSEvent, bool) {
	_, pid, op, payload, commb, daddr, dport, ok := decodeIOUringTLSEvent(raw)
	if !ok {
		return telemetry.IOUringTLSEvent{}, false
	}
	sni, parsed := telemetry.ParseClientHelloSNI(payload)
	if !parsed || sni == "" {
		return telemetry.IOUringTLSEvent{}, false
	}
	dst := "unknown"
	if daddr != [4]byte{} {
		dst = net.IPv4(daddr[0], daddr[1], daddr[2], daddr[3]).String()
	}
	return telemetry.IOUringTLSEvent{
		Type:    telemetry.EventTypeIOUringTLS,
		TS:      ts,
		Seq:     seq,
		PID:     pid,
		Comm:    telemetry.SanitizeField(nullTermStr(commb[:]), 16),
		Op:      ioUringOpName(op),
		SNI:     telemetry.SanitizeField(sni, 253),
		Dst:     dst,
		DstPort: dport,
	}, true
}

// readIoUringTLSRing drains io_uring_tls_events: io_uring SEND/SENDMSG
// submissions whose captured user buffer parsed as a TLS ClientHello with an
// extractable SNI (P6 Phase 2.5, enhanced profile). Each parsed SNI feeds the
// digest "io_uring TLS SNI" KPI row via runStats.
func readIoUringTLSRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	return runRingReader(ctx, "io_uring_tls", rd, func(raw []byte) {
		// Decode + parse outside jsonlMu and only allocate a sequence number
		// once emit is known — parse misses must not burn seq values, and the
		// stats update must not run under the JSONL lock (matches every other
		// ring reader in this file).
		ts := time.Now().UTC().Format(time.RFC3339Nano)
		ev, emit := ioUringTLSEventFromRaw(raw, ts, 0)
		if !emit {
			return
		}
		stats.addIoUringTLSSNI(ev.SNI)
		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			ev.Seq = seq.Next()
			werr := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if werr != nil {
				stats.addDropped("io_uring_tls_jsonl")
				slog.Warn("events jsonl (io_uring_tls)", "err", werr)
			}
		}
	})
}

func readBPFAuditRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	return runRingReader(ctx, "bpf_audit", rd, func(raw []byte) {
		tgid, tid, commb, cmd, ok := decodeBPFAuditEvent(raw)
		if !ok {
			stats.addDropped("bpf_audit_decode")
			slog.Warn("decode bpf audit", "len", len(raw))
			return
		}

		stats.addBPFAudit()
		comm := telemetry.SanitizeField(nullTermStr(commb[:]), 16)
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		slog.Info("bpf syscall audit", "tgid", tgid, "comm", comm, "cmd", cmd)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.BPFAuditEvent{
				Type: "bpf_audit", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, Cmd: cmd,
			}
			err := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if err != nil {
				stats.addDropped("bpf_audit_jsonl")
				slog.Warn("events jsonl (bpf_audit)", "err", err)
			}
		}
	})
}

// ipv6ObsEventWireSize must match the _Static_assert in
// bpf/trace_ipv6_obs.bpf.c (44 bytes). The layout is frozen:
//
//	daddr [16] + dport [2] + _pad0 [2] + pid [4] + comm [16] + hook [1] + _pad1 [3] = 44.
const ipv6ObsEventWireSize = 44

// ipv6ObsEventWire is the userspace mirror of struct ipv6_obs_event from
// bpf/trace_ipv6_obs.bpf.c. Wire-format only — never written; decoded with
// binary.LittleEndian via binary.Read. Dport is a [2]byte rather than a
// uint16 so the network-order bytes are preserved through the LE decode;
// it is converted to a host-order uint16 with binary.BigEndian.
type ipv6ObsEventWire struct {
	Daddr [16]byte
	Dport [2]byte // network byte order — decode with binary.BigEndian
	Pad0  [2]byte
	PID   uint32
	Comm  [16]byte
	Hook  uint8
	Pad1  [3]byte
}

// ipv6ObsHookName maps the BPF hook tag byte (0/1) to the JSONL "type"
// discriminator. Unknown values fall through to EventTypeIPv6TCP — the BPF
// program only emits 0 and 1, so a non-canonical value is treated as a
// connect-class event for forensic continuity rather than dropped.
func ipv6ObsHookName(hook uint8) string {
	if hook == 1 {
		return telemetry.EventTypeIPv6UDP
	}
	return telemetry.EventTypeIPv6TCP
}

// readIPv6ObsRing drains the H7 traceipv6 ringbuf. One record per
// non-loopback, non-link-local IPv6 cgroup/connect6 or cgroup/sendmsg6;
// loopback and link-local are filtered in BPF. Bumps stats.IPv6EventCount
// and emits a telemetry.IPv6Event JSONL line per record.
//
// Defend mode does not load the traceipv6 object (its own defend IPv6
// hooks already attach to the same cgroup), so this reader is detect-mode-
// only — running it in defend mode would silently observe zero events.
func readIPv6ObsRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	return runRingReader(ctx, "ipv6_obs", rd, func(raw []byte) {
		if len(raw) < ipv6ObsEventWireSize {
			stats.addDropped("ipv6_obs_decode")
			slog.Warn("decode ipv6_obs", "len", len(raw), "want", ipv6ObsEventWireSize)
			return
		}

		var wire ipv6ObsEventWire
		if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &wire); err != nil {
			stats.addDropped("ipv6_obs_decode")
			slog.Warn("decode ipv6_obs", "err", err)
			return
		}

		stats.addIPv6Event()
		comm := telemetry.SanitizeField(nullTermStr(wire.Comm[:]), 16)
		dport := binary.BigEndian.Uint16(wire.Dport[:])
		dstIP := net.IP(wire.Daddr[:]).String()
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.IPv6Event{
				Type:  ipv6ObsHookName(wire.Hook),
				TS:    ts,
				Seq:   n,
				PID:   wire.PID,
				Comm:  comm,
				Dst:   dstIP,
				Dport: dport,
				Note:  telemetry.IPv6NotEnforcedNote,
			}
			werr := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer)
			jsonlMu.Unlock()
			if werr != nil {
				stats.addDropped("ipv6_obs_jsonl")
				slog.Warn("events jsonl (ipv6_obs)", "err", werr)
			}
		}
	})
}
