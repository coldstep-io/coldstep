//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/proctree"
	"github.com/coldstep-io/coldstep/internal/report"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func readExecRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	rows *rowBuffer, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
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
			slog.Warn("ringbuf read (exec)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()

		var ev execEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			stats.addDropped("exec_decode")
			slog.Warn("decode exec", "err", err)
			continue
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
		rows.addExec(report.ExecDigestRow{
			TS: ts, PID: ev.TGID, ThreadID: ev.TID, Comm: comm,
			Exe: report.TruncateExeForDigest(exe),
		}, stats)

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
	}
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
	forkBuf *forkEdgeBuffer, forkState *forkSectionState, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
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
			if forkState != nil {
				forkState.addReadError()
			}
			delay := backoff.sleep()
			slog.Warn("ringbuf read (fork)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()

		var ev forkEventWire
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			forkState.addReadError()
			stats.addDropped("proc_fork_decode")
			slog.Warn("decode fork", "err", err)
			continue
		}

		pcomm := telemetry.SanitizeField(nullTermStr(ev.ParentComm[:]), 16)
		ccomm := telemetry.SanitizeField(nullTermStr(ev.ChildComm[:]), 16)
		forkBuf.add(proctree.Edge{
			ParentTGID:    ev.ParentPID,
			ChildTGID:     ev.ChildPID,
			ParentComm:    pcomm,
			ChildComm:     ccomm,
			ChildSID:      ev.ChildSID,
			ChildPidnsNum: ev.ChildPidnsNum,
		})
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
	}
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
	fsRows *fsRowBuffer, fsState *fsSectionState, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	count := 0
	backoff := newRingReadRetryBackoff()
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			fsState.addReadError()
			delay := backoff.sleep()
			slog.Warn("ringbuf read (fs)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()
		var ev fsEventWire
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			fsState.addReadError()
			stats.addDropped("fs_decode")
			slog.Warn("decode fs event", "err", err)
			continue
		}

		count++
		stats.addFS() // count all events even when rate-capped
		if count > maxFSEventsTotal {
			stats.addDropped("fs_cap")
			if count == maxFSEventsTotal+1 {
				slog.Warn("fs event cap reached; further events counted but not written to JSONL or rows", "cap", maxFSEventsTotal)
			}
			continue
		}

		comm := telemetry.SanitizeField(nullTermStr(ev.Comm[:]), 16)
		path := telemetry.SanitizeField(nullTermStr(ev.Path[:]), 4096)
		op := fsOpName(ev.Op)
		ts := time.Now().UTC().Format(time.RFC3339Nano)

		fsRows.add(report.FSDigestRow{
			TS:   ts,
			PID:  ev.TGID,
			Comm: comm,
			Op:   op,
			Path: path,
		})

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
	}
}

func readConnectRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, dns *DNSCache,
	pol *policy.Policy, stats *runStats, rows *rowBuffer, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, sectionState *networkSectionState, canary *canaryState, signer *telemetry.Signer) error {
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
			if sectionState != nil {
				sectionState.addTCPReaderError()
			}
			delay := backoff.sleep()
			slog.Warn("ringbuf read (tcp)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()

		// Magic-prefix dispatch on the shared connect_events ringbuf:
		//   CANARY_MAGIC (0xCA1A1210)        → telemetry integrity canary
		//   CONNECT_RESULT_MAGIC (0xC0EE0001) → P3-2 kretprobe tcp_v4_connect result
		//   else                              → connect_event (entry-side connect(2))
		// Real connect_event records begin with __u32 tgid (bounded by
		// PID_MAX_LIMIT), so neither magic can collide with a real tgid.
		switch classifyConnectRingRecord(record.RawSample) {
		case connectRingKindCanary:
			if len(record.RawSample) >= canaryEventWireSize {
				seqNr := binary.LittleEndian.Uint64(record.RawSample[8:16])
				if canary != nil {
					canary.noteReceived(seqNr)
				}
				slog.Debug("canary received", "seq", seqNr)
			}
			continue
		case connectRingKindConnectResult:
			rtgid, rtid, rcommb, rresult, rok := decodeConnectResultEvent(record.RawSample)
			if !rok {
				stats.addDropped("tcp_result_decode")
				slog.Warn("decode tcp_result", "len", len(record.RawSample))
				continue
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
			continue
		}

		tgid, tid, commb, daddr, port, decOK := decodeConnectEvent(record.RawSample)
		if !decOK {
			if sectionState != nil {
				sectionState.addTCPDecodeError()
			}
			stats.addDropped("tcp_decode")
			slog.Warn("decode tcp", "len", len(record.RawSample))
			continue
		}

		ip := net.IP(daddr[:]).To4()
		if ip == nil {
			continue
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
		notes := "—"
		if fqdn != "" {
			notes = fmt.Sprintf("fqdn `%s` (%s)", report.SanitizeForMarkdown(fqdn), fqdnProv)
		}
		rows.addTCP(report.TCPDigestRow{
			TS: ts, PID: tgid, Comm: comm,
			Remote: fmt.Sprintf("`%s:%d`", ip.String(), port),
			Notes:  notes,
			Policy: cl.Display(),
		}, stats)

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
	}
}

func readTLSRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, pol *policy.Policy,
	stats *runStats, rows *rowBuffer, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, sectionState *networkSectionState, signer *telemetry.Signer, ktlsTr *ktlsTracker) error {
	backoff := newRingReadRetryBackoff()
	reasm := newTLSReassembler()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if sectionState != nil {
				sectionState.addTLSReaderError()
			}
			delay := backoff.sleep()
			slog.Warn("ringbuf read (tls)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()

		// Capture the userspace ringbuf arrival time as close to rd.Read() as
		// possible. Threaded into ktlsTr.IsKTLS so that a KTLS Mark observed
		// later does not retroactively clobber THIS TLS event's confidence —
		// only TLS events whose arrival time is >= the Mark's markedAt are
		// flipped to unknown/ktls (Bug-1 fix).
		tlsRecvAtNs := time.Now().UnixNano()

		tgid, tid, commb, daddr, port, rawPay, ok := decodeTLSSniffEvent(record.RawSample)
		if !ok {
			if sectionState != nil {
				sectionState.addTLSDecodeError()
			}
			stats.addDropped("tls_decode")
			slog.Warn("decode tls sniff", "len", len(record.RawSample))
			continue
		}
		ip := net.IP(daddr[:]).To4()
		if ip == nil {
			continue
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
			res := reasm.appendAndParse(tlsReassemblyKey{PID: tgid, Dst: daddr, Dport: port}, rawPay)
			if !res.parsed {
				stats.addDropped("tls_sni_parse")
				continue
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

		ts := time.Now().UTC().Format(time.RFC3339Nano)
		rows.addTLS(report.TLSDigestRow{
			TS: ts, PID: tgid, Comm: comm,
			SNI:              sni,
			Remote:           fmt.Sprintf("`%s:%d`", ip.String(), port),
			Policy:           cl.Display(),
			Confidence:       conf,
			ConfidenceReason: confReason,
		}, stats)

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
	}
}

func readUDPRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, dns *DNSCache,
	pol *policy.Policy, stats *runStats, rows *rowBuffer, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, sectionState *networkSectionState, signer *telemetry.Signer) error {
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
			if sectionState != nil {
				sectionState.addUDPReaderError()
			}
			delay := backoff.sleep()
			slog.Warn("ringbuf read (udp)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()

		tgid, tid, commb, daddr, port, dgramLen, ok := decodeUDPSendEvent(record.RawSample)
		if !ok {
			if sectionState != nil {
				sectionState.addUDPDecodeError()
			}
			stats.addDropped("udp_decode")
			slog.Warn("decode udp", "len", len(record.RawSample))
			continue
		}
		ip := net.IP(daddr[:]).To4()
		if ip == nil {
			continue
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
		rows.addUDP(report.UDPDigestRow{
			TS: ts, PID: tgid, Comm: comm,
			Remote:   fmt.Sprintf("`%s:%d`", ip.String(), port),
			DgramLen: dgramLen,
			FQDN:     fqdn,
			Policy:   cl.Display(),
		}, stats)

		ipStr := ip.String()
		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.UDPEvent{
				Type: "udp", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, Dst: ipStr, Dport: port,
				DatagramLen: dgramLen, FQDN: fqdn, FQDNProvenance: fqdnProv,
				Direction: "egress",
				Policy:    string(cl),
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
	}
}

func readHTTPRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, pol *policy.Policy,
	stats *runStats, rows *rowBuffer, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, sectionState *networkSectionState, signer *telemetry.Signer) error {
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
			if sectionState != nil {
				sectionState.addHTTPReaderError()
			}
			delay := backoff.sleep()
			slog.Warn("ringbuf read (http)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()

		tgid, tid, commb, daddr, port, rawPay, ok := decodeHTTPSniffEvent(record.RawSample)
		if !ok {
			if sectionState != nil {
				sectionState.addHTTPDecodeError()
			}
			stats.addDropped("http_decode")
			slog.Warn("decode http sniff", "len", len(record.RawSample))
			continue
		}
		ip := net.IP(daddr[:]).To4()
		if ip == nil {
			continue
		}
		comm := telemetry.SanitizeField(nullTermStr(commb[:]), 16)
		method, host, path, parsed := telemetry.ParseHTTPRequestPrefix(rawPay)
		if !parsed {
			stats.addDropped("http_prefix_parse")
			continue
		}
		// HTTP request prefix is parsed from a kernel-captured first-write buffer.
		method = telemetry.SanitizeField(method, 16)
		host = telemetry.SanitizeField(host, 253)
		path = telemetry.SanitizeField(path, 4096)
		cl := pol.Classify(host, ip)
		stats.addHTTP(cl)

		ts := time.Now().UTC().Format(time.RFC3339Nano)
		sumPath := telemetry.RedactPathForSummary(path)
		rows.addHTTP(report.HTTPDigestRow{
			TS: ts, PID: tgid, Comm: comm,
			Method: method, Host: host, Path: sumPath,
			Remote: fmt.Sprintf("`%s:%d`", ip.String(), port),
			Policy: cl.Display(),
		}, stats)

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
	}
}

func readDNSRing(ctx context.Context, rd *ringbuf.Reader, cache *DNSCache, stats *runStats) error {
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
			slog.Warn("ringbuf read (dns)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()
		pkt, isTCP, ok := decodeDNSSniffSample(record.RawSample)
		if !ok || len(pkt) < 12 {
			stats.addDropped("dns_decode")
			continue
		}
		if isTCP {
			// Strip RFC 1035 TCP framing 2-byte length prefix before the DNS header.
			if len(pkt) < 14 {
				stats.addDropped("dns_decode_tcp_short")
				continue
			}
			pkt = pkt[2:]
		}
		if len(pkt) < 12 {
			stats.addDropped("dns_decode")
			continue
		}
		cache.AddFromPacket(pkt)
	}
}

// readKTLSRing drains setsockopt(SOL_TLS, TLS_TX|TLS_RX) ringbuf events from
// trace_ktls.bpf.c. Each event names one socket that handed TLS encryption to
// the kernel — meaning the userspace SNI sniffer in trace_tls_write.inc will
// observe ciphertext on that fd and cannot resolve SNI. Counted in runStats
// for the digest KPI; appended to JSONL when EventsLogPath is set.
func readKTLSRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer, ktlsTr *ktlsTracker) error {
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
			slog.Warn("ringbuf read (ktls)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()

		// Capture the userspace ringbuf arrival time as close to rd.Read() as
		// possible. The ktlsTracker uses this as `markedAt` so a later
		// IsKTLS query from readTLSRing only flips confidence when the TLS
		// event arrived AFTER this Mark — pre-offload TLS events with an
		// earlier tlsTimestampNs are preserved (Bug-1 fix).
		recvAtNs := time.Now().UnixNano()

		tgid, tid, fd, commb, dirByte, ok := decodeKTLSEvent(record.RawSample)
		if !ok {
			stats.addDropped("ktls_decode")
			slog.Warn("decode ktls", "len", len(record.RawSample))
			continue
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
	}
}

// readTCPStateRing drains the tcp_state_events ringbuf (P3-2b). The BPF
// program filters to outgoing IPv4 TCP connects (oldstate == SYN_SENT), so
// every event seen here is one resolved 3-way handshake — newstate ==
// ESTABLISHED means success, newstate == CLOSE means RST/timeout/unreach.
// PID and Comm are best-effort because the tracepoint fires in softirq
// context; downstream tooling correlates by tuple (saddr:sport→daddr:dport)
// with the preceding `tcp` connect_event when reliable attribution is needed.
func readTCPStateRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader,
	stats *runStats, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, sectionState *networkSectionState, signer *telemetry.Signer) error {
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
			if sectionState != nil {
				sectionState.addTCPStateReaderError()
			}
			delay := backoff.sleep()
			slog.Warn("ringbuf read (tcp_state)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()

		timestampNS, pid, saddr, daddr, sport, dport, oldState, newState, commb, ok := decodeTCPStateEvent(record.RawSample)
		if !ok {
			if sectionState != nil {
				sectionState.addTCPStateDecodeError()
			}
			stats.addDropped("tcp_state_decode")
			slog.Warn("decode tcp_state", "len", len(record.RawSample))
			continue
		}

		oldStr := telemetry.TCPStateName(oldState)
		newStr := telemetry.TCPStateName(newState)
		confirmed, refused := classifyTCPStateTransition(newStr)
		stats.addTCPState(confirmed, refused)

		dstIP := net.IP(daddr[:]).To4()
		if dstIP == nil {
			continue
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
	}
}

func readBPFAuditRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
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
			slog.Warn("ringbuf read (bpf_audit)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()

		tgid, tid, commb, cmd, ok := decodeBPFAuditEvent(record.RawSample)
		if !ok {
			stats.addDropped("bpf_audit_decode")
			slog.Warn("decode bpf audit", "len", len(record.RawSample))
			continue
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
	}
}
