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

		comm := string(bytes.TrimRight(ev.Comm[:], "\x00"))
		exe := string(bytes.TrimRight(ev.ExePath[:], "\x00"))
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

		pcomm := string(bytes.TrimRight(ev.ParentComm[:], "\x00"))
		ccomm := string(bytes.TrimRight(ev.ChildComm[:], "\x00"))
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

		comm := nullTermStr(ev.Comm[:])
		path := nullTermStr(ev.Path[:])
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

		// Canary event detection: if the record starts with CANARY_MAGIC,
		// it's a telemetry integrity canary — not a connect event.
		if len(record.RawSample) >= canaryEventWireSize {
			magic := binary.LittleEndian.Uint32(record.RawSample[0:4])
			if magic == canaryMagic {
				seqNr := binary.LittleEndian.Uint64(record.RawSample[8:16])
				if canary != nil {
					canary.noteReceived(seqNr)
				}
				slog.Debug("canary received", "seq", seqNr)
				continue
			}
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
		comm := string(bytes.TrimRight(commb[:], "\x00"))
		fqdn, fqdnProv := "", "unknown"
		if dns != nil {
			fqdn, fqdnProv = dns.LookupProvenance(ip)
		}
		cl := pol.Classify(fqdn, ip)
		stats.addTCP(cl)

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
				sectionState.addTLSReaderError()
			}
			delay := backoff.sleep()
			slog.Warn("ringbuf read (tls)", "err", err, "backoff", delay)
			continue
		}
		backoff.reset()

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
		comm := string(bytes.TrimRight(commb[:], "\x00"))
		sni, parsed := telemetry.ParseClientHelloSNI(rawPay)
		if !parsed {
			stats.addDropped("tls_sni_parse")
			continue
		}
		cl := pol.Classify(sni, ip)
		stats.addTLS(cl)

		ts := time.Now().UTC().Format(time.RFC3339Nano)
		rows.addTLS(report.TLSDigestRow{
			TS: ts, PID: tgid, Comm: comm,
			SNI:    sni,
			Remote: fmt.Sprintf("`%s:%d`", ip.String(), port),
			Policy: cl.Display(),
		}, stats)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.TLSEvent{
				Type: "tls", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, SNI: sni,
				Dst: ip.String(), Dport: port,
				Policy: string(cl),
				Note:   "ClientHello SNI from first write(2) buffer; fragmented handshakes may be missed",
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
		comm := string(bytes.TrimRight(commb[:], "\x00"))
		fqdn, fqdnProv := "", "unknown"
		if dns != nil {
			fqdn, fqdnProv = dns.LookupProvenance(ip)
		}
		cl := pol.Classify(fqdn, ip)
		stats.addUDP(cl)

		ts := time.Now().UTC().Format(time.RFC3339Nano)
		rows.addUDP(report.UDPDigestRow{
			TS: ts, PID: tgid, Comm: comm,
			Remote:   fmt.Sprintf("`%s:%d`", ip.String(), port),
			DgramLen: dgramLen,
			FQDN:     fqdn,
			Policy:   cl.Display(),
		}, stats)

		if cfg.EventsLogPath != "" {
			jsonlMu.Lock()
			n := seq.Next()
			ev := telemetry.UDPEvent{
				Type: "udp", TS: ts, Seq: n,
				PID: tgid, TGID: tgid, ThreadID: tid,
				Comm: comm, Dst: ip.String(), Dport: port,
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
		comm := string(bytes.TrimRight(commb[:], "\x00"))
		method, host, path, parsed := telemetry.ParseHTTPRequestPrefix(rawPay)
		if !parsed {
			stats.addDropped("http_prefix_parse")
			continue
		}
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
		comm := string(bytes.TrimRight(commb[:], "\x00"))
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
