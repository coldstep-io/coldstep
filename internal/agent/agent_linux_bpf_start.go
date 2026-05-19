//go:build linux

package agent

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/coldstep-io/coldstep/internal/bpf/tracebpfaudit"
	"github.com/coldstep-io/coldstep/internal/bpf/traceconnect"
	"github.com/coldstep-io/coldstep/internal/bpf/tracedns"
	"github.com/coldstep-io/coldstep/internal/bpf/tracektls"
)

var removeMemlockRlimit = rlimit.RemoveMemlock

func initMemlock() error {
	if err := removeMemlockRlimit(); err != nil {
		return fmt.Errorf("init memlock rlimit: %w", err)
	}
	return nil
}

// startSyscallTrace loads observability-only BPF (TCP connect + UDP sendto + HTTP sniff + TLS write sniff; single raw_tp attach).
// cgroup + LSM defend load separately (internal/bpf/defend) when mode is defend.
// When enableTLSSNI is true, sets tls_agent_cfg map so BPF emits TLS ClientHello captures.
// tlsAgentCfgFailed is set when the map update fails (SNI path stays off in BPF) so callers can mark the hook degraded.
func startSyscallTrace(enableTLSSNI bool) (connRd, udpRd, httpRd, tlsRd *ringbuf.Reader, objs *traceconnect.TraceconnectObjects, lnk link.Link, tlsAgentCfgFailed bool, err error) {
	objs = new(traceconnect.TraceconnectObjects)
	// Default: fast verifier path (nil opts). Branch + instruction verifier logging makes
	// LoadTraceconnectObjects disproportionately slow on hosted runners and can exceed the
	// composite action's waitForAgentReady window (see src/main.ts). Opt in via env for debugging:
	//   COLDSTEP_BPF_VERBOSE_VERIFY=1
	var traceLoadOpts *ebpf.CollectionOptions
	if strings.TrimSpace(os.Getenv("COLDSTEP_BPF_VERBOSE_VERIFY")) != "" {
		traceLoadOpts = &ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogLevel:     ebpf.LogLevelBranch | ebpf.LogLevelInstruction,
				LogSizeStart: 512 * 1024,
			},
		}
	}
	if err = traceconnect.LoadTraceconnectObjects(objs, traceLoadOpts); err != nil {
		return nil, nil, nil, nil, nil, nil, false, err
	}

	lnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.HandleRawSysEnter,
	})
	if err != nil {
		_ = objs.Close()
		return nil, nil, nil, nil, nil, nil, false, err
	}

	connRd, err = ringbuf.NewReader(objs.ConnectEvents)
	if err != nil {
		_ = lnk.Close()
		_ = objs.Close()
		return nil, nil, nil, nil, nil, nil, false, err
	}
	udpRd, err = ringbuf.NewReader(objs.UdpEvents)
	if err != nil {
		_ = connRd.Close()
		_ = lnk.Close()
		_ = objs.Close()
		return nil, nil, nil, nil, nil, nil, false, err
	}
	httpRd, err = ringbuf.NewReader(objs.HttpEvents)
	if err != nil {
		_ = udpRd.Close()
		_ = connRd.Close()
		_ = lnk.Close()
		_ = objs.Close()
		return nil, nil, nil, nil, nil, nil, false, err
	}
	tlsRd, err = ringbuf.NewReader(objs.TlsEvents)
	if err != nil {
		_ = httpRd.Close()
		_ = udpRd.Close()
		_ = connRd.Close()
		_ = lnk.Close()
		_ = objs.Close()
		return nil, nil, nil, nil, nil, nil, false, err
	}

	if enableTLSSNI {
		if uerr := objs.TlsAgentCfg.Update(uint32(0), uint8(1), ebpf.UpdateAny); uerr != nil {
			tlsAgentCfgFailed = true
			slog.Warn("tls_sni bpf cfg", "err", uerr)
		}
	}

	return connRd, udpRd, httpRd, tlsRd, objs, lnk, tlsAgentCfgFailed, nil
}

// attachTCPConnectKprobes attaches the P3-2 paired kprobe/kretprobe on
// tcp_v4_connect. The pair captures the kernel return code so the digest
// can distinguish established / refused / timeout / unreachable
// connections (the entry-side raw_tp/sys_enter on connect(2) cannot).
//
// We do NOT strip the kprobe programs from the BPF spec on unsupported
// kernels (unlike defend's LSM stripping): BPF_PROG_TYPE_KPROBE is
// universally available on every Linux kernel coldstep supports, so
// prog_load never fails. The actual failure mode is attach-time when
// tcp_v4_connect isn't exposed via the kprobe machinery (rare — would
// require CONFIG_KPROBES=n, which no hosted Ubuntu kernel ships with).
// Callers should log + carry on if this returns an error; the entry-side
// connect_event still records the attempt, just without a paired result.
func attachTCPConnectKprobes(objs *traceconnect.TraceconnectObjects) (kprobeLnk, kretprobeLnk link.Link, err error) {
	kprobeLnk, err = link.Kprobe("tcp_v4_connect", objs.KprobeTcpV4Connect, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("attach kprobe tcp_v4_connect: %w", err)
	}
	kretprobeLnk, err = link.Kretprobe("tcp_v4_connect", objs.KretprobeTcpV4Connect, nil)
	if err != nil {
		_ = kprobeLnk.Close()
		return nil, nil, fmt.Errorf("attach kretprobe tcp_v4_connect: %w", err)
	}
	return kprobeLnk, kretprobeLnk, nil
}

// startKTLSTrace loads trace_ktls.bpf.c and attaches the setsockopt(SOL_TLS)
// filter on raw_tp/sys_enter. Returns the ringbuf reader, objects (for the
// reserve-failure counter), and the attach link. Closes intermediates on error.
func startKTLSTrace() (rd *ringbuf.Reader, objs *tracektls.TracektlsObjects, lnk link.Link, err error) {
	objs = new(tracektls.TracektlsObjects)
	if err = tracektls.LoadTracektlsObjects(objs, nil); err != nil {
		return nil, nil, nil, err
	}

	lnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.HandleRawSysEnterKtls,
	})
	if err != nil {
		_ = objs.Close()
		return nil, nil, nil, err
	}

	rd, err = ringbuf.NewReader(objs.KtlsEvents)
	if err != nil {
		_ = lnk.Close()
		_ = objs.Close()
		return nil, nil, nil, err
	}
	return rd, objs, lnk, nil
}

func startBPFAuditTrace() (rd *ringbuf.Reader, objs *tracebpfaudit.TracebpfauditObjects, lnk link.Link, err error) {
	objs = new(tracebpfaudit.TracebpfauditObjects)
	if err = tracebpfaudit.LoadTracebpfauditObjects(objs, nil); err != nil {
		return nil, nil, nil, err
	}

	lnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.HandleRawSysEnterBpf,
	})
	if err != nil {
		_ = objs.Close()
		return nil, nil, nil, err
	}

	rd, err = ringbuf.NewReader(objs.BpfAuditEvents)
	if err != nil {
		_ = lnk.Close()
		_ = objs.Close()
		return nil, nil, nil, err
	}
	return rd, objs, lnk, nil
}

func startDNSTrace() (*ringbuf.Reader, *tracedns.TracednsObjects, link.Link, link.Link, error) {
	objs := new(tracedns.TracednsObjects)
	if err := tracedns.LoadTracednsObjects(objs, nil); err != nil {
		return nil, nil, nil, nil, err
	}

	lnkEnter, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.HandleRawSysEnterDns,
	})
	if err != nil {
		_ = objs.Close()
		return nil, nil, nil, nil, err
	}

	lnkExit, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: objs.HandleRawSysExitDns,
	})
	if err != nil {
		_ = lnkEnter.Close()
		_ = objs.Close()
		return nil, nil, nil, nil, err
	}

	rd, err := ringbuf.NewReader(objs.DnsEvents)
	if err != nil {
		_ = lnkExit.Close()
		_ = lnkEnter.Close()
		_ = objs.Close()
		return nil, nil, nil, nil, err
	}

	return rd, objs, lnkEnter, lnkExit, nil
}
