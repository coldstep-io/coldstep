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
)

var removeMemlockRlimit = rlimit.RemoveMemlock

func initMemlock() error {
	if err := removeMemlockRlimit(); err != nil {
		return fmt.Errorf("init memlock rlimit: %w", err)
	}
	return nil
}

// startSyscallTrace loads observability-only BPF (TCP connect + UDP sendto + HTTP sniff + TLS write sniff; single raw_tp attach).
// cgroup enforcement loads separately (traceenforce) when mode is enforce.
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
