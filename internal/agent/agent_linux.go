//go:build linux

// Package agent hosts the Linux BPF-backed Coldstep runtime.
//
// Many BPF loader unwind paths use `_ = x.Close()` during partial failure cleanup:
// the operator-facing error is the primary attach/load failure; chained Close errors
// are treated as best-effort (successful shutdown still uses defer Close() similarly).
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/coldstep-io/coldstep/internal/bpf/defend"
	"github.com/coldstep-io/coldstep/internal/bpf/tracebpfaudit"
	"github.com/coldstep-io/coldstep/internal/bpf/traceconnect"
	"github.com/coldstep-io/coldstep/internal/bpf/tracedns"
	"github.com/coldstep-io/coldstep/internal/bpf/traceexec"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefork"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefs"
	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/proctree"
	"github.com/coldstep-io/coldstep/internal/report"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// Run loads BPF, streams events until ctx is cancelled, then drains workers.
func Run(ctx context.Context, cfg config.Config) error {
	pol, err := cfg.Policy()
	if err != nil {
		return err
	}

	kernel := kernelRelease()
	stats := newRunStats()
	maxRows := report.DefaultMaxRowsPerSection
	rows := newRowBuffer(maxRows)
	sectionState := newNetworkSectionState()
	defendState := newDefendState()
	canary := newCanaryState()
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	procTreeGate := config.FeatureGateEnabled(cfg.FeatureGates, "proc_tree")
	tlsSNIGate := config.FeatureGateEnabled(cfg.FeatureGates, "tls_sni")
	fsGate := config.FeatureGateEnabled(cfg.FeatureGates, "fs_events")
	var forkBuf *forkEdgeBuffer
	var forkState *forkSectionState
	var fsRowBuf *fsRowBuffer
	var fsSt *fsSectionState
	signer, err := telemetry.NewSigner(cfg.SigningKey)
	if err != nil {
		return fmt.Errorf("setup telemetry signer: %w", err)
	}
	if err := initMemlock(); err != nil {
		return err
	}

	bpfSt := []telemetry.BPFStatus{
		{Name: "sched_process_exec", OK: false, Detail: "not loaded"},
		{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: false, Detail: "not loaded"},
		{Name: "dns recvfrom sniff", OK: false, Detail: "not loaded"},
		{Name: "kprobe tcp_v4_connect (connect_result)", OK: false, Detail: "not loaded"},
	}

	detectDest := cfg.StepSummaryPath
	if cfg.DetectLogPath != "" {
		detectDest = cfg.DetectLogPath
	}

	defer func() {
		sum := stats.snapshotSummary(kernel, bpfSt)
		if err := telemetry.WriteSummary(cfg.TelemetrySummaryPath, sum, signer); err != nil {
			slog.Warn("telemetry summary", "err", err)
		}
		if detectDest != "" {
			execRows, tcpRows, udpRows, httpRows, tlsRows := rows.snapshot()
			seqLast := seq.Last()
			var forkEdges []proctree.Edge
			forkTrunc := false
			forkSnap := forkSectionSnapshot{}
			if forkBuf != nil {
				forkEdges, forkTrunc = forkBuf.snapshot()
			}
			if forkState != nil {
				forkSnap = forkState.snapshot()
			}
			var fsDigestRows []report.FSDigestRow
			fsSnap := fsSectionSnapshot{}
			if fsRowBuf != nil {
				fsDigestRows = fsRowBuf.snapshot()
			}
			if fsSt != nil {
				fsSnap = fsSt.snapshot()
			}
			in := buildDigestInput(cfg, stats, bpfSt, execRows, tcpRows, udpRows, httpRows, tlsRows, cfg.EventsLogPath, seqLast, maxRows, sectionState.snapshot(), defendState.snapshot(), forkEdges, forkTrunc, forkSnap, procTreeGate, tlsSNIGate, fsDigestRows, fsSnap, fsGate, canary.snapshot())
			in.PolicyCounts = sum.PolicyCounts
			if err := report.WriteDetectDigest(detectDest, in); err != nil {
				slog.Warn("detect digest", "err", err)
			}
		}
	}()

	compileCtx, compileCancel := context.WithTimeout(ctx, 120*time.Second)
	defer compileCancel()
	defendCompiled, err := compileDefendAllowlist(compileCtx, cfg, nil, 2)
	if err != nil {
		return err
	}

	dnsCache := NewDNSCache()
	dnsCache.SetBPFFailureCallback(stats.addDNSCacheUpdateFailure)

	var connRd, udpRd, httpRd, tlsRd ringReader
	defer connRd.Close()
	defer udpRd.Close()
	defer httpRd.Close()
	defer tlsRd.Close()

	var denyRd ringReader
	defer denyRd.Close()
	var lsmDenyRd ringReader
	defer lsmDenyRd.Close()
	var syscallObjs *traceconnect.TraceconnectObjects
	var syscallLnk link.Link
	var defendObjs defend.DefendObjects
	var hasDefend bool
	var hasLSM bool
	var defendConnectLnk link.Link
	var defendSendmsgLnk link.Link

	// Defend mode: cgroup attach before traceexec/traceconnect. Ready status is written only after
	// syscall egress tracing attaches (defend requires it); sched_process_exec + raw_tp/sys_enter loads
	// can each take minutes on hosted runners — GitHub Actions fail-on-error waits on .coldstep-ready.json.
	if cfg.Mode == config.ModeDefend {
		haveLSM := false
		if err := features.HaveProgramType(ebpf.LSM); err == nil {
			haveLSM = true
		}

		// Phase 2.3: cgroup + LSM share one bpf2go object. The loader strips
		// LSM programs (and their dedicated maps) from the spec when the
		// kernel lacks CONFIG_BPF_LSM so prog_load doesn't fail.
		if err := defend.LoadDefendObjectsForKernel(&defendObjs, haveLSM); err != nil {
			return fmt.Errorf("load defend bpf objects: %w", err)
		}
		hasDefend = true
		defer func() {
			defendState.setDenyReserveFailures(readDenyReserveFailureCount(&defendObjs))
			if hasLSM {
				defendState.setDenyReserveFailures(readLSMDenyReserveFailureCount(&defendObjs))
			}
			_ = defendObjs.Close()
		}()

		var lsmAttachErr error

		if haveLSM {
			if _, _, loadErr := loadLSMDefendMaps(&defendObjs, defendCompiled, pol); loadErr != nil {
				return loadErr
			}

			rd, err := ringbuf.NewReader(defendObjs.LsmDenyEvents)
			if err != nil {
				return fmt.Errorf("ringbuf reader lsm deny: %w", err)
			}

			lnk1, err := link.AttachLSM(link.LSMOptions{Program: defendObjs.LsmSocketConnect})
			if err != nil {
				lsmAttachErr = fmt.Errorf("attach lsm_socket_connect: %w", err)
				_ = rd.Close()
			} else {
				lnk2, err := link.AttachLSM(link.LSMOptions{Program: defendObjs.LsmSocketSendmsg})
				if err != nil {
					lsmAttachErr = fmt.Errorf("attach lsm_socket_sendmsg: %w", err)
					_ = lnk1.Close()
					_ = rd.Close()
				} else {
					hasLSM = true
					// Keep the LSM ringbuf as a secondary reader. The primary denyRd
					// always reads from the cgroup ringbuf (attached below) because on
					// some kernels (e.g. Ubuntu 24.04 default) LSM hooks attach but
					// never fire — `lsm_deny_events` then stays empty even though
					// cgroup is defending.
					lsmDenyRd.R = rd
					defer lnk1.Close()
					defer lnk2.Close()
				}
			}
		}

		backend := chooseDefendBackend(
			defendBackendConfig{
				modeDefend: cfg.Mode == config.ModeDefend,
				haveLSM:    haveLSM,
			},
			lsmAttachErr,
		)
		if lsmAttachErr != nil {
			slog.Warn("lsm defend attach failed; falling back to cgroup", "err", lsmAttachErr)
		}

		// Always program the cgroup defend maps and attach the cgroup hooks,
		// regardless of whether LSM also attached. The cgroup hook is the
		// reliable always-on defense path: LSM hooks may attach but never fire
		// when the kernel's `lsm=` boot chain excludes BPF (Ubuntu 24.04 ships
		// this way). The primary deny reader watches the cgroup `deny_events`
		// ringbuf; the LSM ringbuf, when present, is drained by a separate
		// reader.
		allowlistSize, ignoredSize, loadErr := loadDefendMaps(&defendObjs, defendCompiled, pol)
		if loadErr != nil {
			return loadErr
		}
		defendState.setModeAndAllowlist(defendModeForBackend(backend.backend), allowlistSize, ignoredSize)
		rd, err := ringbuf.NewReader(defendObjs.DenyEvents)
		if err != nil {
			return fmt.Errorf("ringbuf reader deny: %w", err)
		}
		denyRd.R = rd

		cgPath := cfg.CgroupAttachPath
		if cgPath == "" {
			cgPath = "/sys/fs/cgroup"
		}

		defendConnectLnk, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgPath,
			Attach:  ebpf.AttachCGroupInet4Connect,
			Program: defendObjs.DefendConnect4,
		})
		if err != nil {
			return fmt.Errorf("attach defend_connect4: %w", err)
		}
		defer defendConnectLnk.Close()

		defendSendmsgLnk, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgPath,
			Attach:  ebpf.AttachCGroupUDP4Sendmsg,
			Program: defendObjs.DefendSendmsg4,
		})
		if err != nil {
			return fmt.Errorf("attach defend_sendmsg4: %w", err)
		}
		defer defendSendmsgLnk.Close()

		// AttachCgroup returns once the program is bound, but on hosted runners the
		// kernel has been observed to not yet enforce for newly-created sockets for
		// ~1-3s afterward — so the first connect after .coldstep-ready.json was
		// written could slip through. Block until a live probe deny is observed.
		if err := probeDefendEnforcement(denyRd.R, defaultProbeTimeout); err != nil {
			_ = writeAgentStatus(cfg.AgentStatusPath, false)
			return fmt.Errorf("defend mode requires confirmed cgroup BPF enforcement: %w", err)
		}
	}

	var execObjs traceexec.TraceexecObjects
	if err := traceexec.LoadTraceexecObjects(&execObjs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer execObjs.Close()
	defer func() { stats.setExecRingbufReserveFailures(readExecRingbufReserveFailureCount(&execObjs)) }()

	execLnk, err := link.Tracepoint("sched", "sched_process_exec", execObjs.HandleSchedProcessExec, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sched_process_exec: %w", err)
	}
	defer execLnk.Close()
	bpfSt[0] = telemetry.BPFStatus{Name: "sched_process_exec", OK: true}

	var execRd ringReader
	{
		rd, err := ringbuf.NewReader(execObjs.Events)
		if err != nil {
			return fmt.Errorf("ringbuf reader exec: %w", err)
		}
		execRd.R = rd
	}
	// execRd is normally closed by the runCtx shutdown goroutine. The defer here covers
	// any return before that goroutine is registered (e.g. defend mode when syscall trace
	// attach fails). ringReader.Close is once-guarded, so the double defer is safe.
	defer execRd.Close()

	if cR, uR, hR, tR, objs, lnk, tlsCfgFailed, err := startSyscallTrace(tlsSNIGate); err != nil {
		slog.Info("syscall egress tracing disabled", "err", err)
		bpfSt[1] = telemetry.BPFStatus{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: false, Detail: bpfDetail(err)}
		if cfg.Mode == config.ModeDefend {
			// Keep the status file for the composite post step; main may have already saved
			// saveState. Record operational failure explicitly instead of deleting the path.
			_ = writeAgentStatus(cfg.AgentStatusPath, false)
			return fmt.Errorf("defend mode requires syscall trace attach: %w", err)
		}
	} else {
		connRd.R, udpRd.R, httpRd.R, tlsRd.R = cR, uR, hR, tR
		syscallObjs, syscallLnk = objs, lnk
		syscallOK := true
		syscallDetail := ""
		if tlsCfgFailed {
			syscallOK = false
			syscallDetail = "tls_agent_cfg map update failed (TLS SNI sniff disabled in BPF)"
		}
		bpfSt[1] = telemetry.BPFStatus{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: syscallOK, Detail: syscallDetail}
		slog.Info("tracing connect + UDP sendto + HTTP/80 sniff + optional TLS write (raw_tp/sys_enter)")

		// P3-2: paired kprobe/kretprobe on tcp_v4_connect. Captures the
		// kernel return code so the digest can distinguish established
		// from refused / timeout / unreachable connections. Failure here
		// is non-fatal — the entry-side connect_event still records the
		// attempt, just without a paired result.
		if kpLnk, krLnk, kerr := attachTCPConnectKprobes(syscallObjs); kerr != nil {
			slog.Info("tcp_v4_connect kprobe pair attach failed; connect_result events disabled", "err", kerr)
			bpfSt[3] = telemetry.BPFStatus{Name: "kprobe tcp_v4_connect (connect_result)", OK: false, Detail: bpfDetail(kerr)}
		} else {
			bpfSt[3] = telemetry.BPFStatus{Name: "kprobe tcp_v4_connect (connect_result)", OK: true}
			slog.Info("tcp_v4_connect kprobe/kretprobe attached (connect_result events enabled)")
			defer kpLnk.Close()
			defer krLnk.Close()
		}

		// Defend mode readiness is written after the deny reader goroutine launches
		// (further below); writing it here would race the action's probe steps, which
		// run as soon as readiness is set, against the reader being alive.
		defer syscallObjs.Close()
		defer syscallLnk.Close()
		defer func() {
			if syscallObjs != nil {
				stats.setConnect4TupleUpdateFailures(readConnect4TupleUpdateFailureCount(syscallObjs))
				stats.setUDPRingbufReserveFailures(readUDPRingbufReserveFailureCount(syscallObjs))
				stats.setConnectRingbufReserveFailures(readConnectRingbufReserveFailureCount(syscallObjs))
				stats.setHTTPRingbufReserveFailures(readHTTPRingbufReserveFailureCount(syscallObjs))
				stats.setTLSRingbufReserveFailures(readTLSRingbufReserveFailureCount(syscallObjs))
				stats.setUDPSendmsgMultiIovecObserved(readUDPSendmsgMultiIovecObservedCount(syscallObjs))
				stats.setSendmmsgMultiMessage(readSendmmsgMultiMessageCount(syscallObjs))
				stats.setTLSWritevMultiIovecObserved(readTLSWritevMultiIovecObservedCount(syscallObjs))
				sendfileN, spliceN, sendmmsgN := readPartialEgressCounts(syscallObjs)
				stats.setPartialEgressObserved(sendfileN, spliceN, sendmmsgN)
				stats.setIoUringSetupObserved(readIoUringSetupObservedCount(syscallObjs))
			}
		}()
		// Ring readers are closed exactly once via ringReader.Close (runCtx shutdown goroutine + deferred Close).
	}

	// Detect mode: ready after syscall trace initialized. Defend mode defers readiness
	// until after the deny reader goroutine is launched (further below).
	if cfg.Mode != config.ModeDefend {
		if err := writeAgentStatus(cfg.AgentStatusPath, true); err != nil {
			return fmt.Errorf("agent ready status: %w", err)
		}
	}

	var dnsRd ringReader
	defer dnsRd.Close()

	var dnsObjs *tracedns.TracednsObjects
	var dnsLnkEnter, dnsLnkExit link.Link
	if rd, objs, le, lx, err := startDNSTrace(); err != nil {
		slog.Info("dns reply sniffing disabled", "err", err)
		bpfSt[2] = telemetry.BPFStatus{Name: "dns recvfrom sniff", OK: false, Detail: bpfDetail(err)}
	} else {
		dnsRd.R = rd
		dnsObjs, dnsLnkEnter, dnsLnkExit = objs, le, lx
		// Register every live dns_cache map so userspace DNS observations
		// flow into all in-kernel programs that consult dns_cache for
		// late-binding IP -> FQDN attribution. Defend's cgroup + LSM sections
		// share one dns_cache map (Phase 2.3 merge), so a single defend
		// entry covers both hook families (M-14, paired with H-03's deletes).
		dnsCacheMaps := []*ebpf.Map{dnsObjs.DnsCache}
		if hasDefend && defendObjs.DnsCache != nil {
			dnsCacheMaps = append(dnsCacheMaps, defendObjs.DnsCache)
		}
		dnsCache.SetBPFMaps(dnsCacheMaps)
		bpfSt[2] = telemetry.BPFStatus{Name: "dns recvfrom sniff", OK: true}
		slog.Info("tracing DNS replies (recvfrom)")
		defer dnsObjs.Close()
		defer dnsLnkExit.Close()
		defer dnsLnkEnter.Close()
		defer func() {
			if dnsObjs != nil {
				stats.setDNSRingbufReserveFailures(readDNSRingbufReserveFailureCount(dnsObjs))
				stats.setTCPDNSResponsesObserved(readTCPDNSResponsesObservedCount(dnsObjs))
				stats.setTCPDNSSkippedShortRead(readTCPDNSSkippedShortReadCount(dnsObjs))
			}
		}()
	}

	var bpfAuditRd ringReader
	defer bpfAuditRd.Close()
	var bpfAuditObjs *tracebpfaudit.TracebpfauditObjects
	var bpfAuditLnk link.Link

	var forkRd ringReader
	defer forkRd.Close()
	var forkObjs *tracefork.TraceforkObjects
	var forkLnk link.Link
	if procTreeGate {
		forkBuf = newForkEdgeBuffer(5000)
		forkState = newForkSectionState()
		objs := new(tracefork.TraceforkObjects)
		if err := tracefork.LoadTraceforkObjects(objs, nil); err != nil {
			slog.Info("sched_process_fork tracing disabled", "err", err)
			bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: false, Detail: bpfDetail(err)})
		} else {
			forkObjs = objs
			lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
				Name:    "sched_process_fork",
				Program: objs.HandleSchedProcessFork,
			})
			if err != nil {
				slog.Info("sched_process_fork attach failed", "err", err)
				bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: false, Detail: bpfDetail(err)})
				_ = objs.Close()
				forkObjs = nil
			} else {
				forkLnk = lnk
				rd, err := ringbuf.NewReader(objs.ForkEvents)
				if err != nil {
					slog.Info("sched_process_fork ringbuf reader failed", "err", err)
					bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: false, Detail: bpfDetail(err)})
					_ = lnk.Close()
					_ = objs.Close()
					forkObjs = nil
					forkLnk = nil
				} else {
					forkRd.R = rd
					bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: true})
					slog.Info("tracing sched_process_fork (process tree)")
					defer func() {
						if forkObjs != nil {
							stats.setForkRingbufReserveFailures(readForkRingbufReserveFailureCount(forkObjs))
						}
						forkRd.Close()
						if forkLnk != nil {
							_ = forkLnk.Close()
						}
						if forkObjs != nil {
							_ = forkObjs.Close()
						}
					}()
				}
			}
		}
	}

	var fsRd ringReader
	defer fsRd.Close()

	var fsObjs *tracefs.TracefsObjects
	var fsLnk link.Link
	if fsGate {
		fsRowBuf = newFSRowBuffer(maxRows)
		fsSt = newFSSectionState()
		objs := new(tracefs.TracefsObjects)
		if err := tracefs.LoadTracefsObjects(objs, nil); err != nil {
			slog.Info("fs tracing disabled", "err", err)
			bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
		} else {
			var fsCfgErr error
			if err := objs.FsAgentCfg.Update(uint32(0), uint8(1), ebpf.UpdateAny); err != nil {
				fsCfgErr = err
				slog.Warn("fs cfg map update", "err", err)
			}
			fsObjs = objs
			lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
				Name:    "sys_enter",
				Program: objs.HandleFsSysEnter,
			})
			if err != nil {
				slog.Info("fs sys_enter attach failed", "err", err)
				bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
				_ = objs.Close()
				fsObjs = nil
			} else {
				fsLnk = lnk
				rd, err := ringbuf.NewReader(objs.FsEvents)
				if err != nil {
					slog.Info("fs ringbuf reader failed", "err", err)
					bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
					_ = lnk.Close()
					_ = objs.Close()
					fsObjs = nil
					fsLnk = nil
				} else {
					fsRd.R = rd
					fsOK := true
					fsDetail := ""
					if fsCfgErr != nil {
						fsOK = false
						fsDetail = bpfDetail(fsCfgErr)
						if fsDetail == "" {
							fsDetail = "fs_agent_cfg map update failed (fs events disabled in BPF)"
						}
					}
					bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: fsOK, Detail: fsDetail})
					slog.Info("tracing fs events (openat+create, unlink, rename, chmod)")
					defer func() {
						if fsObjs != nil {
							stats.setFSRingbufReserveFailures(readFSRingbufReserveFailureCount(fsObjs))
						}
						fsRd.Close()
						if fsLnk != nil {
							_ = fsLnk.Close()
						}
						if fsObjs != nil {
							_ = fsObjs.Close()
						}
					}()
				}
			}
		}
	}

	// Attach bpf() audit tracing only after other BPF collections finish loading.
	// Otherwise coldstep's own bpf(2) syscalls during object load can fill the small
	// audit ringbuf before readBPFAuditRing starts, dropping later canary traffic (e.g. bpftool).
	if bR, bO, bL, err := startBPFAuditTrace(); err != nil {
		slog.Info("bpf audit trace disabled", "err", err)
		bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (bpf audit)", OK: false, Detail: bpfDetail(err)})
	} else {
		bpfAuditRd.R = bR
		bpfAuditObjs, bpfAuditLnk = bO, bL
		bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (bpf audit)", OK: true})
		slog.Info("tracing bpf() syscall audit (raw_tp/sys_enter)")
		defer bpfAuditObjs.Close()
		defer bpfAuditLnk.Close()
		defer func() {
			if bpfAuditObjs != nil {
				stats.setBPFAuditRingbufReserveFailures(readBPFAuditRingbufReserveFailureCount(bpfAuditObjs))
			}
		}()
	}

	if cfg.EventsLogPath != "" {
		meta, err := telemetry.BuildMeta(agentVersionString(), bpfSt, cfg.DetectProfile)
		if err != nil {
			slog.Warn("build meta", "err", err)
		} else {
			if capabilityEnabled(procTreeGate, bpfSt, "sched_process_fork") {
				if meta.Capabilities == nil {
					meta.Capabilities = make(map[string]bool)
				}
				meta.Capabilities["proc_tree"] = true
			}
			if capabilityEnabled(tlsSNIGate, bpfSt, "raw_tp/sys_enter (connect, sendto, http sniff, tls)") {
				if meta.Capabilities == nil {
					meta.Capabilities = make(map[string]bool)
				}
				meta.Capabilities["tls_sni"] = true
			}
			if capabilityEnabled(fsGate, bpfSt, "raw_tp/sys_enter (fs)") {
				if meta.Capabilities == nil {
					meta.Capabilities = make(map[string]bool)
				}
				meta.Capabilities["fs_events"] = true
			}
			if err := telemetry.AppendJSONL(cfg.EventsLogPath, meta, signer); err != nil {
				slog.Warn("meta jsonl", "err", err)
			}
		}
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	go func() {
		<-runCtx.Done()
		execRd.Close()
		connRd.Close()
		udpRd.Close()
		httpRd.Close()
		tlsRd.Close()
		denyRd.Close()
		lsmDenyRd.Close()
		dnsRd.Close()
		bpfAuditRd.Close()
		forkRd.Close()
		fsRd.Close()
	}()

	slog.Info("coldstep event readers started", "mode", string(cfg.Mode))

	// Each reader goroutine sends one error on exit; buffer must fit all sends before wg.Wait returns.
	readerCount := 1
	if forkRd.R != nil && forkBuf != nil && forkState != nil {
		readerCount++
	}
	if fsRd.R != nil && fsRowBuf != nil && fsSt != nil {
		readerCount++
	}
	if connRd.R != nil {
		readerCount++
	}
	if udpRd.R != nil {
		readerCount++
	}
	if httpRd.R != nil {
		readerCount++
	}
	if tlsRd.R != nil {
		readerCount++
	}
	if denyRd.R != nil {
		readerCount++
	}
	if lsmDenyRd.R != nil {
		readerCount++
	}
	if dnsRd.R != nil {
		readerCount++
	}
	if bpfAuditRd.R != nil {
		readerCount++
	}
	if hasDefend {
		readerCount++
	}
	if hasLSM {
		readerCount++
	}

	var wg sync.WaitGroup
	errCh := make(chan error, readerCount)

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- readExecRing(runCtx, cfg, execRd.R, stats, rows, &seq, &jsonlMu, signer)
	}()

	if forkRd.R != nil && forkBuf != nil && forkState != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readForkRing(runCtx, cfg, forkRd.R, stats, forkBuf, forkState, &seq, &jsonlMu, signer)
		}()
	}

	if fsRd.R != nil && fsRowBuf != nil && fsSt != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readFSRing(runCtx, cfg, fsRd.R, stats, fsRowBuf, fsSt, &seq, &jsonlMu, signer)
		}()
	}

	if connRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readConnectRing(runCtx, cfg, connRd.R, dnsCache, pol, stats, rows, &seq, &jsonlMu, sectionState, canary, signer)
		}()
	}

	// Telemetry integrity canary injection goroutine: writes a monotonic
	// sequence number to the canary_trigger BPF map every canaryInterval.
	// The BPF program picks it up on the next sys_enter and emits a canary
	// event through connect_events ringbuf. If the canary doesn't arrive
	// in readConnectRing, canaryState records a failure.
	if syscallObjs != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var seqNr uint64
			ticker := time.NewTicker(canaryInterval)
			defer ticker.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-ticker.C:
					seqNr++
					var k uint32
					if err := syscallObjs.CanaryTrigger.Update(&k, &seqNr, ebpf.UpdateAny); err != nil {
						slog.Warn("canary trigger write failed", "err", err)
						continue
					}
					canary.noteSent(seqNr)
					slog.Debug("canary armed", "seq", seqNr)

					// Check if previous canary timed out.
					if canary.checkAndRecordFailure() {
						slog.Error("telemetry integrity canary FAILED — pipeline may be compromised",
							"last_sent", canary.snapshot().lastSent,
							"last_received", canary.snapshot().lastReceived)
					}
				}
			}
		}()
	}

	// Capability 7A: BPF self-protection heartbeat monitor.
	// Periodically polls the main sys_enter BPF program to ensure it's still attached and valid.
	if syscallObjs != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-ticker.C:
					// Prog.Info() uses bpf_obj_get_info_by_fd.
					// If the BPF program was detached and garbage collected,
					// or the fd was somehow broken, this will return an error.
					info, err := syscallObjs.HandleRawSysEnter.Info()
					if err != nil {
						slog.Error("BPF heartbeat FAILED: sys_enter program get_info error", "err", err)
						stats.addBPFHeartbeatFailure()
						continue
					}
					id, ok := info.ID()
					if ok {
						slog.Debug("BPF heartbeat OK", "id", id)
					} else {
						slog.Warn("BPF heartbeat: program has no ID")
						stats.addBPFHeartbeatFailure()
					}
				}
			}
		}()
	}

	if udpRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readUDPRing(runCtx, cfg, udpRd.R, dnsCache, pol, stats, rows, &seq, &jsonlMu, sectionState, signer)
		}()
	}
	if httpRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readHTTPRing(runCtx, cfg, httpRd.R, pol, stats, rows, &seq, &jsonlMu, sectionState, signer)
		}()
	}
	if tlsRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readTLSRing(runCtx, cfg, tlsRd.R, pol, stats, rows, &seq, &jsonlMu, sectionState, signer)
		}()
	}
	if denyRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readDenyRing(runCtx, cfg, denyRd.R, &seq, &jsonlMu, defendState, signer, "cgroup", dnsCache)
		}()
	}
	if lsmDenyRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readDenyRing(runCtx, cfg, lsmDenyRd.R, &seq, &jsonlMu, defendState, signer, "lsm", dnsCache)
		}()
	}
	if dnsRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readDNSRing(runCtx, dnsRd.R, dnsCache, stats)
		}()
	}
	if bpfAuditRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readBPFAuditRing(runCtx, cfg, bpfAuditRd.R, stats, &seq, &jsonlMu, signer)
		}()
	}

	if hasDefend {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- watchMapIntegrity(runCtx, cfg, defendObjs.DefendCfg, defendObjs.AllowedIpv4, defendObjs.IgnoredIpv4Lpm, defendCompiled, pol, stats, defendState, &seq, &jsonlMu, signer)
		}()
	}
	if hasLSM {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- watchMapIntegrity(runCtx, cfg, defendObjs.LsmDefendCfg, defendObjs.LsmAllowedIpv4, defendObjs.LsmIgnoredIpv4Lpm, defendCompiled, pol, stats, defendState, &seq, &jsonlMu, signer)
		}()
	}

	// Defend-mode readiness: write only after the deny reader goroutine(s) are alive,
	// so the GitHub Action's probe steps (which start as soon as readiness flips) cannot
	// race the reader being attached. Detect-mode readiness was written above.
	var readyErr error
	if cfg.Mode == config.ModeDefend {
		if err := writeAgentStatus(cfg.AgentStatusPath, true); err != nil {
			readyErr = fmt.Errorf("agent ready status: %w", err)
			runCancel()
		}
	}

	wg.Wait()
	close(errCh)

	var retErr error
	for err := range errCh {
		retErr = preferRunError(retErr, err)
	}
	if readyErr != nil {
		return preferRunError(readyErr, retErr)
	}
	return retErr
}

// Main is the entry-point used by cmd/coldstep when the agent re-execs
// itself under sudo. It loads configuration from environment variables
// (see config.LoadFromEnv), installs SIGINT/SIGTERM-aware cancellation,
// and delegates to Run. A nil return signals normal shutdown; cancellation
// via SIGINT/SIGTERM is intentionally collapsed to nil because the wrapper
// process treats it as a graceful stop, not a failure.
func Main() error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	setupLogging(cfg.LogLevel)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func loadAllowedDomainsMap(m *ebpf.Map, pol *policy.Policy) error {
	if pol != nil && pol.HasWildSuffixes() {
		// The BPF allowed_domains map uses exact-string lookup; wildcard allowed-hosts
		// entries (e.g. *.example.com) are not inserted and have no effect in defend
		// mode. Use allowed-domains or allowed-ips for BPF defense of those hosts.
		slog.Warn("defend mode: wildcard allowed-hosts entries are classify-only and will NOT be applied by BPF; add matching allowed-domains or allowed-ips entries")
	}
	domains := pol.AllowedDomains()
	for _, domain := range domains {
		// Key is [256]byte (fixed size in BPF)
		var key [256]byte
		copy(key[:], domain)
		val := uint8(1)
		if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update allowed_domains map for %s: %w", domain, err)
		}
	}
	return nil
}
