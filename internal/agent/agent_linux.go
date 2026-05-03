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
	"github.com/coldstep-io/coldstep/internal/bpf/tracebpfaudit"
	"github.com/coldstep-io/coldstep/internal/bpf/traceconnect"
	"github.com/coldstep-io/coldstep/internal/bpf/tracedns"
	"github.com/coldstep-io/coldstep/internal/bpf/traceenforce"
	"github.com/coldstep-io/coldstep/internal/bpf/traceexec"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefork"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefs"
	"github.com/coldstep-io/coldstep/internal/bpf/tracelsmenforce"
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
	enforceState := newEnforcementState()
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
			in := buildDigestInput(cfg, stats, bpfSt, execRows, tcpRows, udpRows, httpRows, tlsRows, cfg.EventsLogPath, seqLast, maxRows, sectionState.snapshot(), enforceState.snapshot(), forkEdges, forkTrunc, forkSnap, procTreeGate, tlsSNIGate, fsDigestRows, fsSnap, fsGate, canary.snapshot())
			in.PolicyCounts = sum.PolicyCounts
			if err := report.WriteDetectDigest(detectDest, in); err != nil {
				slog.Warn("detect digest", "err", err)
			}
		}
	}()

	compileCtx, compileCancel := context.WithTimeout(ctx, 120*time.Second)
	defer compileCancel()
	enforceCompiled, err := compileEnforceAllowlist(compileCtx, cfg, nil, 2)
	if err != nil {
		return err
	}

	dnsCache := NewDNSCache()
	dnsCache.SetBPFFailureCallback(stats.addDNSCacheUpdateFailure)

	var connRd, udpRd, httpRd, tlsRd *ringbuf.Reader
	var syscallReadersOnce sync.Once
	closeSyscallReaders := func() {
		syscallReadersOnce.Do(func() {
			if connRd != nil {
				_ = connRd.Close()
			}
			if udpRd != nil {
				_ = udpRd.Close()
			}
			if httpRd != nil {
				_ = httpRd.Close()
			}
			if tlsRd != nil {
				_ = tlsRd.Close()
			}
		})
	}
	defer closeSyscallReaders()

	var denyRd *ringbuf.Reader
	var denyRdOnce sync.Once
	closeDenyRd := func() {
		denyRdOnce.Do(func() {
			if denyRd != nil {
				_ = denyRd.Close()
			}
		})
	}
	defer closeDenyRd()
	var syscallObjs *traceconnect.TraceconnectObjects
	var syscallLnk link.Link
	var enforceObjs traceenforce.TraceenforceObjects
	var lsmObjs *tracelsmenforce.TracelsmenforceObjects
	var hasEnforce bool
	var hasLSM bool
	var enforceConnectLnk link.Link
	var enforceSendmsgLnk link.Link

	// Enforce mode: cgroup attach before traceexec/traceconnect. Ready status is written only after
	// syscall egress tracing attaches (enforce requires it); sched_process_exec + raw_tp/sys_enter loads
	// can each take minutes on hosted runners — GitHub Actions fail-on-error waits on .coldstep-ready.json.
	if cfg.Mode == config.ModeEnforce {
		haveLSM := false
		if err := features.HaveProgramType(ebpf.LSM); err == nil {
			haveLSM = true
		}
		var lsmAttachErr error

		if haveLSM {
			lsmCandidate := new(tracelsmenforce.TracelsmenforceObjects)
			if err := tracelsmenforce.LoadTracelsmenforceObjects(lsmCandidate, nil); err != nil {
				return fmt.Errorf("load lsm enforce bpf objects: %w", err)
			}

			allowlistSize, ignoredSize, loadErr := loadLSMEnforceMaps(lsmCandidate, enforceCompiled, pol)
			if loadErr != nil {
				_ = lsmCandidate.Close()
				return loadErr
			}

			lsmDenyRd, err := ringbuf.NewReader(lsmCandidate.LsmDenyEvents)
			if err != nil {
				_ = lsmCandidate.Close()
				return fmt.Errorf("ringbuf reader lsm deny: %w", err)
			}

			lnk1, err := link.AttachLSM(link.LSMOptions{Program: lsmCandidate.LsmSocketConnect})
			if err != nil {
				lsmAttachErr = fmt.Errorf("attach lsm_socket_connect: %w", err)
				_ = lsmDenyRd.Close()
				_ = lsmCandidate.Close()
			} else {
				lnk2, err := link.AttachLSM(link.LSMOptions{Program: lsmCandidate.LsmSocketSendmsg})
				if err != nil {
					lsmAttachErr = fmt.Errorf("attach lsm_socket_sendmsg: %w", err)
					_ = lnk1.Close()
					_ = lsmDenyRd.Close()
					_ = lsmCandidate.Close()
				} else {
					lsmObjs = lsmCandidate
					hasLSM = true
					denyRd = lsmDenyRd
					enforceState.setModeAndAllowlist(enforceModeForBackend(enforceBackendLSM), allowlistSize, ignoredSize)
					defer func() {
						enforceState.setDenyReserveFailures(readLSMDenyReserveFailureCount(lsmObjs))
						_ = lsmObjs.Close()
					}()
					defer lnk1.Close()
					defer lnk2.Close()
				}
			}
		}

		backend := chooseEnforceBackend(
			enforceBackendConfig{
				modeEnforce: cfg.Mode == config.ModeEnforce,
				haveLSM:     haveLSM,
			},
			lsmAttachErr,
		)
		if backend.backend == enforceBackendCgroup {
			if lsmAttachErr != nil {
				slog.Warn("lsm enforce attach failed; falling back to cgroup", "err", lsmAttachErr)
			}
			if err := traceenforce.LoadTraceenforceObjects(&enforceObjs, nil); err != nil {
				return fmt.Errorf("load enforce bpf objects: %w", err)
			}
			hasEnforce = true
			defer func() {
				enforceState.setDenyReserveFailures(readDenyReserveFailureCount(&enforceObjs))
				_ = enforceObjs.Close()
			}()

			allowlistSize, ignoredSize, loadErr := loadEnforceMaps(&enforceObjs, enforceCompiled, pol)
			if loadErr != nil {
				return loadErr
			}
			enforceState.setModeAndAllowlist(enforceModeForBackend(backend.backend), allowlistSize, ignoredSize)
			var err error
			denyRd, err = ringbuf.NewReader(enforceObjs.DenyEvents)
			if err != nil {
				return fmt.Errorf("ringbuf reader deny: %w", err)
			}

			cgPath := cfg.CgroupAttachPath
			if cgPath == "" {
				cgPath = "/sys/fs/cgroup"
			}

			enforceConnectLnk, err = link.AttachCgroup(link.CgroupOptions{
				Path:    cgPath,
				Attach:  ebpf.AttachCGroupInet4Connect,
				Program: enforceObjs.EnforceConnect4,
			})
			if err != nil {
				return fmt.Errorf("attach enforce_connect4: %w", err)
			}
			defer enforceConnectLnk.Close()

			enforceSendmsgLnk, err = link.AttachCgroup(link.CgroupOptions{
				Path:    cgPath,
				Attach:  ebpf.AttachCGroupUDP4Sendmsg,
				Program: enforceObjs.EnforceSendmsg4,
			})
			if err != nil {
				return fmt.Errorf("attach enforce_sendmsg4: %w", err)
			}
			defer enforceSendmsgLnk.Close()
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

	execRd, err := ringbuf.NewReader(execObjs.Events)
	if err != nil {
		return fmt.Errorf("ringbuf reader exec: %w", err)
	}
	// execRd is normally closed when runCtx is cancelled (see goroutine below). Any return
	// before that goroutine is registered would otherwise leak the reader (e.g. enforce mode
	// when syscall trace attach fails, or enforce BPF/map/attach errors).
	closeExecRdOnEarlyExit := true
	defer func() {
		if closeExecRdOnEarlyExit {
			_ = execRd.Close()
		}
	}()

	if cR, uR, hR, tR, objs, lnk, tlsCfgFailed, err := startSyscallTrace(tlsSNIGate); err != nil {
		slog.Info("syscall egress tracing disabled", "err", err)
		bpfSt[1] = telemetry.BPFStatus{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: false, Detail: bpfDetail(err)}
		if cfg.Mode == config.ModeEnforce {
			// Keep the status file for the composite post step; main may have already saved
			// saveState. Record operational failure explicitly instead of deleting the path.
			_ = writeAgentStatus(cfg.AgentStatusPath, false)
			return fmt.Errorf("enforce mode requires syscall trace attach: %w", err)
		}
	} else {
		connRd, udpRd, httpRd, tlsRd, syscallObjs, syscallLnk = cR, uR, hR, tR, objs, lnk
		syscallOK := true
		syscallDetail := ""
		if tlsCfgFailed {
			syscallOK = false
			syscallDetail = "tls_agent_cfg map update failed (TLS SNI sniff disabled in BPF)"
		}
		bpfSt[1] = telemetry.BPFStatus{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: syscallOK, Detail: syscallDetail}
		slog.Info("tracing connect + UDP sendto + HTTP/80 sniff + optional TLS write (raw_tp/sys_enter)")
		if cfg.Mode == config.ModeEnforce {
			if err := writeAgentStatus(cfg.AgentStatusPath, true); err != nil {
				return fmt.Errorf("agent ready status: %w", err)
			}
		}
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
				stats.setTLSWritevMultiIovecObserved(readTLSWritevMultiIovecObservedCount(syscallObjs))
				stats.setUnobservedEgressSyscalls(readUnobservedEgressSyscallsCount(syscallObjs))
				stats.setIoUringSetupObserved(readIoUringSetupObservedCount(syscallObjs))
			}
		}()
		// Ring readers are closed exactly once via closeSyscallReaders (runCtx shutdown goroutine + defer).
	}

	// Detect mode: ready after syscall trace initialized. Enforce mode wrote ready after syscall attach succeeds.
	if cfg.Mode != config.ModeEnforce {
		if err := writeAgentStatus(cfg.AgentStatusPath, true); err != nil {
			return fmt.Errorf("agent ready status: %w", err)
		}
	}

	var dnsRd *ringbuf.Reader
	var dnsRdOnce sync.Once
	closeDNSRd := func() {
		dnsRdOnce.Do(func() {
			if dnsRd != nil {
				_ = dnsRd.Close()
			}
		})
	}
	defer closeDNSRd()

	var dnsObjs *tracedns.TracednsObjects
	var dnsLnkEnter, dnsLnkExit link.Link
	if rd, objs, le, lx, err := startDNSTrace(); err != nil {
		slog.Info("dns reply sniffing disabled", "err", err)
		bpfSt[2] = telemetry.BPFStatus{Name: "dns recvfrom sniff", OK: false, Detail: bpfDetail(err)}
	} else {
		dnsRd, dnsObjs, dnsLnkEnter, dnsLnkExit = rd, objs, le, lx
		// Register every live dns_cache map so userspace DNS observations
		// flow into all in-kernel programs that consult dns_cache for
		// late-binding IP -> FQDN attribution. Enforce/LSM collections each
		// instantiate their own dns_cache via dns_cache.h, so registering
		// only the DNS-tracer instance previously left enforce decisions
		// blind to runtime DNS learning (M-14, paired with H-03's deletes).
		dnsCacheMaps := []*ebpf.Map{dnsObjs.DnsCache}
		if hasEnforce && enforceObjs.DnsCache != nil {
			dnsCacheMaps = append(dnsCacheMaps, enforceObjs.DnsCache)
		}
		if hasLSM && lsmObjs != nil && lsmObjs.DnsCache != nil {
			dnsCacheMaps = append(dnsCacheMaps, lsmObjs.DnsCache)
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

	var bpfAuditRd *ringbuf.Reader
	var bpfAuditRdOnce sync.Once
	closeBPFAuditRd := func() {
		bpfAuditRdOnce.Do(func() {
			if bpfAuditRd != nil {
				_ = bpfAuditRd.Close()
			}
		})
	}
	defer closeBPFAuditRd()
	var bpfAuditObjs *tracebpfaudit.TracebpfauditObjects
	var bpfAuditLnk link.Link

	var forkRd *ringbuf.Reader
	var forkRdOnce sync.Once
	closeForkRd := func() {
		forkRdOnce.Do(func() {
			if forkRd != nil {
				_ = forkRd.Close()
			}
		})
	}
	defer closeForkRd()
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
					forkRd = rd
					bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: true})
					slog.Info("tracing sched_process_fork (process tree)")
					defer func() {
						if forkObjs != nil {
							stats.setForkRingbufReserveFailures(readForkRingbufReserveFailureCount(forkObjs))
						}
						closeForkRd()
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

	var fsRd *ringbuf.Reader
	var fsRdOnce sync.Once
	closeFsRd := func() {
		fsRdOnce.Do(func() {
			if fsRd != nil {
				_ = fsRd.Close()
			}
		})
	}
	defer closeFsRd()

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
					fsRd = rd
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
						closeFsRd()
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
		bpfAuditRd, bpfAuditObjs, bpfAuditLnk = bR, bO, bL
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
		_ = execRd.Close()
		closeSyscallReaders()
		closeDenyRd()
		closeDNSRd()
		closeBPFAuditRd()
		closeForkRd()
		closeFsRd()
	}()

	slog.Info("coldstep event readers started", "mode", string(cfg.Mode))

	// Each reader goroutine sends one error on exit; buffer must fit all sends before wg.Wait returns.
	readerCount := 1
	if forkRd != nil && forkBuf != nil && forkState != nil {
		readerCount++
	}
	if fsRd != nil && fsRowBuf != nil && fsSt != nil {
		readerCount++
	}
	if connRd != nil {
		readerCount++
	}
	if udpRd != nil {
		readerCount++
	}
	if httpRd != nil {
		readerCount++
	}
	if tlsRd != nil {
		readerCount++
	}
	if denyRd != nil {
		readerCount++
	}
	if dnsRd != nil {
		readerCount++
	}
	if bpfAuditRd != nil {
		readerCount++
	}
	if hasEnforce {
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
		errCh <- readExecRing(runCtx, cfg, execRd, stats, rows, &seq, &jsonlMu, signer)
	}()

	if forkRd != nil && forkBuf != nil && forkState != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readForkRing(runCtx, cfg, forkRd, stats, forkBuf, forkState, &seq, &jsonlMu, signer)
		}()
	}

	if fsRd != nil && fsRowBuf != nil && fsSt != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readFSRing(runCtx, cfg, fsRd, stats, fsRowBuf, fsSt, &seq, &jsonlMu, signer)
		}()
	}

	if connRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readConnectRing(runCtx, cfg, connRd, dnsCache, pol, stats, rows, &seq, &jsonlMu, sectionState, canary, signer)
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

	if udpRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readUDPRing(runCtx, cfg, udpRd, dnsCache, pol, stats, rows, &seq, &jsonlMu, sectionState, signer)
		}()
	}
	if httpRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readHTTPRing(runCtx, cfg, httpRd, pol, stats, rows, &seq, &jsonlMu, sectionState, signer)
		}()
	}
	if tlsRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readTLSRing(runCtx, cfg, tlsRd, pol, stats, rows, &seq, &jsonlMu, sectionState, signer)
		}()
	}
	if denyRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readDenyRing(runCtx, cfg, denyRd, &seq, &jsonlMu, enforceState, signer)
		}()
	}
	if dnsRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readDNSRing(runCtx, dnsRd, dnsCache, stats)
		}()
	}
	if bpfAuditRd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- readBPFAuditRing(runCtx, cfg, bpfAuditRd, stats, &seq, &jsonlMu, signer)
		}()
	}

	if hasEnforce {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- watchMapIntegrity(runCtx, cfg, enforceObjs.EnforceCfg, enforceObjs.AllowedIpv4, enforceObjs.IgnoredIpv4Lpm, enforceCompiled, pol, stats, enforceState, &seq, &jsonlMu, signer)
		}()
	}
	if hasLSM {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- watchMapIntegrity(runCtx, cfg, lsmObjs.LsmEnforceCfg, lsmObjs.LsmAllowedIpv4, lsmObjs.LsmIgnoredIpv4Lpm, enforceCompiled, pol, stats, enforceState, &seq, &jsonlMu, signer)
		}()
	}

	wg.Wait()
	close(errCh)

	var retErr error
	for err := range errCh {
		retErr = preferRunError(retErr, err)
	}
	closeExecRdOnEarlyExit = false
	return retErr
}

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
