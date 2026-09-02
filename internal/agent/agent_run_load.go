//go:build linux

package agent

// This file decomposes the BPF load/attach phases that agent.Run drives. Each
// method transcribes one phase of the original monolithic Run body verbatim;
// the only structural change is that Run-level cleanup is registered on the
// shared runCleanup LIFO stack (s.cleanup.push) instead of a local `defer`, so
// the resource is released at Run return in the exact same order even though
// the load logic now lives in a helper. Within a subsystem the push order
// mirrors the original defer registration order, preserving the
// security-critical close ordering (links before objects; counter snapshots
// before objects close).

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/coldstep-io/coldstep/internal/bpf/defend"
	"github.com/coldstep-io/coldstep/internal/bpf/traceexec"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefork"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefs"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// loadDefend loads + attaches the defend collection (cgroup hooks always, LSM
// hooks where the kernel supports them). No-op outside defend mode. Sets
// s.hasDefend / s.hasLSM / s.defendObjs and the defend ring readers.
func (s *runState) loadDefend(compileCtx context.Context) error {
	if !s.mode.Defend {
		return nil
	}
	haveLSM := false
	if err := features.HaveProgramType(ebpf.LSM); err == nil {
		haveLSM = true
	}

	// H15: lsm/io_uring_cmd needs `security_uring_cmd` in kernel BTF
	// (Linux 5.19+). Probe before loading so older kernels keep the
	// other LSM hooks instead of failing prog_load for the whole spec.
	haveIOUringLSM := haveLSM && defend.HaveIOUringLSM()

	// Phase 2.3: cgroup + LSM share one bpf2go object. The loader strips
	// LSM programs (and their dedicated maps) from the spec when the
	// kernel lacks CONFIG_BPF_LSM so prog_load doesn't fail.
	loadResult, err := defend.LoadDefendObjectsForKernel(&s.defendObjs, haveLSM, haveIOUringLSM, s.btfCache)
	if err != nil {
		return fmt.Errorf("load defend bpf objects: %w", err)
	}
	if loadResult.LSMFellBack {
		haveLSM = false
		detail := "lsm prog_load failed; reloaded cgroup-only defend collection"
		if loadResult.LSMFallbackErr != nil {
			detail = fmt.Sprintf("%s: %v", detail, loadResult.LSMFallbackErr)
		}
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{
			Name:   "lsm_load_failed_fallback_cgroup",
			OK:     false,
			Detail: detail,
		})
		slog.Warn("defend: lsm prog_load failed; continuing with cgroup-only enforcement",
			"err", loadResult.LSMFallbackErr)
	}
	s.hasDefend = true
	s.cleanup.push(func() {
		s.defendState.setDenyReserveFailures(readUint32PerCPUArraySum(s.defendObjs.DenyReserveFailures, "deny_reserve_failures"))
		s.stats.setEgressBackstopReserveFailures(readUint32PerCPUArraySum(s.defendObjs.SkbBackstopReserveFailures, "skb_backstop_reserve_failures"))
		s.stats.setBpfSelfDefenseReserveFailures(readUint32PerCPUArraySum(s.defendObjs.BpfSelfDefenseReserveFailures, "bpf_self_defense_reserve_failures"))
		if s.hasLSM {
			s.defendState.setDenyReserveFailures(readUint32PerCPUArraySum(s.defendObjs.LsmDenyReserveFailures, "lsm_deny_reserve_failures"))
		}
		s.stats.setIPv6ConnectObserved(readIPv6ConnectObservedCount(&s.defendObjs))
		s.stats.setIPv6SendmsgObserved(readIPv6SendmsgObservedCount(&s.defendObjs))
		s.stats.setSendpageObserved(readSendpageObservedCount(&s.defendObjs))
		_ = s.defendObjs.Close()
	})

	lsmAttachErr, fatal := s.loadDefendLSM(haveLSM, haveIOUringLSM)
	if fatal != nil {
		return fatal
	}

	backend := chooseDefendBackend(
		defendBackendConfig{
			modeDefend: s.mode.Defend,
			haveLSM:    s.hasLSM,
		},
		lsmAttachErr,
	)
	if lsmAttachErr != nil {
		slog.Warn("lsm defend attach failed; falling back to cgroup", "err", lsmAttachErr)
	}

	return s.loadDefendCgroup(compileCtx, backend.backend)
}

// loadDefendLSM attaches the BPF LSM defend hooks (socket_connect/sendmsg,
// optional sendpage, bpf self-defense, optional io_uring_cmd). Returns the
// non-fatal lsmAttachErr (triggers cgroup-only fallback) separately from a
// fatal error (aborts the agent: map load / ringbuf reader failures).
func (s *runState) loadDefendLSM(haveLSM, haveIOUringLSM bool) (lsmAttachErr error, fatal error) {
	var ioUringAttachErr error
	ioUringAttempted := false

	if haveLSM {
		if _, _, loadErr := loadLSMDefendMaps(&s.defendObjs, s.defendCompiled, s.pol); loadErr != nil {
			return nil, loadErr
		}

		rd, err := ringbuf.NewReader(s.defendObjs.LsmDenyEvents)
		if err != nil {
			return nil, fmt.Errorf("ringbuf reader lsm deny: %w", err)
		}

		lnk1, err := link.AttachLSM(link.LSMOptions{Program: s.defendObjs.LsmSocketConnect})
		if err != nil {
			lsmAttachErr = fmt.Errorf("attach lsm_socket_connect: %w", err)
			_ = rd.Close()
		} else {
			lnk2, err := link.AttachLSM(link.LSMOptions{Program: s.defendObjs.LsmSocketSendmsg})
			if err != nil {
				lsmAttachErr = fmt.Errorf("attach lsm_socket_sendmsg: %w", err)
				_ = lnk1.Close()
				_ = rd.Close()
			} else {
				s.hasLSM = true
				// Keep the LSM ringbuf as a secondary reader. The primary denyRd
				// always reads from the cgroup ringbuf (attached below) because on
				// some kernels (e.g. Ubuntu 24.04 default) LSM hooks attach but
				// never fire — `lsm_deny_events` then stays empty even though
				// cgroup is defending.
				s.lsmDenyRd.R = rd
				s.cleanup.push(func() { _ = lnk1.Close() })
				s.cleanup.push(func() { _ = lnk2.Close() })

				// Sendfile/splice gap (kernel 5.15): attach lsm/socket_sendpage
				// so the sock_sendpage() path is gated against the same IPv4
				// allowlist. Optional — tolerate missing program and attach
				// failures (very old kernels that lack the sendpage LSM hook).
				if s.defendObjs.LsmSocketSendpage != nil {
					sendpageLnk, attachErr := link.AttachLSM(link.LSMOptions{Program: s.defendObjs.LsmSocketSendpage})
					if attachErr != nil {
						slog.Info("lsm/socket_sendpage attach failed; sendfile/splice gap remains on this kernel", "err", attachErr)
					} else {
						s.cleanup.push(func() { _ = sendpageLnk.Close() })
					}
				} else {
					slog.Info("lsm/socket_sendpage program not present in defend stubs; rebuild defend objects on Linux to close the sendfile/splice gap")
				}

				// Sub-project B: lsm/bpf self-defense. Attach the hook, arm
				// it (record coldstep's own object ids + enabled=1), and
				// open its ringbuf. Best-effort defense-in-depth — never
				// fatal. Inert until armed; armBpfSelfDefense flips enabled
				// only after the protected-id sets are populated.
				if s.defendObjs.ColdstepBpfSelfDefense != nil {
					if sdLnk, sdErr := link.AttachLSM(link.LSMOptions{Program: s.defendObjs.ColdstepBpfSelfDefense}); sdErr != nil {
						slog.Info("lsm/bpf self-defense attach failed; monitor tamper protection inactive", "err", sdErr)
						s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "lsm/bpf (self-defense)", OK: false, Detail: bpfDetail(sdErr)})
					} else {
						s.cleanup.push(func() { _ = sdLnk.Close() })
						progN, mapN := armBpfSelfDefense(&s.defendObjs, uint32(os.Getpid())) // #nosec G115 -- pid is always a small positive int; uint32 round-trip is intentional //nolint:gosec
						if sdRd, rerr := ringbuf.NewReader(s.defendObjs.BpfSelfDefenseEvents); rerr != nil {
							slog.Info("bpf self-defense ringbuf unavailable; continuing", "err", rerr)
						} else {
							s.selfDefenseRd.R = sdRd
						}
						s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{
							Name:   "lsm/bpf (self-defense)",
							OK:     true,
							Detail: fmt.Sprintf("protecting %d prog(s) + %d map(s)", progN, mapN),
						})
					}
				}

				// H15: lsm/io_uring_cmd is best-effort defense-in-depth on
				// IORING_OP_URING_CMD; only emit a BPFStatus row when we
				// actually attempted attach so pre-5.19 kernels are not
				// reported as degraded for a hook they can't host.
				if haveIOUringLSM && s.defendObjs.LsmIoUringCmd != nil {
					ioUringAttempted = true
					if lnk3, ioErr := link.AttachLSM(link.LSMOptions{Program: s.defendObjs.LsmIoUringCmd}); ioErr != nil {
						slog.Info("lsm/io_uring_cmd attach failed; cgroup+socket LSM still active", "err", ioErr)
						ioUringAttachErr = ioErr
					} else {
						s.cleanup.push(func() { _ = lnk3.Close() })
					}
				}
			}
		}
	}

	if ioUringAttempted {
		row := telemetry.BPFStatus{Name: "lsm/io_uring_cmd", OK: ioUringAttachErr == nil}
		if ioUringAttachErr != nil {
			row.Detail = bpfDetail(ioUringAttachErr)
		}
		s.bpfSt = append(s.bpfSt, row)
	}

	return lsmAttachErr, nil
}

// loadDefendCgroup programs the cgroup defend maps and attaches the always-on
// cgroup hooks (connect4/sendmsg4 + observe-only IPv6 + tc/clsact backstop),
// then blocks until live enforcement is confirmed.
func (s *runState) loadDefendCgroup(compileCtx context.Context, backend string) error {
	// Always program the cgroup defend maps and attach the cgroup hooks,
	// regardless of whether LSM also attached. The cgroup hook is the
	// reliable always-on defense path: LSM hooks may attach but never fire
	// when the kernel's `lsm=` boot chain excludes BPF (Ubuntu 24.04 ships
	// this way).
	allowlistSize, ipv6AllowlistSize, ignoredSize, loadErr := loadDefendMaps(&s.defendObjs, s.defendCompiled, s.pol)
	if loadErr != nil {
		return loadErr
	}
	s.defendState.setModeAndAllowlist(defendModeForBackend(backend), allowlistSize, ignoredSize)
	s.defendState.setIPv6AllowlistSize(ipv6AllowlistSize)

	// SECURITY (dns-cache-trust): seed the defend dns_cache owner-fallback map
	// from the agent's own resolver so dst_is_allowlisted's late-binding path
	// is trusted, never fed by poisonable sniffed traffic.
	if s.defendObjs.DnsCache != nil && len(s.cfg.AllowedDomains) > 0 {
		owners := policy.ResolveOwners(compileCtx, s.cfg.AllowedDomains, nil, 2)
		seeded := seedDefendOwners(s.defendObjs.DnsCache, owners, s.stats.addDNSCacheUpdateFailure)
		slog.Info("defend dns_cache owner map seeded from trusted resolver", "entries", seeded)
	}
	rd, err := ringbuf.NewReader(s.defendObjs.DenyEvents)
	if err != nil {
		return fmt.Errorf("ringbuf reader deny: %w", err)
	}
	s.denyRd.R = rd

	cgPath := s.cfg.CgroupAttachPath
	if cgPath == "" {
		cgPath = "/sys/fs/cgroup"
	}

	defendConnectLnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: s.defendObjs.DefendConnect4,
	})
	if err != nil {
		return fmt.Errorf("attach defend_connect4: %w", err)
	}
	s.cleanup.push(func() { _ = defendConnectLnk.Close() })

	defendSendmsgLnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupUDP4Sendmsg,
		Program: s.defendObjs.DefendSendmsg4,
	})
	if err != nil {
		return fmt.Errorf("attach defend_sendmsg4: %w", err)
	}
	s.cleanup.push(func() { _ = defendSendmsgLnk.Close() })

	s.attachEgressBackstop()
	s.attachDefendIPv6(cgPath)

	// AttachCgroup returns once the program is bound, but on hosted runners the
	// kernel has been observed to not yet enforce for newly-created sockets for
	// ~1-3s afterward — so the first connect after .coldstep-ready.json was
	// written could slip through. Block until a live probe deny is observed.
	if err := probeDefendEnforcement(s.denyRd.R, defaultProbeTimeout); err != nil {
		_ = writeAgentStatus(s.cfg.AgentStatusPath, false)
		return fmt.Errorf("defend mode requires confirmed cgroup BPF enforcement: %w", err)
	}

	// Bug #3: AttachLSM can succeed but the kernel may still never invoke
	// our LSM programs. Cgroup probe just confirmed cgroup is firing; run the
	// same dial-loop-and-drain pattern against the LSM ringbuf, and downgrade
	// the backend label from `defend+lsm` to `defend+cgroup` when no LSM
	// events arrive.
	if s.hasLSM && s.lsmDenyRd.R != nil {
		if probeLSMSilent(s.lsmDenyRd.R, lsmProbeTimeout) {
			s.defendState.downgradeMode(defendModeForBackend(defendBackendCgroup))
			s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{
				Name:   "lsm_attached_but_silent",
				OK:     false,
				Detail: "lsm hooks attached but no deny events observed during post-attach probe; downgraded backend label to cgroup. Common on Ubuntu 24.04 where the kernel `lsm=` boot chain omits bpf — boot with e.g. `lsm=lockdown,yama,bpf,apparmor` to restore LSM dispatch.",
			})
			slog.Warn("defend: lsm hooks attached but silent during post-attach probe; downgrading backend label to cgroup",
				"hint", "kernel `lsm=` boot chain likely missing `bpf` (Ubuntu 24.04 default)")
		}
	}
	return nil
}

// attachEgressBackstop attaches the observe-only tc/clsact egress backstop to
// every non-loopback, up interface (best-effort; never fatal).
func (s *runState) attachEgressBackstop() {
	// Sub-project A: tc/clsact egress backstop (observe-only). Attaches the
	// defend_skb_egress tc program to every non-loopback, up interface via
	// TCX (kernel 6.6+).
	if s.defendObjs.DefendSkbEgress == nil {
		return
	}
	rd, rerr := ringbuf.NewReader(s.defendObjs.SkbBackstopEvents)
	if rerr != nil {
		slog.Info("egress backstop ringbuf unavailable; continuing", "err", rerr)
		return
	}
	attached := 0
	ifaces, ierr := net.Interfaces()
	if ierr != nil {
		slog.Info("egress backstop: net.Interfaces failed; continuing", "err", ierr)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		tcxLnk, attachErr := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   s.defendObjs.DefendSkbEgress,
			Attach:    ebpf.AttachTCXEgress,
		})
		if attachErr != nil {
			slog.Info("egress backstop tcx attach failed; continuing", "iface", iface.Name, "err", attachErr)
			continue
		}
		s.cleanup.push(func() { _ = tcxLnk.Close() })
		attached++
	}
	if attached > 0 {
		s.egressBackstopRd.R = rd
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "tcx/egress (backstop)", OK: true, Detail: fmt.Sprintf("%d interface(s)", attached)})
	} else {
		_ = rd.Close()
		slog.Info("egress backstop: no non-loopback interface attached; backstop inactive")
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "tcx/egress (backstop)", OK: false, Detail: "no non-loopback interface attached"})
	}
}

// attachDefendIPv6 attaches the observe-only cgroup connect6/sendmsg6 hooks
// (best-effort; tolerates missing programs and attach failures).
func (s *runState) attachDefendIPv6(cgPath string) {
	// P0-1 Phase 1: IPv6 observe-only hooks. Tolerate missing programs and
	// attach failures (very old kernels without cgroup/connect6 support).
	if s.defendObjs.DefendCgroupConnect6 != nil {
		ipv6ConnectLnk, attachErr := link.AttachCgroup(link.CgroupOptions{
			Path:    cgPath,
			Attach:  ebpf.AttachCGroupInet6Connect,
			Program: s.defendObjs.DefendCgroupConnect6,
		})
		if attachErr != nil {
			slog.Info("ipv6 connect6 observe-only hook unavailable; continuing without IPv6 visibility", "err", attachErr)
		} else {
			s.cleanup.push(func() { _ = ipv6ConnectLnk.Close() })
		}
	} else {
		slog.Info("ipv6 connect6 observe-only program not present in defend stubs; rebuild defend objects on Linux to enable IPv6 visibility")
	}
	if s.defendObjs.DefendCgroupSendmsg6 != nil {
		ipv6SendmsgLnk, attachErr := link.AttachCgroup(link.CgroupOptions{
			Path:    cgPath,
			Attach:  ebpf.AttachCGroupUDP6Sendmsg,
			Program: s.defendObjs.DefendCgroupSendmsg6,
		})
		if attachErr != nil {
			slog.Info("ipv6 sendmsg6 observe-only hook unavailable; continuing without IPv6 visibility", "err", attachErr)
		} else {
			s.cleanup.push(func() { _ = ipv6SendmsgLnk.Close() })
		}
	} else {
		slog.Info("ipv6 sendmsg6 observe-only program not present in defend stubs; rebuild defend objects on Linux to enable IPv6 visibility")
	}
}

// loadExec loads the sched_process_exec tracepoint (mandatory) and its ring
// reader. Returns a fatal error if the exec probe cannot attach.
func (s *runState) loadExec() error {
	if err := traceexec.LoadTraceexecObjects(&s.execObjs, &ebpf.CollectionOptions{Cache: s.btfCache}); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	s.cleanup.push(func() { _ = s.execObjs.Close() })
	s.cleanup.push(func() {
		s.stats.setExecRingbufReserveFailures(readUint32PerCPUArraySum(s.execObjs.ExecRingbufReserveFailures, "exec_ringbuf_reserve_failures"))
	})

	execLnk, err := link.Tracepoint("sched", "sched_process_exec", s.execObjs.HandleSchedProcessExec, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sched_process_exec: %w", err)
	}
	s.cleanup.push(func() { _ = execLnk.Close() })
	s.bpfSt[0] = telemetry.BPFStatus{Name: "sched_process_exec", OK: true}

	rd, err := ringbuf.NewReader(s.execObjs.Events)
	if err != nil {
		return fmt.Errorf("ringbuf reader exec: %w", err)
	}
	s.execRd.R = rd
	// execRd (like every ring reader) is closed by the runCtx shutdown goroutine
	// on the happy path and by the early closeAllReaders cleanup push on any
	// return before that goroutine is registered. ringReader.Close is
	// once-guarded, so the double close is safe.
	return nil
}

// armSyscall attaches the raw_tp/sys_enter egress probe (connect/sendto/HTTP
// sniff/TLS) plus its companion kprobes and the io_uring submit_sqe probe.
// In defend mode a syscall-trace attach failure is fatal.
func (s *runState) armSyscall() error {
	cR, uR, hR, tR, objs, lnk, tlsCfgFailed, err := startSyscallTrace(s.tlsSNIGate, s.btfCache)
	if err != nil {
		slog.Info("syscall egress tracing disabled", "err", err)
		s.bpfSt[1] = telemetry.BPFStatus{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: false, Detail: bpfDetail(err)}
		if s.mode.Defend {
			// Keep the status file for the composite post step; record operational
			// failure explicitly instead of deleting the path.
			_ = writeAgentStatus(s.cfg.AgentStatusPath, false)
			return fmt.Errorf("defend mode requires syscall trace attach: %w", err)
		}
		return nil
	}

	s.connRd.R, s.udpRd.R, s.httpRd.R, s.tlsRd.R = cR, uR, hR, tR
	s.syscallObjs, s.syscallLnk = objs, lnk
	syscallOK := true
	syscallDetail := ""
	if tlsCfgFailed {
		syscallOK = false
		syscallDetail = "tls_agent_cfg map update failed (TLS SNI sniff disabled in BPF)"
	}
	s.bpfSt[1] = telemetry.BPFStatus{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: syscallOK, Detail: syscallDetail}
	slog.Info("tracing connect + UDP sendto + HTTP/80 sniff + optional TLS write (raw_tp/sys_enter)")

	// P3-2: paired kprobe/kretprobe on tcp_v4_connect. Failure is non-fatal —
	// the entry-side connect_event still records the attempt.
	if kpLnk, krLnk, kerr := attachTCPConnectKprobes(s.syscallObjs); kerr != nil {
		slog.Info("tcp_v4_connect kprobe pair attach failed; connect_result events disabled", "err", kerr)
		s.bpfSt[4] = telemetry.BPFStatus{Name: "kprobe tcp_v4_connect (connect_result)", OK: false, Detail: bpfDetail(kerr)}
	} else {
		s.bpfSt[4] = telemetry.BPFStatus{Name: "kprobe tcp_v4_connect (connect_result)", OK: true}
		slog.Info("tcp_v4_connect kprobe/kretprobe attached (connect_result events enabled)")
		s.cleanup.push(func() { _ = kpLnk.Close() })
		s.cleanup.push(func() { _ = krLnk.Close() })
	}

	s.cleanup.push(func() { _ = s.syscallObjs.Close() })
	s.cleanup.push(func() { _ = s.syscallLnk.Close() })
	s.cleanup.push(func() {
		if s.syscallObjs != nil {
			s.stats.setConnect4TupleUpdateFailures(readUint32PerCPUArraySum(s.syscallObjs.Connect4TupleUpdateFailures, "connect4_tuple_update_failures"))
			s.stats.setUDPRingbufReserveFailures(readUint32PerCPUArraySum(s.syscallObjs.UdpRingbufReserveFailures, "udp_ringbuf_reserve_failures"))
			s.stats.setConnectRingbufReserveFailures(readUint32PerCPUArraySum(s.syscallObjs.ConnectRingbufReserveFailures, "connect_ringbuf_reserve_failures"))
			s.stats.setHTTPRingbufReserveFailures(readUint32PerCPUArraySum(s.syscallObjs.HttpRingbufReserveFailures, "http_ringbuf_reserve_failures"))
			s.stats.setTLSRingbufReserveFailures(readUint32PerCPUArraySum(s.syscallObjs.TlsRingbufReserveFailures, "tls_ringbuf_reserve_failures"))
			s.stats.setUDPSendmsgMultiIovecObserved(readUint32PerCPUArraySum(s.syscallObjs.UdpSendmsgMultiIovecObserved, "udp_sendmsg_multi_iovec_observed"))
			s.stats.setSendmmsgMultiMessage(readUint32PerCPUArraySum(s.syscallObjs.SendmmsgMultiMessageObserved, "sendmmsg_multi_message_observed"))
			s.stats.setSendmmsgUnobservedExtra(readUint32PerCPUArraySum(s.syscallObjs.SendmmsgUnobservedExtra, "sendmmsg_unobserved_extra"))
			s.stats.setTLSWritevMultiIovecObserved(readUint32PerCPUArraySum(s.syscallObjs.TlsWritevMultiIovecObserved, "tls_writev_multi_iovec_observed"))
			sendfileN, spliceN, sendmmsgN := readPartialEgressCounts(s.syscallObjs.PartialEgressObserved)
			s.stats.setPartialEgressObserved(sendfileN, spliceN, sendmmsgN)
			s.stats.setIoUringSetupObserved(readUint32PerCPUArraySum(s.syscallObjs.IoUringSetupObserved, "io_uring_setup_observed"))
			s.stats.setTCPStateRingbufReserveFailures(readUint32PerCPUArraySum(s.syscallObjs.TcpStateRingbufReserveFailures, "tcp_state_ringbuf_reserve_failures"))
			s.stats.setIoUringRingbufReserveFailures(readUint32PerCPUArraySum(s.syscallObjs.IoUringRingbufReserveFailures, "io_uring_ringbuf_reserve_failures"))
			s.stats.setIoUringTLSRingbufReserveFailures(readUint32PerCPUArraySum(s.syscallObjs.IoUringTlsRingbufReserveFailures, "io_uring_tls_ringbuf_reserve_failures"))
			s.stats.setIoUringTLSHelloObserved(readUint32PerCPUArraySum(s.syscallObjs.IoUringTlsHelloObserved, "io_uring_tls_hello_observed"))
		}
	})

	s.armTCPStateTrace()
	s.armIoUringTrace()
	return nil
}

// armTCPStateTrace attaches the sock/inet_sock_set_state tracepoint for
// kernel-confirmed TCP handshake outcomes (best-effort).
func (s *runState) armTCPStateTrace() {
	lnk, lerr := link.Tracepoint("sock", "inet_sock_set_state", s.syscallObjs.HandleInetSockSetState, nil)
	if lerr != nil {
		slog.Info("inet_sock_set_state tracepoint disabled", "err", lerr)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "tp/sock/inet_sock_set_state", OK: false, Detail: bpfDetail(lerr)})
		return
	}
	s.tcpStateLnk = lnk
	rd, rerr := ringbuf.NewReader(s.syscallObjs.TcpStateEvents)
	if rerr != nil {
		slog.Info("tcp_state_events ringbuf reader failed", "err", rerr)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "tp/sock/inet_sock_set_state", OK: false, Detail: bpfDetail(rerr)})
		_ = s.tcpStateLnk.Close()
		s.tcpStateLnk = nil
		return
	}
	s.tcpStateRd.R = rd
	s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "tp/sock/inet_sock_set_state", OK: true})
	slog.Info("tracing TCP handshake outcomes (tp/sock/inet_sock_set_state)")
	s.cleanup.push(func() {
		if s.tcpStateLnk != nil {
			_ = s.tcpStateLnk.Close()
		}
	})
}

// armIoUringTrace attaches the raw_tp/io_uring_submit_sqe probe, optionally
// enabling the enhanced TLS ClientHello peek under the enhanced detect profile.
func (s *runState) armIoUringTrace() {
	// P6 Phase 1+2: best-effort attach of raw_tp/io_uring_submit_sqe.
	enhancedIoUringPeek := strings.EqualFold(strings.TrimSpace(s.cfg.DetectProfile), "enhanced")
	rd, tlsRd, lnk, peekFailed, ioErr := startIoUringTrace(s.syscallObjs, enhancedIoUringPeek)
	if ioErr != nil {
		slog.Info("io_uring submit_sqe tracing disabled", "err", ioErr)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{
			Name:   "raw_tp/io_uring_submit_sqe",
			OK:     false,
			Detail: bpfDetail(ioErr),
		})
		return
	}
	s.ioUringLnk = lnk
	s.ioUringRd.R = rd
	s.ioUringTLSRd.R = tlsRd
	ioStatus := telemetry.BPFStatus{Name: "raw_tp/io_uring_submit_sqe", OK: true}
	if peekFailed {
		ioStatus.OK = false
		ioStatus.Detail = "io_uring_peek_cfg map update failed (TLS ClientHello peek disabled in BPF)"
	}
	s.bpfSt = append(s.bpfSt, ioStatus)
	if enhancedIoUringPeek && !peekFailed {
		slog.Info("tracing io_uring write-class submissions + enhanced TLS peek (raw_tp/io_uring_submit_sqe)")
	} else {
		slog.Info("tracing io_uring write-class submissions (raw_tp/io_uring_submit_sqe)")
	}
	s.cleanup.push(func() {
		if s.ioUringLnk != nil {
			_ = s.ioUringLnk.Close()
		}
	})
}

// loadDNS attaches the DNS recvfrom reply sniffer (best-effort) and registers
// its enrichment-side dns_cache map with the userspace DNS cache.
func (s *runState) loadDNS() {
	rd, objs, le, lx, err := startDNSTrace(s.btfCache)
	if err != nil {
		slog.Info("dns reply sniffing disabled", "err", err)
		s.bpfSt[2] = telemetry.BPFStatus{Name: "dns recvfrom sniff", OK: false, Detail: bpfDetail(err)}
		return
	}
	s.dnsRd.R = rd
	s.dnsObjs = objs
	// SECURITY (dns-cache-trust): the sniffed DNS cache feeds ONLY the
	// detection-side enrichment map (dnsObjs.DnsCache). The defend ENFORCEMENT
	// map (defendObjs.DnsCache) is deliberately NOT registered here.
	s.dnsCache.SetBPFMaps([]*ebpf.Map{s.dnsObjs.DnsCache})
	s.bpfSt[2] = telemetry.BPFStatus{Name: "dns recvfrom sniff", OK: true}
	slog.Info("tracing DNS replies (recvfrom)")
	s.cleanup.push(func() { _ = s.dnsObjs.Close() })
	s.cleanup.push(func() { _ = lx.Close() })
	s.cleanup.push(func() { _ = le.Close() })
	s.cleanup.push(func() {
		if s.dnsObjs != nil {
			s.stats.setDNSRingbufReserveFailures(readUint32PerCPUArraySum(s.dnsObjs.DnsRingbufReserveFailures, "dns_ringbuf_reserve_failures"))
			s.stats.setTCPDNSResponsesObserved(readUint32PerCPUArraySum(s.dnsObjs.TcpDnsResponsesObserved, "tcp_dns_responses_observed"))
			s.stats.setTCPDNSSkippedShortRead(readUint32PerCPUArraySum(s.dnsObjs.TcpDnsSkippedShortRead, "tcp_dns_skipped_short_read"))
		}
	})
}

// loadFork attaches the sched_process_fork raw tracepoint when the proc_tree
// feature gate is enabled (best-effort).
func (s *runState) loadFork() {
	if !s.procTreeGate {
		return
	}
	objs := new(tracefork.TraceforkObjects)
	if err := tracefork.LoadTraceforkObjects(objs, &ebpf.CollectionOptions{Cache: s.btfCache}); err != nil {
		slog.Info("sched_process_fork tracing disabled", "err", err)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: false, Detail: bpfDetail(err)})
		return
	}
	s.forkObjs = objs
	lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_fork",
		Program: objs.HandleSchedProcessFork,
	})
	if err != nil {
		slog.Info("sched_process_fork attach failed", "err", err)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: false, Detail: bpfDetail(err)})
		_ = objs.Close()
		s.forkObjs = nil
		return
	}
	s.forkLnk = lnk
	rd, err := ringbuf.NewReader(objs.ForkEvents)
	if err != nil {
		slog.Info("sched_process_fork ringbuf reader failed", "err", err)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: false, Detail: bpfDetail(err)})
		_ = lnk.Close()
		_ = objs.Close()
		s.forkObjs = nil
		s.forkLnk = nil
		return
	}
	s.forkRd.R = rd
	s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "sched_process_fork", OK: true})
	slog.Info("tracing sched_process_fork (process tree)")
	s.cleanup.push(func() {
		if s.forkObjs != nil {
			s.stats.setForkRingbufReserveFailures(readUint32PerCPUArraySum(s.forkObjs.ForkRingbufReserveFailures, "fork_ringbuf_reserve_failures"))
		}
		s.forkRd.Close()
		if s.forkLnk != nil {
			_ = s.forkLnk.Close()
		}
		if s.forkObjs != nil {
			_ = s.forkObjs.Close()
		}
	})
}

// loadFS attaches the filesystem sys_enter raw tracepoint when the fs_events
// feature gate is enabled (best-effort).
func (s *runState) loadFS() {
	if !s.fsGate {
		return
	}
	objs := new(tracefs.TracefsObjects)
	if err := tracefs.LoadTracefsObjects(objs, &ebpf.CollectionOptions{Cache: s.btfCache}); err != nil {
		slog.Info("fs tracing disabled", "err", err)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
		return
	}
	var fsCfgErr error
	if err := objs.FsAgentCfg.Update(uint32(0), uint8(1), ebpf.UpdateAny); err != nil {
		fsCfgErr = err
		slog.Warn("fs cfg map update", "err", err)
	}
	s.fsObjs = objs
	lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.HandleFsSysEnter,
	})
	if err != nil {
		slog.Info("fs sys_enter attach failed", "err", err)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
		_ = objs.Close()
		s.fsObjs = nil
		return
	}
	s.fsLnk = lnk
	rd, err := ringbuf.NewReader(objs.FsEvents)
	if err != nil {
		slog.Info("fs ringbuf reader failed", "err", err)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
		_ = lnk.Close()
		_ = objs.Close()
		s.fsObjs = nil
		s.fsLnk = nil
		return
	}
	s.fsRd.R = rd
	fsOK := true
	fsDetail := ""
	if fsCfgErr != nil {
		fsOK = false
		fsDetail = bpfDetail(fsCfgErr)
		if fsDetail == "" {
			fsDetail = "fs_agent_cfg map update failed (fs events disabled in BPF)"
		}
	}
	s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: fsOK, Detail: fsDetail})
	slog.Info("tracing fs events (openat+create, unlink, rename, chmod)")
	s.cleanup.push(func() {
		if s.fsObjs != nil {
			s.stats.setFSRingbufReserveFailures(readUint32PerCPUArraySum(s.fsObjs.FsRingbufReserveFailures, "fs_ringbuf_reserve_failures"))
		}
		s.fsRd.Close()
		if s.fsLnk != nil {
			_ = s.fsLnk.Close()
		}
		if s.fsObjs != nil {
			_ = s.fsObjs.Close()
		}
	})
}

// loadKTLS attaches the setsockopt(SOL_TLS) KTLS-offload detection probe
// (best-effort).
func (s *runState) loadKTLS() {
	kR, kO, kL, err := startKTLSTrace(s.btfCache)
	if err != nil {
		slog.Info("ktls offload trace disabled", "err", err)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (ktls)", OK: false, Detail: bpfDetail(err)})
		return
	}
	s.ktlsRd.R = kR
	s.ktlsObjs, s.ktlsLnk = kO, kL
	s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (ktls)", OK: true})
	slog.Info("tracing setsockopt(SOL_TLS) for KTLS offload detection")
	s.cleanup.push(func() { _ = s.ktlsObjs.Close() })
	s.cleanup.push(func() { _ = s.ktlsLnk.Close() })
	s.cleanup.push(func() {
		if s.ktlsObjs != nil {
			s.stats.setKTLSRingbufReserveFailures(readUint32PerCPUArraySum(s.ktlsObjs.KtlsRingbufReserveFailures, "ktls_ringbuf_reserve_failures"))
		}
	})
}

// loadIPv6Obs attaches the detect-mode IPv6 observe-only cgroup hooks. No-op in
// defend mode (defend attaches its own cgroup6 programs).
func (s *runState) loadIPv6Obs() {
	// H7: detect-mode IPv6 observe-only hooks. Loaded only in detect mode —
	// defend's own cgroup/connect6+sendmsg6 programs already attach there
	// (cgroup hook attach is single-program by default).
	if s.mode.Defend {
		return
	}
	cgPath := s.cfg.CgroupAttachPath
	if cgPath == "" {
		cgPath = "/sys/fs/cgroup"
	}
	r, o, c, sm, err := startIPv6ObsTrace(cgPath, s.btfCache)
	if err != nil {
		slog.Info("ipv6 observe-only trace disabled", "err", err)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "cgroup/connect6+sendmsg6 (ipv6_obs)", OK: false, Detail: bpfDetail(err)})
		return
	}
	s.ipv6ObsRd.R = r
	s.ipv6ObsObjs = o
	s.ipv6ObsConnectLnk = c
	s.ipv6ObsSendmsgLnk = sm
	s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "cgroup/connect6+sendmsg6 (ipv6_obs)", OK: true})
	slog.Info("tracing IPv6 egress (observe-only)")
	s.cleanup.push(func() {
		if s.ipv6ObsObjs != nil {
			s.stats.setIPv6RingbufReserveFailures(readUint32PerCPUArraySum(s.ipv6ObsObjs.Ipv6ObsRingbufReserveFailures, "ipv6_obs_ringbuf_reserve_failures"))
		}
		s.ipv6ObsRd.Close()
		if s.ipv6ObsSendmsgLnk != nil {
			_ = s.ipv6ObsSendmsgLnk.Close()
		}
		if s.ipv6ObsConnectLnk != nil {
			_ = s.ipv6ObsConnectLnk.Close()
		}
		if s.ipv6ObsObjs != nil {
			_ = s.ipv6ObsObjs.Close()
		}
	})
}

// loadBPFAudit attaches the bpf() syscall audit tracepoint. Attached last so
// coldstep's own object-load bpf(2) calls don't flood the small audit ringbuf
// before its reader starts (best-effort).
func (s *runState) loadBPFAudit() {
	bR, bO, bL, err := startBPFAuditTrace(s.btfCache)
	if err != nil {
		slog.Info("bpf audit trace disabled", "err", err)
		s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (bpf audit)", OK: false, Detail: bpfDetail(err)})
		return
	}
	s.bpfAuditRd.R = bR
	s.bpfAuditObjs, s.bpfAuditLnk = bO, bL
	s.bpfSt = append(s.bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (bpf audit)", OK: true})
	slog.Info("tracing bpf() syscall audit (raw_tp/sys_enter)")
	s.cleanup.push(func() { _ = s.bpfAuditObjs.Close() })
	s.cleanup.push(func() { _ = s.bpfAuditLnk.Close() })
	s.cleanup.push(func() {
		if s.bpfAuditObjs != nil {
			s.stats.setBPFAuditRingbufReserveFailures(readUint32PerCPUArraySum(s.bpfAuditObjs.BpfAuditReserveFailures, "bpf_audit_ringbuf_reserve_failures"))
		}
	})
}
