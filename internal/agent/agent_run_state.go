//go:build linux

package agent

// runState carries the shared mutable state that agent.Run threads through its
// load / attach / spawn phases. Run constructs one *runState and drives the
// phase methods in agent_run_load.go and the spawn helpers below. The type is
// pointer-only (it embeds sync primitives and once-guarded ring readers) and
// must never be copied.

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/coldstep-io/coldstep/internal/bpf/defend"
	"github.com/coldstep-io/coldstep/internal/bpf/tracebpfaudit"
	"github.com/coldstep-io/coldstep/internal/bpf/traceconnect"
	"github.com/coldstep-io/coldstep/internal/bpf/tracedns"
	"github.com/coldstep-io/coldstep/internal/bpf/traceexec"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefork"
	"github.com/coldstep-io/coldstep/internal/bpf/tracefs"
	"github.com/coldstep-io/coldstep/internal/bpf/traceipv6"
	"github.com/coldstep-io/coldstep/internal/bpf/tracektls"
	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// runCleanup is a LIFO cleanup stack. Phase helpers push best-effort close /
// snapshot funcs as they succeed; Run defers a single unwind() so resources are
// released at Run return in reverse registration order — exactly mirroring the
// `defer X.Close()` LIFO the monolithic Run body used, including the
// security-critical "links before objects, counter snapshots before object
// close" ordering within each subsystem.
type runCleanup struct {
	fns []func()
}

func (c *runCleanup) push(fn func()) { c.fns = append(c.fns, fn) }

func (c *runCleanup) unwind() {
	for i := len(c.fns) - 1; i >= 0; i-- {
		c.fns[i]()
	}
}

// runState holds everything the phase helpers read or mutate. Pointer receiver
// only; do not copy.
type runState struct {
	cfg config.Config
	pol *policy.Policy

	stats       *runStats
	defendState *defendState
	canary      *canaryState
	ktlsTr      *ktlsTracker
	dnsCache    *DNSCache
	signer      *telemetry.Signer

	bpfSt   []telemetry.BPFStatus
	cleanup runCleanup

	kernel         string
	runnerEnv      string
	compatWarnings []telemetry.CompatWarning
	defendCompiled policy.CompileResult

	procTreeGate bool
	tlsSNIGate   bool
	fsGate       bool

	// ring readers (once-guarded; closed by the shutdown goroutine and the
	// cleanup stack).
	execRd, connRd, udpRd, httpRd, tlsRd, tcpStateRd   ringReader
	ioUringRd, ioUringTLSRd                            ringReader
	denyRd, egressBackstopRd, lsmDenyRd, selfDefenseRd ringReader
	dnsRd, bpfAuditRd, forkRd, fsRd, ktlsRd, ipv6ObsRd ringReader

	// BPF objects + links retained past their load phase (needed by the
	// reader/monitor goroutines and the shutdown counter snapshots).
	execObjs                             traceexec.TraceexecObjects
	syscallObjs                          *traceconnect.TraceconnectObjects
	syscallLnk                           link.Link
	defendObjs                           defend.DefendObjects
	dnsObjs                              *tracedns.TracednsObjects
	forkObjs                             *tracefork.TraceforkObjects
	forkLnk                              link.Link
	fsObjs                               *tracefs.TracefsObjects
	fsLnk                                link.Link
	ktlsObjs                             *tracektls.TracektlsObjects
	ktlsLnk                              link.Link
	ipv6ObsObjs                          *traceipv6.Traceipv6Objects
	ipv6ObsConnectLnk, ipv6ObsSendmsgLnk link.Link
	bpfAuditObjs                         *tracebpfaudit.TracebpfauditObjects
	bpfAuditLnk                          link.Link
	tcpStateLnk                          link.Link
	ioUringLnk                           link.Link

	hasDefend bool
	hasLSM    bool

	seq     telemetry.SeqGen
	jsonlMu sync.Mutex
}

// finalizeAllowlist performs the defend-mode resolver auto-allow, records the
// compiled allowlist snapshot for the digest, and warns on unresolved domains.
func (s *runState) finalizeAllowlist(compileCtx context.Context) {
	if s.cfg.Mode == config.ModeDefend && !s.cfg.NoResolverAutoAllow {
		resolverV4, resolverV6 := autoAllowSystemResolvers(&s.defendCompiled, policy.DefaultResolvConfPaths()...)
		for _, ip := range resolverV4 {
			slog.Info("defend: system DNS resolver auto-allowed", "resolver", ip.String(), "family", "ipv4")
		}
		for _, ip := range resolverV6 {
			slog.Info("defend: system DNS resolver auto-allowed", "resolver", ip.String(), "family", "ipv6")
		}
		if len(resolverV4)+len(resolverV6) == 0 {
			slog.Warn("defend: no system DNS resolvers discovered — workload DNS may fail (EAI_AGAIN) unless resolver IPs are allowlisted explicitly")
		}
	}
	allowlistCompileTime := s.defendCompiled.CompileTimestamp
	if allowlistCompileTime.IsZero() {
		allowlistCompileTime = time.Now()
	}
	s.stats.setAllowlistCompileSnapshot(
		allowlistCompileTime,
		s.defendCompiled.AllowedIPv4.Len(),
		s.defendCompiled.Domains,
		s.defendCompiled.UnresolvedDomains,
		s.defendCompiled.WildcardRiskDomains,
	)
	for _, d := range s.defendCompiled.UnresolvedDomains {
		slog.Warn("allowlist domain did not resolve", "domain", d)
	}
	if s.cfg.Mode == config.ModeDefend && len(s.defendCompiled.UnresolvedDomains) > 0 {
		slog.Warn("allowlist domains unresolved — legitimate traffic to these domains may be blocked",
			"count", len(s.defendCompiled.UnresolvedDomains))
	}
}

// writeStartupMeta appends the startup MetaEvent (capabilities, allowlist
// counts, coverage) to the JSONL stream.
func (s *runState) writeStartupMeta() {
	if s.cfg.EventsLogPath == "" {
		return
	}
	meta, err := telemetry.BuildMeta(agentVersionString(), s.bpfSt, s.cfg.DetectProfile, string(s.cfg.Mode))
	if err != nil {
		slog.Warn("build meta", "err", err)
		return
	}
	if capabilityEnabled(s.procTreeGate, s.bpfSt, "sched_process_fork") {
		if meta.Capabilities == nil {
			meta.Capabilities = make(map[string]bool)
		}
		meta.Capabilities["proc_tree"] = true
	}
	if capabilityEnabled(s.tlsSNIGate, s.bpfSt, "raw_tp/sys_enter (connect, sendto, http sniff, tls)") {
		if meta.Capabilities == nil {
			meta.Capabilities = make(map[string]bool)
		}
		meta.Capabilities["tls_sni"] = true
	}
	if capabilityEnabled(s.fsGate, s.bpfSt, "raw_tp/sys_enter (fs)") {
		if meta.Capabilities == nil {
			meta.Capabilities = make(map[string]bool)
		}
		meta.Capabilities["fs_events"] = true
	}
	meta.AllowlistIPCount = s.defendCompiled.AllowedIPv4.Len()
	meta.AllowlistEntryCount = s.defendState.snapshot().allowlistSize
	if len(s.defendCompiled.WildcardRiskDomains) > 0 {
		meta.WildcardRiskDomains = append([]string(nil), s.defendCompiled.WildcardRiskDomains...)
	}
	meta.UnresolvedDomains = s.defendCompiled.UnresolvedDomains
	meta.RunnerHasIPv6 = s.cfg.RunnerHasIPv6
	if s.runnerEnv != RunnerEnvStandard {
		meta.RunnerEnv = s.runnerEnv
	}
	// H14 v0.4.0 — IPv6 cgroup6 hooks enforce only when defend mode is active.
	ipv6Enforced := s.cfg.Mode == config.ModeDefend && s.hasDefend
	meta.Coverage = buildCoverageReport(s.bpfSt, s.tlsSNIGate, s.ioUringRd.R != nil, ipv6Enforced, 0)
	if err := telemetry.AppendJSONL(s.cfg.EventsLogPath, meta, s.signer); err != nil {
		slog.Warn("meta jsonl", "err", err)
	}
}

// writeShutdownTelemetry writes the telemetry summary and the shutdown
// MetaEvent. Registered as the first cleanup push so it unwinds last, after all
// reader goroutines have exited and every counter snapshot has been taken.
func (s *runState) writeShutdownTelemetry() {
	sum := s.stats.snapshotSummary(s.kernel, s.bpfSt)
	sum.CompatWarnings = s.compatWarnings
	if err := telemetry.WriteSummary(s.cfg.TelemetrySummaryPath, sum, s.signer); err != nil {
		slog.Warn("telemetry summary", "err", err)
	}
	// H2: emit a shutdown MetaEvent carrying per-channel ringbuf reserve-failure
	// counts under `dropped_events`, plus the JSONL file hash (H11) and the
	// QUIC coverage total (H19). Map is nil (and omitted) when every counter is
	// zero.
	if s.cfg.EventsLogPath == "" {
		return
	}
	shutdownMeta, err := telemetry.BuildMeta(agentVersionString(), s.bpfSt, s.cfg.DetectProfile, string(s.cfg.Mode))
	if err != nil {
		slog.Warn("build shutdown meta", "err", err)
		return
	}
	shutdownMeta.DroppedEvents = buildDroppedEventsMap(s.stats, s.defendState)
	if sum, herr := sha256File(s.cfg.EventsLogPath); herr != nil {
		slog.Warn("events file sha256", "err", herr)
	} else {
		shutdownMeta.EventsFileSHA256 = sum
	}
	ipv6EnforcedShutdown := s.cfg.Mode == config.ModeDefend && s.hasDefend
	shutdownMeta.Coverage = buildCoverageReport(s.bpfSt, s.tlsSNIGate, s.ioUringRd.R != nil, ipv6EnforcedShutdown, s.stats.quicObservedTotal())
	if err := telemetry.AppendJSONL(s.cfg.EventsLogPath, shutdownMeta, s.signer); err != nil {
		slog.Warn("shutdown meta jsonl", "err", err)
	}
}

// closeAllReaders closes every ring reader. Invoked from the runCtx shutdown
// goroutine; ringReader.Close is once-guarded so the cleanup stack closing them
// again at Run return is safe.
func (s *runState) closeAllReaders() {
	s.execRd.Close()
	s.connRd.Close()
	s.udpRd.Close()
	s.httpRd.Close()
	s.tlsRd.Close()
	s.tcpStateRd.Close()
	s.ioUringRd.Close()
	s.ioUringTLSRd.Close()
	s.denyRd.Close()
	s.lsmDenyRd.Close()
	s.egressBackstopRd.Close()
	s.selfDefenseRd.Close()
	s.dnsRd.Close()
	s.bpfAuditRd.Close()
	s.forkRd.Close()
	s.fsRd.Close()
	s.ktlsRd.Close()
	s.ipv6ObsRd.Close()
}

// countReaders returns the number of reader/monitor goroutines that will be
// launched, so the error channel buffer fits every send before wg.Wait drains.
func (s *runState) countReaders() int {
	readerCount := 1 // exec reader is always launched
	for _, active := range []bool{
		s.forkRd.R != nil,
		s.fsRd.R != nil,
		s.connRd.R != nil,
		s.udpRd.R != nil,
		s.httpRd.R != nil,
		s.tlsRd.R != nil,
		s.tcpStateRd.R != nil,
		s.ioUringRd.R != nil,
		s.ioUringTLSRd.R != nil,
		s.denyRd.R != nil,
		s.egressBackstopRd.R != nil,
		s.lsmDenyRd.R != nil,
		s.selfDefenseRd.R != nil,
		s.dnsRd.R != nil,
		s.bpfAuditRd.R != nil,
		s.ktlsRd.R != nil,
		s.ipv6ObsRd.R != nil,
		s.hasDefend,
		s.hasLSM,
	} {
		if active {
			readerCount++
		}
	}
	return readerCount
}

// spawnReaders launches every active event-reader goroutine plus the canary,
// heartbeat, DNS-drift, and map-integrity monitor goroutines. sendReaderErr is
// invoked with each reader's terminal error.
func (s *runState) spawnReaders(runCtx context.Context, wg *sync.WaitGroup, sendReaderErr func(error)) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		sendReaderErr(readExecRing(runCtx, s.cfg, s.execRd.R, s.stats, &s.seq, &s.jsonlMu, s.signer))
	}()

	if s.forkRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readForkRing(runCtx, s.cfg, s.forkRd.R, s.stats, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
	if s.fsRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readFSRing(runCtx, s.cfg, s.fsRd.R, s.stats, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
	if s.connRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readConnectRing(runCtx, s.cfg, s.connRd.R, s.dnsCache, s.pol, s.stats, &s.seq, &s.jsonlMu, s.canary, s.signer))
		}()
	}

	// Telemetry integrity canary + BPF self-protection heartbeat both require
	// the syscall objects.
	if s.syscallObjs != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runCanaryLoop(runCtx)
		}()
	}

	// H16: DNS allowlist trust hardening — background re-resolution goroutine.
	// Only spins up when an allowlist was compiled (defend mode with at least
	// one resolvable domain).
	if len(s.defendCompiled.Domains) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runDNSDriftLoop(runCtx)
		}()
	}

	if s.syscallObjs != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runHeartbeatLoop(runCtx)
		}()
	}

	if s.udpRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readUDPRing(runCtx, s.cfg, s.udpRd.R, s.dnsCache, s.pol, s.stats, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
	if s.httpRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readHTTPRing(runCtx, s.cfg, s.httpRd.R, s.pol, s.stats, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
	if s.tlsRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readTLSRing(runCtx, s.cfg, s.tlsRd.R, s.pol, s.stats, &s.seq, &s.jsonlMu, s.signer, s.ktlsTr))
		}()
	}
	if s.tcpStateRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readTCPStateRing(runCtx, s.cfg, s.tcpStateRd.R, s.stats, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
	if s.ioUringRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readIoUringRing(runCtx, s.cfg, s.ioUringRd.R, s.stats, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
	if s.ioUringTLSRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readIoUringTLSRing(runCtx, s.cfg, s.ioUringTLSRd.R, s.stats, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
	if s.denyRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readDenyRing(runCtx, s.cfg, s.denyRd.R, &s.seq, &s.jsonlMu, s.defendState, s.signer, "cgroup", s.dnsCache))
		}()
	}
	if s.egressBackstopRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readEgressBackstopRing(runCtx, s.cfg, s.egressBackstopRd.R, s.stats, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
	if s.lsmDenyRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readDenyRing(runCtx, s.cfg, s.lsmDenyRd.R, &s.seq, &s.jsonlMu, s.defendState, s.signer, "lsm", s.dnsCache))
		}()
	}
	if s.selfDefenseRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readBpfSelfDefenseRing(runCtx, s.cfg, s.selfDefenseRd.R, s.stats, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
	if s.dnsRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readDNSRing(runCtx, s.dnsRd.R, s.dnsCache, s.stats))
		}()
	}
	if s.bpfAuditRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readBPFAuditRing(runCtx, s.cfg, s.bpfAuditRd.R, s.stats, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
	if s.ktlsRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readKTLSRing(runCtx, s.cfg, s.ktlsRd.R, s.stats, &s.seq, &s.jsonlMu, s.signer, s.ktlsTr))
		}()
	}
	if s.ipv6ObsRd.R != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(readIPv6ObsRing(runCtx, s.cfg, s.ipv6ObsRd.R, s.stats, &s.seq, &s.jsonlMu, s.signer))
		}()
	}

	if s.hasDefend {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(watchMapIntegrity(runCtx, s.cfg, s.defendObjs.DefendCfg, s.defendObjs.AllowedIpv4, s.defendObjs.IgnoredIpv4Lpm, s.defendCompiled, s.pol, s.stats, s.defendState, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
	if s.hasLSM {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendReaderErr(watchMapIntegrity(runCtx, s.cfg, s.defendObjs.LsmDefendCfg, s.defendObjs.LsmAllowedIpv4, s.defendObjs.LsmIgnoredIpv4Lpm, s.defendCompiled, s.pol, s.stats, s.defendState, &s.seq, &s.jsonlMu, s.signer))
		}()
	}
}

// runCanaryLoop writes a monotonic sequence number to the canary_trigger BPF
// map every canaryInterval; the BPF program echoes it back through
// connect_events. A missing echo records a canary failure.
func (s *runState) runCanaryLoop(runCtx context.Context) {
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
			if err := s.syscallObjs.CanaryTrigger.Update(&k, &seqNr, ebpf.UpdateAny); err != nil {
				slog.Warn("canary trigger write failed", "err", err)
				continue
			}
			s.canary.noteSent(seqNr)
			slog.Debug("canary armed", "seq", seqNr)

			if s.canary.checkAndRecordFailure() {
				slog.Error("telemetry integrity canary FAILED — pipeline may be compromised",
					"last_sent", s.canary.snapshot().lastSent,
					"last_received", s.canary.snapshot().lastReceived)
			}
		}
	}
}

// runDNSDriftLoop periodically re-resolves the startup allowlist and emits a
// `dns_drift` JSONL event when the IPv4 set changes. WARNING-ONLY: the live BPF
// enforce policy is intentionally not updated mid-run (mid-job allowlist
// expansion is a TOCTOU risk).
func (s *runState) runDNSDriftLoop(runCtx context.Context) {
	// SECURITY (dns-cache-trust): refresh the defend dns_cache owner fallback
	// from the trusted resolver on every re-resolution tick so a domain whose
	// A-records rotate mid-job stays reachable via the trusted late-binding
	// path — without ever trusting sniffed traffic.
	reseedDefendOwners := func() {
		if s.defendObjs.DnsCache == nil || len(s.cfg.AllowedDomains) == 0 {
			return
		}
		rctx, rcancel := context.WithTimeout(runCtx, 60*time.Second)
		owners := policy.ResolveOwners(rctx, s.cfg.AllowedDomains, nil, allowlistReCheckMaxAttempts)
		rcancel()
		seeded := seedDefendOwners(s.defendObjs.DnsCache, owners, s.stats.addDNSCacheUpdateFailure)
		slog.Debug("defend dns_cache owner map refreshed from trusted resolver", "entries", seeded)
	}
	onDrift := func(dr policy.DriftReport) {
		s.stats.addDNSDrift()
		reseedDefendOwners()
		if s.cfg.EventsLogPath == "" {
			return
		}
		ev := telemetry.DNSDriftEvent{
			Type:        telemetry.EventTypeDNSDrift,
			TS:          time.Now().UTC().Format(time.RFC3339Nano),
			AddedIPs:    dr.AddedIPs,
			RemovedIPs:  dr.RemovedIPs,
			DomainCount: len(s.defendCompiled.Domains),
			CheckedAt:   dr.CheckedAt,
		}
		s.jsonlMu.Lock()
		err := telemetry.AppendJSONL(s.cfg.EventsLogPath, ev, s.signer)
		s.jsonlMu.Unlock()
		if err != nil {
			slog.Warn("dns_drift jsonl append failed", "err", err)
		}
	}
	onClean := func() {
		reseedDefendOwners()
		slog.Debug("allowlist DNS re-resolution: no drift", "domains", len(s.defendCompiled.Domains))
	}
	runDNSDriftWatch(runCtx, s.defendCompiled, nil, allowlistReCheckMaxAttempts, allowlistReCheckInterval, onDrift, onClean)
}

// runHeartbeatLoop polls the main sys_enter BPF program every 30s to confirm it
// is still attached and valid; a get_info failure records a heartbeat failure.
func (s *runState) runHeartbeatLoop(runCtx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-runCtx.Done():
			return
		case <-ticker.C:
			info, err := s.syscallObjs.HandleRawSysEnter.Info()
			if err != nil {
				slog.Error("BPF heartbeat FAILED: sys_enter program get_info error", "err", err)
				s.stats.addBPFHeartbeatFailure()
				continue
			}
			id, ok := info.ID()
			if ok {
				slog.Debug("BPF heartbeat OK", "id", id)
			} else {
				slog.Warn("BPF heartbeat: program has no ID")
				s.stats.addBPFHeartbeatFailure()
			}
		}
	}
}
