//go:build linux

// Package agent hosts the Linux BPF-backed Coldstep runtime.
//
// Many BPF loader unwind paths use `_ = x.Close()` during partial failure cleanup:
// the operator-facing error is the primary attach/load failure; chained Close errors
// are treated as best-effort (successful shutdown still uses defer Close() similarly).
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// Run loads BPF, streams events until ctx is cancelled, then drains workers.
//
// Run is orchestration only: it builds the shared *runState, drives the load /
// attach phases (agent_run_load.go), spawns the reader and monitor goroutines
// (agent_run_state.go), then waits for shutdown. Every Run-level resource is
// released through the single runCleanup LIFO stack (s.cleanup) so the close
// ordering matches the original monolithic body exactly — see runCleanup and
// the per-phase push() calls for the ordering contract.
func Run(ctx context.Context, cfg config.Config) error {
	pol, err := cfg.Policy()
	if err != nil {
		return err
	}

	s := &runState{
		cfg:            cfg,
		mode:           cfg.ModeConfig(),
		pol:            pol,
		stats:          newRunStats(),
		defendState:    newDefendState(),
		canary:         newCanaryState(),
		ktlsTr:         newKTLSTracker(),
		dnsCache:       NewDNSCache(),
		btfCache:       btf.NewCache(),
		kernel:         kernelRelease(),
		runnerEnv:      DetectRunnerEnv(),
		compatWarnings: CheckRunnerCompat(),
		procTreeGate:   config.FeatureGateEnabled(cfg.FeatureGates, "proc_tree"),
		tlsSNIGate:     config.FeatureGateEnabled(cfg.FeatureGates, "tls_sni"),
		fsGate:         config.FeatureGateEnabled(cfg.FeatureGates, "fs_events"),
	}
	for _, w := range s.compatWarnings {
		slog.Warn("runner_compat_warning", "code", w.Code, "detail", w.Detail)
	}
	if s.runnerEnv != RunnerEnvStandard {
		slog.Info("runner_env_detected", "env", s.runnerEnv)
	}
	s.stats.setRunnerEnv(s.runnerEnv)
	// P4: ktlsTr is shared between readKTLSRing (Mark) and readTLSRing (IsKTLS)
	// so a pre-offload ClientHello sniff is reclassified before it lands in JSONL.
	s.dnsCache.SetBPFFailureCallback(s.stats.addDNSCacheUpdateFailure)

	signer, err := telemetry.NewSigner(cfg.SigningKey)
	if err != nil {
		return fmt.Errorf("setup telemetry signer: %w", err)
	}
	s.signer = signer
	if err := initMemlock(); err != nil {
		return err
	}

	s.bpfSt = []telemetry.BPFStatus{
		{Name: "sched_process_exec", OK: false, Detail: "not loaded"},
		{Name: "raw_tp/sys_enter (connect, sendto, http sniff, tls)", OK: false, Detail: "not loaded"},
		{Name: "dns recvfrom sniff", OK: false, Detail: "not loaded"},
		// Reaching Run means probeBTF() in Main has already succeeded; record
		// that explicitly so .coldstep-telemetry.json carries a positive btf
		// availability signal. Kept at index 3 so bpfSt[0..2] index-sets stay stable.
		{Name: "btf", OK: true, BTFAvailable: true},
		// P3-2: paired kprobe/kretprobe on tcp_v4_connect. Filled in by
		// armSyscall; kept at index 4 so existing bpfSt[0..3] index-sets stay stable.
		{Name: "kprobe tcp_v4_connect (connect_result)", OK: false, Detail: "not loaded"},
	}

	// One LIFO cleanup stack drives every Run-level teardown. writeShutdownTelemetry
	// is pushed first so it unwinds LAST (after all reader goroutines exit and every
	// counter snapshot is taken); closeAllReaders is pushed early so it unwinds late
	// (covering any early-return before the runCtx shutdown goroutine is registered).
	// Subsequent per-phase pushes unwind in reverse registration order, preserving
	// the original defer LIFO — including the security-critical close ordering.
	defer s.cleanup.unwind()
	s.cleanup.push(s.writeShutdownTelemetry)

	compileCtx, compileCancel := context.WithTimeout(ctx, 120*time.Second)
	s.cleanup.push(compileCancel)
	s.defendCompiled, err = compileDefendAllowlist(compileCtx, cfg, nil, 2)
	if err != nil {
		return err
	}
	s.finalizeAllowlist(compileCtx)
	s.cleanup.push(s.closeAllReaders)

	// Defend mode: cgroup attach before traceexec/traceconnect. Ready status is
	// written only after syscall egress tracing attaches (defend requires it).
	if err := s.loadDefend(compileCtx); err != nil {
		return err
	}
	if err := s.loadExec(); err != nil {
		return err
	}
	if err := s.armSyscall(); err != nil {
		return err
	}

	// Detect mode: ready after syscall trace initialized. Defend mode defers
	// readiness until after the deny reader goroutine is launched (below).
	if !s.mode.DeferReadiness {
		if err := writeAgentStatus(cfg.AgentStatusPath, true); err != nil {
			return fmt.Errorf("agent ready status: %w", err)
		}
	}

	s.loadDNS()
	s.loadFork()
	s.loadFS()
	s.loadKTLS()
	s.loadIPv6Obs()
	// Attach bpf() audit tracing only after other BPF collections finish loading,
	// so coldstep's own bpf(2) load syscalls don't fill the small audit ringbuf
	// before its reader starts.
	s.loadBPFAudit()

	s.writeStartupMeta()

	runCtx, runCancel := context.WithCancel(ctx)
	s.cleanup.push(runCancel)

	go func() {
		<-runCtx.Done()
		s.closeAllReaders()
	}()

	slog.Info("coldstep event readers started", "mode", string(cfg.Mode))

	var wg sync.WaitGroup
	errCh := make(chan error, s.countReaders())

	// sendReaderErr cancels runCtx whenever a reader returns a fatal error
	// (anything other than context.Canceled) so peer goroutines unblock and
	// wg.Wait returns promptly, letting the deferred digest/telemetry writers run
	// (P3-bug-audit Bug 5).
	sendReaderErr := func(err error) {
		if err != nil && !errors.Is(err, context.Canceled) {
			runCancel()
		}
		errCh <- err
	}

	s.spawnReaders(runCtx, &wg, sendReaderErr)

	// Defend-mode readiness: write only after the deny reader goroutine(s) are
	// alive, so the GitHub Action's probe steps cannot race the reader being
	// attached. Detect-mode readiness was written above.
	var readyErr error
	if s.mode.DeferReadiness {
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

	if err := probeBTF(); err != nil {
		slog.Error("startup gate failed", "gate", "btf", "btf_available", false, "err", err)
		return err
	}

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

// sha256File returns the lowercase-hex SHA-256 digest of path's contents.
// H11 helper used to populate MetaEvent.EventsFileSHA256 on shutdown.
func sha256File(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 — path is the agent's own events log under $GITHUB_WORKSPACE
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
