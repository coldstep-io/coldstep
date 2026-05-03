//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/coldstep-io/coldstep/internal/config"
	"github.com/coldstep-io/coldstep/internal/policy"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// integrityBackoffWindow caps how long a single asset's failures are
// downgraded to slog.Warn after the first slog.Error. Within this window
// each fresh failure logs as Warn (deduplicated severity); after the window
// elapses, or after a successful re-arm clears the asset, the next failure
// re-escalates to Error. JSONL emission and counter increments are unchanged
// so M-12's bpf_tamper-based hard-fail keeps signaling.
const integrityBackoffWindow = 5 * time.Minute

// integrityBackoff tracks per-asset last-failure timestamps so recurring
// integrity failures within integrityBackoffWindow downgrade their slog
// level (M-13). Each watchMapIntegrity goroutine owns its own instance —
// the enforce and LSM watchers run independently and reuse asset names.
type integrityBackoff struct {
	mu       sync.Mutex
	lastFail map[string]time.Time
}

func newIntegrityBackoff() *integrityBackoff {
	return &integrityBackoff{lastFail: make(map[string]time.Time)}
}

// noteFailure records a fresh failure for asset and returns true when the
// caller should escalate to slog.Error (first failure or first failure
// after the backoff window expired). Subsequent failures inside the window
// return false so the caller can degrade to slog.Warn.
func (b *integrityBackoff) noteFailure(asset string) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	last, ok := b.lastFail[asset]
	b.lastFail[asset] = now
	if !ok {
		return true
	}
	return now.Sub(last) >= integrityBackoffWindow
}

// clear forgets the backoff state for asset so the next failure re-escalates
// to slog.Error. Called after a successful revert / re-arm.
func (b *integrityBackoff) clear(asset string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.lastFail, asset)
}

func watchMapIntegrity(ctx context.Context, cfg config.Config, enforceCfg, allowedIpv4, ignoredIpv4 *ebpf.Map, enforceCompiled policy.CompileResult, pol *policy.Policy, stats *runStats, enforceState *enforcementState, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	backoff := newIntegrityBackoff()

	for {
		select {
		case <-ctx.Done():
			// Shutdown via SIGTERM/SIGINT — avoid treating cancellation like an operational reader failure.
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			return ctx.Err()
		case <-ticker.C:
			checkMapIntegrity(cfg, enforceCfg, allowedIpv4, ignoredIpv4, enforceCompiled, pol, stats, enforceState, backoff, seq, jsonlMu, signer)
		}
	}
}

func checkMapIntegrity(cfg config.Config, enforceCfg, allowedIpv4, ignoredIpv4 *ebpf.Map, enforceCompiled policy.CompileResult, pol *policy.Policy, stats *runStats, enforceState *enforcementState, backoff *integrityBackoff, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) {
	if enforceCfg == nil || allowedIpv4 == nil || ignoredIpv4 == nil {
		return
	}

	// 1. Check enforce_cfg
	const assetEnforceCfg = "map:enforce_cfg"
	var key uint32 = 0
	var val uint32
	modeEnforce := uint32(1)
	if err := enforceCfg.Lookup(&key, &val); err != nil {
		logMapIntegrityFailure(cfg, assetEnforceCfg, "lookup error", "", "", stats, seq, jsonlMu, enforceState, backoff, signer)
		// H-05: a missing/unreadable enforce_cfg key behaves like detect mode in
		// BPF (`enforcement_enabled()` returns false when the key is absent).
		// Try to restore the enforce mode key on the same path the value-mismatch
		// branch uses so a transient lookup failure or tamper does not silently
		// disable enforcement.
		if updErr := enforceCfg.Update(&key, &modeEnforce, ebpf.UpdateAny); updErr != nil {
			slog.Error("BPF map enforce_cfg revert failed (lookup error)", "err", updErr)
		} else {
			slog.Error("BPF map enforce_cfg revert succeeded after lookup error")
			backoff.clear(assetEnforceCfg)
		}
	} else if val != 1 {
		logMapIntegrityFailure(cfg, assetEnforceCfg, "value mismatch", "1", fmt.Sprintf("%d", val), stats, seq, jsonlMu, enforceState, backoff, signer)
		// Revert tampering.
		if err := enforceCfg.Update(&key, &modeEnforce, ebpf.UpdateAny); err != nil {
			slog.Error("BPF map enforce_cfg revert failed", "err", err)
		} else {
			backoff.clear(assetEnforceCfg)
		}
	}

	// 2. Check allowed_ipv4 count
	const assetAllowed = "map:allowed_ipv4"
	count := 0
	iter := allowedIpv4.Iterate()
	var k [8]byte // LPM key (4 prefixlen + 4 ip)
	var v uint8
	for iter.Next(&k, &v) {
		count++
	}
	if err := iter.Err(); err != nil {
		logMapIntegrityFailure(cfg, assetAllowed, "iterate error", "", "", stats, seq, jsonlMu, enforceState, backoff, signer)
	} else {
		enforceState.mu.Lock()
		expected := enforceState.expectedEntries
		enforceState.mu.Unlock()
		if count != expected {
			logMapIntegrityFailure(cfg, assetAllowed, "count mismatch", fmt.Sprintf("%d", expected), fmt.Sprintf("%d", count), stats, seq, jsonlMu, enforceState, backoff, signer)
			// H-04: re-program the LPM trie from the compiled snapshot so a
			// tampered widening (extra allowed entries) or count corruption
			// does not persist until process restart.
			added, removed, rearmErr := rearmAllowedFromSnapshot(allowedIpv4, enforceCompiled, pol)
			if rearmErr != nil {
				slog.Error("BPF allowlist re-arm failed", "asset", assetAllowed, "err", rearmErr)
			} else {
				slog.Error("BPF allowlist re-armed after tamper", "asset", assetAllowed, "removed", removed, "added", added)
				backoff.clear(assetAllowed)
			}
		}
	}

	// 3. Check ignored_ipv4 count
	const assetIgnored = "map:ignored_ipv4_lpm"
	countIgnored := 0
	iterIgnored := ignoredIpv4.Iterate()
	for iterIgnored.Next(&k, &v) {
		countIgnored++
	}
	if err := iterIgnored.Err(); err != nil {
		logMapIntegrityFailure(cfg, assetIgnored, "iterate error", "", "", stats, seq, jsonlMu, enforceState, backoff, signer)
	} else {
		enforceState.mu.Lock()
		expectedIgnored := enforceState.expectedIgnoredEntries
		enforceState.mu.Unlock()
		if countIgnored != expectedIgnored {
			logMapIntegrityFailure(cfg, assetIgnored, "count mismatch", fmt.Sprintf("%d", expectedIgnored), fmt.Sprintf("%d", countIgnored), stats, seq, jsonlMu, enforceState, backoff, signer)
			// H-04: same self-heal posture as allowed_ipv4 — restore from
			// policy.IgnoredIPv4Nets so an attacker cannot widen the
			// implicit-allow surface by injecting extra ignored CIDRs.
			added, removed, rearmErr := rearmIgnoredFromPolicy(ignoredIpv4, pol)
			if rearmErr != nil {
				slog.Error("BPF allowlist re-arm failed", "asset", assetIgnored, "err", rearmErr)
			} else {
				slog.Error("BPF allowlist re-armed after tamper", "asset", assetIgnored, "removed", removed, "added", added)
				backoff.clear(assetIgnored)
			}
		}
	}
}

func logMapIntegrityFailure(cfg config.Config, asset, errStr, expected, actual string, stats *runStats, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, enforceState *enforcementState, backoff *integrityBackoff, signer *telemetry.Signer) {
	stats.addBPFMapIntegrityFailure()
	if enforceState != nil {
		enforceState.addMapIntegrityFailure()
	}
	// M-13: dedupe slog severity per asset within integrityBackoffWindow. The
	// JSONL bpf_tamper event and counter increments still flow on every tick
	// so M-12 (anti-blindness gating) keeps a stable signal — only the
	// operator-facing log level is dampened.
	if backoff.noteFailure(asset) {
		slog.Error("BPF map integrity failure", "asset", asset, "error", errStr, "expected", expected, "actual", actual)
	} else {
		slog.Warn("BPF map integrity failure (recurring within backoff window)",
			"asset", asset, "error", errStr, "expected", expected, "actual", actual,
			"backoff_window", integrityBackoffWindow)
	}
	if cfg.EventsLogPath != "" {
		jsonlMu.Lock()
		defer jsonlMu.Unlock()
		n := seq.Next()
		ts := time.Now().UTC().Format(time.RFC3339Nano)
		ev := telemetry.BPFTamperEvent{
			Type:     "bpf_tamper",
			TS:       ts,
			Seq:      n,
			Asset:    asset,
			Error:    errStr,
			Expected: expected,
			Actual:   actual,
		}
		if err := telemetry.AppendJSONL(cfg.EventsLogPath, ev, signer); err != nil {
			slog.Warn("bpf_tamper JSONL append failed", "err", err)
		}
	}
}
