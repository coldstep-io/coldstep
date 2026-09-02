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
// the defend and LSM watchers run independently and reuse asset names.
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

func watchMapIntegrity(ctx context.Context, cfg config.Config, defendCfg, allowedIpv4, ignoredIpv4 *ebpf.Map, defendCompiled policy.CompileResult, pol *policy.Policy, stats *runStats, defendState *defendState, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) error {
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
			checkMapIntegrity(cfg, defendCfg, allowedIpv4, ignoredIpv4, defendCompiled, pol, stats, defendState, backoff, seq, jsonlMu, signer)
		}
	}
}

func checkMapIntegrity(cfg config.Config, defendCfg, allowedIpv4, ignoredIpv4 *ebpf.Map, defendCompiled policy.CompileResult, pol *policy.Policy, stats *runStats, defendState *defendState, backoff *integrityBackoff, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, signer *telemetry.Signer) {
	if defendCfg == nil || allowedIpv4 == nil || ignoredIpv4 == nil {
		return
	}

	// 1. Check defend_cfg
	const assetDefendCfg = "map:defend_cfg"
	var key uint32 = 0
	var val uint32
	modeDefend := uint32(1)
	if err := defendCfg.Lookup(&key, &val); err != nil {
		logMapIntegrityFailure(cfg, assetDefendCfg, "lookup error", "", "", stats, seq, jsonlMu, defendState, backoff, signer)
		// H-05: a missing/unreadable defend_cfg key behaves like detect mode in
		// BPF (`defense_enabled()` returns false when the key is absent).
		// Try to restore the defend mode key on the same path the value-mismatch
		// branch uses so a transient lookup failure or tamper does not silently
		// disable defend.
		if updErr := defendCfg.Update(&key, &modeDefend, ebpf.UpdateAny); updErr != nil {
			slog.Error("BPF map defend_cfg revert failed (lookup error)", "err", updErr)
		} else {
			slog.Error("BPF map defend_cfg revert succeeded after lookup error")
			backoff.clear(assetDefendCfg)
		}
	} else if val != 1 {
		logMapIntegrityFailure(cfg, assetDefendCfg, "value mismatch", "1", fmt.Sprintf("%d", val), stats, seq, jsonlMu, defendState, backoff, signer)
		// Revert tampering.
		if err := defendCfg.Update(&key, &modeDefend, ebpf.UpdateAny); err != nil {
			slog.Error("BPF map defend_cfg revert failed", "err", err)
		} else {
			backoff.clear(assetDefendCfg)
		}
	}

	// 2. Check allowed_ipv4 keyset. A same-count key substitution (delete one
	// allowed /32, insert a different one — e.g. 0.0.0.0/0) is invisible to a
	// pure count comparison, so this compares the actual keyset against the
	// keyset expectedAllowedKeys derives from the same compiled snapshot +
	// policy that loadAllowedLPMMap originally programmed from, matching
	// rearmAllowedFromSnapshot's own reconciliation exactly.
	const assetAllowed = "map:allowed_ipv4"
	actual := make(map[[8]byte]struct{})
	iter := allowedIpv4.Iterate()
	var k [8]byte // LPM key (4 prefixlen + 4 ip)
	var v uint8
	for iter.Next(&k, &v) {
		actual[k] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		logMapIntegrityFailure(cfg, assetAllowed, "iterate error", "", "", stats, seq, jsonlMu, defendState, backoff, signer)
	} else {
		expected := expectedAllowedKeys(defendCompiled, pol)
		if !lpmKeysetsEqual(actual, expected) {
			logMapIntegrityFailure(cfg, assetAllowed, "keyset mismatch", fmt.Sprintf("%d entries", len(expected)), fmt.Sprintf("%d entries", len(actual)), stats, seq, jsonlMu, defendState, backoff, signer)
			// H-04: re-program the LPM trie from the compiled snapshot so a
			// tampered widening (extra allowed entries) or substitution does
			// not persist until process restart.
			added, removed, rearmErr := rearmAllowedFromSnapshot(allowedIpv4, defendCompiled, pol)
			if rearmErr != nil {
				slog.Error("BPF allowlist re-arm failed", "asset", assetAllowed, "err", rearmErr)
			} else {
				slog.Error("BPF allowlist re-armed after tamper", "asset", assetAllowed, "removed", removed, "added", added)
				backoff.clear(assetAllowed)
			}
		}
	}

	// 3. Check ignored_ipv4 keyset (same substitution gap as allowed_ipv4).
	const assetIgnored = "map:ignored_ipv4_lpm"
	actualIgnored := make(map[[8]byte]struct{})
	iterIgnored := ignoredIpv4.Iterate()
	for iterIgnored.Next(&k, &v) {
		actualIgnored[k] = struct{}{}
	}
	if err := iterIgnored.Err(); err != nil {
		logMapIntegrityFailure(cfg, assetIgnored, "iterate error", "", "", stats, seq, jsonlMu, defendState, backoff, signer)
	} else {
		expectedIgnored := expectedIgnoredKeys(pol)
		if !lpmKeysetsEqual(actualIgnored, expectedIgnored) {
			logMapIntegrityFailure(cfg, assetIgnored, "keyset mismatch", fmt.Sprintf("%d entries", len(expectedIgnored)), fmt.Sprintf("%d entries", len(actualIgnored)), stats, seq, jsonlMu, defendState, backoff, signer)
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

// lpmKeysetsEqual reports whether two LPM-trie keysets (8-byte prefixlen+IP
// keys) contain exactly the same keys.
func lpmKeysetsEqual(a, b map[[8]byte]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func logMapIntegrityFailure(cfg config.Config, asset, errStr, expected, actual string, stats *runStats, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, defendState *defendState, backoff *integrityBackoff, signer *telemetry.Signer) {
	stats.addBPFMapIntegrityFailure()
	if defendState != nil {
		defendState.addMapIntegrityFailure()
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
