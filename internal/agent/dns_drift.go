package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/coldstep-io/coldstep/internal/policy"
)

// allowlistReCheckInterval is how often the background goroutine re-runs
// CompileDomainAllowlist against the startup allowlist to compare against
// the IPv4 set programmed into the BPF map (H16 DNS allowlist trust
// hardening). Five minutes mirrors the digest's TTL-staleness threshold
// (report.allowlistStaleThreshold) so drift is observed before the digest
// would flag the snapshot as stale.
const allowlistReCheckInterval = 5 * time.Minute

// allowlistReCheckMaxAttempts caps per-domain DNS retries inside one tick.
// A single attempt keeps the periodic check cheap; transient resolver flakes
// recover naturally on the next tick rather than producing a long-running
// retry storm against the runner's stub resolver.
const allowlistReCheckMaxAttempts = 1

// runDNSDriftWatch periodically re-resolves original.Domains and reports
// IPv4 drift via onDrift. It is the agent's H16 watchdog: warning-only —
// it never updates the live BPF enforce policy, since mid-job expansion is a
// TOCTOU risk (a freshly-resolved CDN tenant IP could be added between the
// lookup and the egress attempt).
//
// The loop terminates when ctx is cancelled and ignores ticks that fire while
// the previous re-resolution is still running (a stuck stub resolver on the
// runner cannot pile up overlapping work).
//
// Dependencies are injected for testability:
//   - resolver: nil → net.DefaultResolver.LookupIP (production path)
//   - onDrift: called once per non-empty DriftReport; agent-side closure
//     emits a JSONL DNSDriftEvent and bumps the runStats counter.
//   - onClean: called once per tick when AddedIPs and RemovedIPs are both
//     empty; agent-side closure logs at debug level.
func runDNSDriftWatch(
	ctx context.Context,
	original policy.CompileResult,
	resolver policy.LookupIPFunc,
	maxAttempts int,
	interval time.Duration,
	onDrift func(policy.DriftReport),
	onClean func(),
) {
	if len(original.Domains) == 0 {
		return
	}
	if interval <= 0 {
		interval = allowlistReCheckInterval
	}
	if maxAttempts < 1 {
		maxAttempts = allowlistReCheckMaxAttempts
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return
		}
		updated := policy.ReResolve(ctx, original, resolver, maxAttempts)
		if ctx.Err() != nil {
			return
		}
		dr := policy.Diff(original, updated)
		if len(dr.AddedIPs) == 0 && len(dr.RemovedIPs) == 0 {
			if onClean != nil {
				onClean()
			}
			continue
		}
		slog.Warn("allowlist DNS drift detected",
			"added", len(dr.AddedIPs),
			"removed", len(dr.RemovedIPs))
		if onDrift != nil {
			onDrift(dr)
		}
	}
}
