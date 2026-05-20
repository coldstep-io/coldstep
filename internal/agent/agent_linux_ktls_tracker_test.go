//go:build linux

package agent

import (
	"testing"
	"time"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// TestKTLSTracker_OverridesConfidence covers the P4 happy path: when a
// ktls_offload event is observed for (pid, fd), the next TLS event on the
// same socket flows through the same override path and ends up with
// Confidence=unknown and ConfidenceReason="ktls". The test mirrors the
// production override sequence in readTLSRing rather than calling into the
// ring reader directly so it stays isolated from BPF/ringbuf wiring.
func TestKTLSTracker_OverridesConfidence(t *testing.T) {
	tr := newKTLSTracker()

	const pid uint32 = 1234
	const fd uint32 = 7
	const markedAtNs int64 = 1_000_000_000
	const tlsAfterNs int64 = 1_500_000_000 // TLS event after the Mark

	tr.Mark(pid, fd, markedAtNs)

	if !tr.IsKTLS(pid, fd, tlsAfterNs) {
		t.Fatalf("IsKTLS(%d, %d, %d) = false right after Mark; want true", pid, fd, tlsAfterNs)
	}
	// Wildcard fd path used by the TLS ring reader (tls_sniff_event has no fd
	// today). The TLS event also has to be flipped to unknown/ktls in that
	// path, so the wildcard must hit too.
	if !tr.IsKTLS(pid, 0, tlsAfterNs) {
		t.Fatalf("IsKTLS(%d, 0, %d) wildcard = false right after Mark; want true", pid, tlsAfterNs)
	}

	conf := telemetry.ScoreTLSConfidence("example.com")
	reason := ""
	if tr.IsKTLS(pid, 0, tlsAfterNs) {
		conf = telemetry.TLSConfidenceUnknown
		reason = "ktls"
	}
	if conf != telemetry.TLSConfidenceUnknown {
		t.Fatalf("overridden Confidence = %q; want %q", conf, telemetry.TLSConfidenceUnknown)
	}
	if reason != "ktls" {
		t.Fatalf("overridden ConfidenceReason = %q; want %q", reason, "ktls")
	}
}

// TestKTLSTracker_PreOffloadTLSPreserved guards the timestamp gate: a TLS
// event whose userspace arrival timestamp predates the KTLS Mark must NOT be
// reclassified, even when it falls inside the per-pid wildcard window. The
// failure mode this prevents is "wildcard fd=0 clobbers every TLS event for
// the next 60s including ones that arrived before the offload was observed".
func TestKTLSTracker_PreOffloadTLSPreserved(t *testing.T) {
	tr := newKTLSTracker()

	const pid uint32 = 4321
	const fd uint32 = 11
	const tlsBeforeNs int64 = 500_000_000 // pre-offload TLS event
	const markedAtNs int64 = 1_000_000_000
	const tlsAfterNs int64 = 1_500_000_000

	tr.Mark(pid, fd, markedAtNs)

	// Pre-offload TLS event: must stay un-overridden via the wildcard path.
	if tr.IsKTLS(pid, 0, tlsBeforeNs) {
		t.Fatalf("IsKTLS(%d, 0, %d) wildcard = true for tlsTimestampNs < markedAt; "+
			"want false (pre-offload TLS event must keep its original confidence)",
			pid, tlsBeforeNs)
	}
	// Exact-fd lookup must enforce the same ordering rule.
	if tr.IsKTLS(pid, fd, tlsBeforeNs) {
		t.Fatalf("IsKTLS(%d, %d, %d) exact = true for tlsTimestampNs < markedAt; "+
			"want false", pid, fd, tlsBeforeNs)
	}
	// Sanity: a TLS event AFTER the Mark is still flipped on both paths.
	if !tr.IsKTLS(pid, 0, tlsAfterNs) {
		t.Fatalf("IsKTLS(%d, 0, %d) wildcard = false for tlsTimestampNs >= markedAt; want true",
			pid, tlsAfterNs)
	}
	if !tr.IsKTLS(pid, fd, tlsAfterNs) {
		t.Fatalf("IsKTLS(%d, %d, %d) exact = false for tlsTimestampNs >= markedAt; want true",
			pid, fd, tlsAfterNs)
	}
}

// TestKTLSTracker_TTLEviction asserts that an offload recorded more than
// ktlsTrackerTTL ago is not used to override a later TLS event. fd reuse and
// long-lived runners can re-bind the same (pid, fd) to a non-KTLS socket; the
// TTL bounds the blast radius of that race.
func TestKTLSTracker_TTLEviction(t *testing.T) {
	var now = time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	tr := newKTLSTrackerClock(clock)

	const pid uint32 = 4242
	const fd uint32 = 11
	const markedAtNs int64 = 1_000_000_000
	const tlsAfterNs int64 = 2_000_000_000

	tr.Mark(pid, fd, markedAtNs)
	if !tr.IsKTLS(pid, fd, tlsAfterNs) {
		t.Fatalf("IsKTLS(%d, %d, %d) = false immediately after Mark; want true",
			pid, fd, tlsAfterNs)
	}

	// Advance the injected clock past the TTL. Mark on a different pid forces
	// the amortized eviction sweep so the original entry is provably gone
	// rather than merely returning false from a one-shot read.
	now = now.Add(ktlsTrackerTTL + time.Second)
	tr.Mark(9999, 1, 10_000_000_000)

	if tr.IsKTLS(pid, fd, tlsAfterNs) {
		t.Fatalf("IsKTLS(%d, %d, %d) = true after %v; want false (entry should be evicted)",
			pid, fd, tlsAfterNs, ktlsTrackerTTL+time.Second)
	}
	if tr.IsKTLS(pid, 0, tlsAfterNs) {
		t.Fatalf("IsKTLS(%d, 0, %d) wildcard = true after eviction; want false",
			pid, tlsAfterNs)
	}
}

// TestKTLSTracker_WildcardIsolation guards the per-pid wildcard against
// cross-pid bleed: marking pid=A must not make IsKTLS(pid=B, 0) return true.
// Without this property the digest would falsely tag unrelated TLS events as
// KTLS-overridden whenever any process on the runner happened to use kTLS.
func TestKTLSTracker_WildcardIsolation(t *testing.T) {
	tr := newKTLSTracker()
	const markedAtNs int64 = 1_000_000_000
	const tlsAfterNs int64 = 2_000_000_000

	tr.Mark(100, 3, markedAtNs)
	if !tr.IsKTLS(100, 0, tlsAfterNs) {
		t.Fatalf("IsKTLS(100, 0, %d) = false after Mark(100, 3); want true", tlsAfterNs)
	}
	if tr.IsKTLS(200, 0, tlsAfterNs) {
		t.Fatalf("IsKTLS(200, 0, %d) = true after Mark(100, 3); want false (cross-pid bleed)",
			tlsAfterNs)
	}
}
