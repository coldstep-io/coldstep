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

	tr.Mark(pid, fd)

	if !tr.IsKTLS(pid, fd) {
		t.Fatalf("IsKTLS(%d, %d) = false right after Mark; want true", pid, fd)
	}
	// Wildcard fd path used by the TLS ring reader (tls_sniff_event has no fd
	// today). The TLS event also has to be flipped to unknown/ktls in that
	// path, so the wildcard must hit too.
	if !tr.IsKTLS(pid, 0) {
		t.Fatalf("IsKTLS(%d, 0) wildcard = false right after Mark; want true", pid)
	}

	conf := telemetry.ScoreTLSConfidence("example.com")
	reason := ""
	if tr.IsKTLS(pid, 0) {
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

	tr.Mark(pid, fd)
	if !tr.IsKTLS(pid, fd) {
		t.Fatalf("IsKTLS(%d, %d) = false immediately after Mark; want true", pid, fd)
	}

	// Advance the injected clock past the TTL. Mark on a different pid forces
	// the amortized eviction sweep so the original entry is provably gone
	// rather than merely returning false from a one-shot read.
	now = now.Add(ktlsTrackerTTL + time.Second)
	tr.Mark(9999, 1)

	if tr.IsKTLS(pid, fd) {
		t.Fatalf("IsKTLS(%d, %d) = true after %v; want false (entry should be evicted)",
			pid, fd, ktlsTrackerTTL+time.Second)
	}
	if tr.IsKTLS(pid, 0) {
		t.Fatalf("IsKTLS(%d, 0) wildcard = true after eviction; want false", pid)
	}
}

// TestKTLSTracker_WildcardIsolation guards the per-pid wildcard against
// cross-pid bleed: marking pid=A must not make IsKTLS(pid=B, 0) return true.
// Without this property the digest would falsely tag unrelated TLS events as
// KTLS-overridden whenever any process on the runner happened to use kTLS.
func TestKTLSTracker_WildcardIsolation(t *testing.T) {
	tr := newKTLSTracker()
	tr.Mark(100, 3)
	if !tr.IsKTLS(100, 0) {
		t.Fatalf("IsKTLS(100, 0) = false after Mark(100, 3); want true")
	}
	if tr.IsKTLS(200, 0) {
		t.Fatalf("IsKTLS(200, 0) = true after Mark(100, 3); want false (cross-pid bleed)")
	}
}
