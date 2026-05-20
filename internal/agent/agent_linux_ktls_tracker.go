//go:build linux

package agent

import (
	"sync"
	"time"
)

// ktlsTrackerTTL is the window during which a recorded setsockopt(SOL_TLS)
// offload is treated as still load-bearing for a subsequent TLS event on the
// same socket. 60 seconds covers the realistic gap between the KTLS handshake
// (which fires once per connection setup) and the longest run-of-the-mill
// keepalive/idle gaps within a single CI step.
const ktlsTrackerTTL = 60 * time.Second

// ktlsKey identifies one offloaded socket within a run. PID is the tgid as
// emitted by trace_ktls.bpf.c; FD is the userspace file descriptor passed to
// setsockopt(2). The pair is unique within the lifetime of the process and —
// for our purposes — within the ktlsTrackerTTL window: even if the fd is
// later reused for a non-TLS socket, that would race with KTLS teardown and
// is well outside the time horizon we care about.
type ktlsKey struct {
	PID uint32
	FD  uint32
}

// ktlsTracker correlates `ktls_offload` events with subsequent `tls`
// ClientHello events emitted by trace_tls_write.inc. Both events flow through
// the agent's ringbuf readers (readKTLSRing -> Mark, readTLSRing -> IsKTLS).
//
// The tracker exists because once setsockopt(SOL_TLS, TLS_TX|TLS_RX) succeeds
// the kernel takes over TLS encryption — write(2) buffers carry ciphertext and
// the userspace SNI sniffer can never resolve a server name on that socket.
// Any TLS event still produced for that socket (e.g. from a pre-offload write
// observed before the offload setsockopt) is a misleading "full" or "partial"
// confidence row. P4 forces those rows to TLSConfidenceUnknown with the
// confidence_reason "ktls" so operators can tell SNI failures caused by KTLS
// offload (structural) apart from SNI failures caused by fragmentation (which
// may be recoverable with reassembly tuning).
//
// Implementation notes:
//
//   - The TLS event wire format (tls_sniff_event in trace_connect_obs.h) does
//     not carry fd today. IsKTLS therefore accepts fd==0 as a wildcard match
//     meaning "any KTLS offload recorded for this pid within the TTL window".
//     The (pid, fd) primary key remains the canonical record so a future BPF
//     change that adds fd to tls_sniff_event can switch IsKTLS to the exact
//     lookup without churning the tracker contract.
//
//   - Eviction is amortized into Mark: every insert sweeps entries older than
//     ktlsTrackerTTL. There is no background goroutine — the tracker lives
//     as long as a single agent run and the entry count is bounded by the
//     per-run KTLS setsockopt rate (single-digit to low-thousands).
type ktlsTracker struct {
	mu     sync.Mutex
	now    func() time.Time
	by     map[ktlsKey]time.Time
	latest map[uint32]time.Time // pid -> most recent offload time (wildcard path)
}

// newKTLSTracker constructs a tracker with the wall-clock time source. Tests
// substitute now via the unexported newKTLSTrackerClock so TTL eviction is
// deterministic.
func newKTLSTracker() *ktlsTracker {
	return newKTLSTrackerClock(time.Now)
}

func newKTLSTrackerClock(now func() time.Time) *ktlsTracker {
	return &ktlsTracker{
		now:    now,
		by:     make(map[ktlsKey]time.Time),
		latest: make(map[uint32]time.Time),
	}
}

// Mark records that (pid, fd) handed TLS encryption to the kernel at the
// current clock tick. Subsequent IsKTLS queries within ktlsTrackerTTL will
// return true for either the exact key or the (pid, 0) wildcard form used by
// the TLS ring reader. Each call also evicts any expired entries.
func (t *ktlsTracker) Mark(pid, fd uint32) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.evictLocked(now)
	t.by[ktlsKey{PID: pid, FD: fd}] = now
	t.latest[pid] = now
}

// IsKTLS reports whether (pid, fd) has been Marked within ktlsTrackerTTL.
// When fd==0 the lookup falls back to the per-pid latest offload time — the
// wildcard path used by the TLS ring reader, whose wire event does not carry
// fd. Callers pass fd==0 deliberately to opt into that fallback.
func (t *ktlsTracker) IsKTLS(pid, fd uint32) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	cutoff := now.Add(-ktlsTrackerTTL)
	if fd != 0 {
		if ts, ok := t.by[ktlsKey{PID: pid, FD: fd}]; ok && ts.After(cutoff) {
			return true
		}
		return false
	}
	if ts, ok := t.latest[pid]; ok && ts.After(cutoff) {
		return true
	}
	return false
}

func (t *ktlsTracker) evictLocked(now time.Time) {
	cutoff := now.Add(-ktlsTrackerTTL)
	for k, ts := range t.by {
		if !ts.After(cutoff) {
			delete(t.by, k)
		}
	}
	for pid, ts := range t.latest {
		if !ts.After(cutoff) {
			delete(t.latest, pid)
		}
	}
}
