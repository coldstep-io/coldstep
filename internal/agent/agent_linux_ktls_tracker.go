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

// ktlsEntry records a single Mark: the wall-clock time used for TTL eviction
// and the monotonic-ish markedAt timestamp (nanoseconds, captured at ringbuf
// arrival in userspace) used to gate IsKTLS by ordering. The two clocks are
// separate because the TTL evictor was already wall-clock-driven and tests
// inject the clock, while the ordering gate is fundamentally about comparing
// event arrival times within a single agent process.
type ktlsEntry struct {
	at       time.Time // wall-clock for TTL eviction
	markedAt int64     // userspace arrival time of the KTLS event, in ns
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
//   - The wildcard path is further gated by the TLS event's arrival timestamp:
//     IsKTLS only returns true when tlsTimestampNs >= markedAt. A TLS event
//     that landed in userspace before the KTLS Mark cannot have been encrypted
//     by the offload that hadn't yet been observed, so its original SNI
//     confidence is preserved. Without this ordering check, a single KTLS
//     event would clobber every TLS event from the same pid for the entire
//     TTL window — including pre-offload writes that legitimately carried
//     plaintext ClientHello bytes. The timestamps are userspace ringbuf
//     arrival times rather than kernel bpf_ktime_get_ns() because neither
//     wire event currently ships a kernel timestamp; arrival-order matches
//     emit-order in all but pathological ringbuf-drain stalls.
//
//   - Eviction is amortized into Mark: every insert sweeps entries older than
//     ktlsTrackerTTL. There is no background goroutine — the tracker lives
//     as long as a single agent run and the entry count is bounded by the
//     per-run KTLS setsockopt rate (single-digit to low-thousands).
type ktlsTracker struct {
	mu     sync.Mutex
	now    func() time.Time
	by     map[ktlsKey]ktlsEntry
	latest map[uint32]ktlsEntry // pid -> most recent offload (wildcard path)
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
		by:     make(map[ktlsKey]ktlsEntry),
		latest: make(map[uint32]ktlsEntry),
	}
}

// Mark records that (pid, fd) handed TLS encryption to the kernel at
// markedAtNs (the TLS-offload event's userspace ringbuf arrival time in
// nanoseconds). Subsequent IsKTLS queries within ktlsTrackerTTL whose own
// tlsTimestampNs >= markedAtNs will return true; queries from events that
// arrived before markedAtNs will not. Each call also evicts any expired
// entries against the wall clock.
//
// For the per-(pid, fd) entry the most recent Mark wins — that record is
// keyed by fd, so the second offload genuinely supersedes the first. The
// per-pid `latest` map is the wildcard fallback (for TLS events whose wire
// format does not carry fd) and tracks the *earliest* surviving Mark for
// the pid: when two fds on the same pid both offload, a pre-offload TLS
// write captured between the two Marks must still gate against the
// earlier offload's markedAt, not the later one — otherwise the
// arrival-order ordering check (`tlsTimestampNs >= markedAt`) would be
// evaluated against the wrong reference and the TLS event could be
// misclassified as pre-offload plaintext.
func (t *ktlsTracker) Mark(pid, fd uint32, markedAtNs int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.evictLocked(now)
	entry := ktlsEntry{at: now, markedAt: markedAtNs}
	t.by[ktlsKey{PID: pid, FD: fd}] = entry
	if existing, ok := t.latest[pid]; !ok || markedAtNs < existing.markedAt {
		t.latest[pid] = entry
	}
}

// IsKTLS reports whether (pid, fd) has been Marked within ktlsTrackerTTL AND
// tlsTimestampNs (the TLS event's userspace arrival time in nanoseconds) is at
// or after the recorded markedAt. When fd==0 the lookup falls back to the
// per-pid latest offload — the wildcard path used by the TLS ring reader,
// whose wire event does not carry fd. Callers pass fd==0 deliberately to opt
// into that fallback. A tlsTimestampNs that precedes the Mark always returns
// false: the TLS event was observed before the offload and therefore cannot
// have been clobbered by it.
func (t *ktlsTracker) IsKTLS(pid, fd uint32, tlsTimestampNs int64) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	cutoff := now.Add(-ktlsTrackerTTL)
	if fd != 0 {
		if e, ok := t.by[ktlsKey{PID: pid, FD: fd}]; ok && e.at.After(cutoff) {
			return tlsTimestampNs >= e.markedAt
		}
		return false
	}
	if e, ok := t.latest[pid]; ok && e.at.After(cutoff) {
		return tlsTimestampNs >= e.markedAt
	}
	return false
}

func (t *ktlsTracker) evictLocked(now time.Time) {
	cutoff := now.Add(-ktlsTrackerTTL)
	for k, e := range t.by {
		if !e.at.After(cutoff) {
			delete(t.by, k)
		}
	}
	for pid, e := range t.latest {
		if !e.at.After(cutoff) {
			delete(t.latest, pid)
		}
	}
}
