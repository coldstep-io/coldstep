//go:build linux

package agent

import (
	"sync"
	"time"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// P3-3: TLS ClientHello inter-syscall reassembly.
//
// Some TLS stacks (Go crypto/tls, rustls, Node.js TLSWrap) split the ClientHello
// across two write/writev/sendto calls — a 5-byte record header in one syscall
// and the handshake body in the next. The single-buffer SNI parser sees only the
// header and fails. This package keeps a small per-(pid,dst,dport) accumulator
// in userspace and retries the parse once enough bytes have arrived.
//
// Option A (BPF-side per-socket state via a hash map keyed on (pid, fd)) is the
// long-term path because it avoids userspace allocation pressure and tracks the
// real connection identity. It is deferred: the BPF programs do not yet plumb
// the file descriptor into the wire event, and adding a 512-byte value map per
// tracked socket needs additional verifier audit work. Until then this
// userspace fallback covers the common header/body split.

const (
	tlsReassemblyBufferCap     = 512
	tlsReassemblyDefaultTTL    = 30 * time.Second
	tlsReassemblyDefaultMaxKey = 1024
)

// tlsReassemblyKey identifies a partially observed ClientHello. Because the BPF
// wire format does not currently include the socket file descriptor, we key on
// the next-best tuple: (pid, dst, dport). False sharing across two simultaneous
// TLS connections to the same (dst,dport) from one pid is possible but rare —
// real workloads multiplex over distinct destinations.
type tlsReassemblyKey struct {
	PID   uint32
	Dst   [4]byte
	Dport uint16
}

type tlsReassemblyEntry struct {
	buf       []byte
	createdAt time.Time
	updatedAt time.Time
}

// tlsReassembler accumulates ClientHello bytes per key and retries SNI parsing.
// All public methods are safe for concurrent use.
type tlsReassembler struct {
	mu     sync.Mutex
	now    func() time.Time
	ttl    time.Duration
	maxKey int
	bufCap int
	store  map[tlsReassemblyKey]*tlsReassemblyEntry
}

func newTLSReassembler() *tlsReassembler {
	return newTLSReassemblerWithClock(time.Now, tlsReassemblyDefaultTTL, tlsReassemblyDefaultMaxKey, tlsReassemblyBufferCap)
}

func newTLSReassemblerWithClock(now func() time.Time, ttl time.Duration, maxKey, bufCap int) *tlsReassembler {
	if now == nil {
		now = time.Now
	}
	if ttl <= 0 {
		ttl = tlsReassemblyDefaultTTL
	}
	if maxKey <= 0 {
		maxKey = tlsReassemblyDefaultMaxKey
	}
	if bufCap <= 0 {
		bufCap = tlsReassemblyBufferCap
	}
	return &tlsReassembler{
		now:    now,
		ttl:    ttl,
		maxKey: maxKey,
		bufCap: bufCap,
		store:  make(map[tlsReassemblyKey]*tlsReassemblyEntry),
	}
}

// appendResult describes the outcome of feeding more payload into the reassembler.
type appendResult struct {
	sni        string
	parsed     bool
	bufferLen  int
	reassembly bool // true when the success used buffered bytes from a previous syscall
}

// appendAndParse adds payload to the (pid,dst,dport) accumulator (up to bufCap
// bytes total) and attempts a ClientHello SNI parse on the cumulative buffer.
//
// Returns parsed=true with the SNI when the extension was recovered. When
// reassembly=true, the SNI came from multiple syscalls combined and the caller
// should mark the event TLSConfidence="partial" / ReassembledSNI=true.
//
// If the first byte of accumulated data is not a TLS handshake record (0x16),
// the entry is dropped — there is no point holding state for application data
// or non-TLS streams. Entries are also evicted on parse success.
func (r *tlsReassembler) appendAndParse(key tlsReassemblyKey, payload []byte) appendResult {
	if len(payload) == 0 {
		return appendResult{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.evictExpiredLocked()

	entry, hadEntry := r.store[key]
	if !hadEntry {
		if len(r.store) >= r.maxKey {
			r.evictOldestLocked()
		}
		entry = &tlsReassemblyEntry{
			buf:       make([]byte, 0, r.bufCap),
			createdAt: r.now(),
		}
		r.store[key] = entry
	}

	// Append up to the per-entry cap. We never grow past bufCap; once full, we
	// parse what we have and stop accumulating to avoid unbounded memory.
	remaining := r.bufCap - len(entry.buf)
	if remaining > 0 {
		take := payload
		if len(take) > remaining {
			take = take[:remaining]
		}
		entry.buf = append(entry.buf, take...)
	}
	entry.updatedAt = r.now()

	// Discard entries that are not TLS handshake records — caller likely passed
	// us an application_data record or non-TLS bytes.
	if len(entry.buf) >= 1 && entry.buf[0] != 0x16 {
		delete(r.store, key)
		return appendResult{bufferLen: len(entry.buf)}
	}

	sni, ok := telemetry.ParseClientHelloSNI(entry.buf)
	if ok {
		delete(r.store, key)
		return appendResult{
			sni:        sni,
			parsed:     true,
			bufferLen:  len(entry.buf),
			reassembly: hadEntry,
		}
	}
	return appendResult{bufferLen: len(entry.buf)}
}

// forget drops any buffered state for a key (e.g. on socket close).
func (r *tlsReassembler) forget(key tlsReassemblyKey) {
	r.mu.Lock()
	delete(r.store, key)
	r.mu.Unlock()
}

// sweep evicts expired entries and returns the number removed. Callers may
// invoke this periodically from a long-running goroutine; the appendAndParse
// path already calls it lazily on every insertion.
func (r *tlsReassembler) sweep() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.evictExpiredLocked()
}

// len returns the number of tracked keys (test helper; safe for production).
func (r *tlsReassembler) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.store)
}

func (r *tlsReassembler) evictExpiredLocked() int {
	if r.ttl <= 0 || len(r.store) == 0 {
		return 0
	}
	cutoff := r.now().Add(-r.ttl)
	n := 0
	for k, v := range r.store {
		if v.updatedAt.Before(cutoff) {
			delete(r.store, k)
			n++
		}
	}
	return n
}

// evictOldestLocked drops the least-recently-updated entry to keep the store
// bounded when many short-lived sockets pile up faster than ttl can clear them.
func (r *tlsReassembler) evictOldestLocked() {
	var oldestKey tlsReassemblyKey
	var oldestAt time.Time
	first := true
	for k, v := range r.store {
		if first || v.updatedAt.Before(oldestAt) {
			oldestKey = k
			oldestAt = v.updatedAt
			first = false
		}
	}
	if !first {
		delete(r.store, oldestKey)
	}
}
