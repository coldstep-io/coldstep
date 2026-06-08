//go:build linux

package agent

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// denyDedupWindow bounds how long after an emitted deny a second deny with the
// SAME {tgid,tid,dst,dport,proto} key but a DIFFERENT hook family is treated as
// the cross-layer twin of the same syscall (cgroup/connect4 + lsm/socket_connect
// both fire on one connect() on LSM-enabled kernels). Cross-layer ringbuf
// delivery is near-simultaneous; 1s is generous. Same-family repeats always emit
// regardless of the window, so genuine retries are never collapsed.
const denyDedupWindow = time.Second

// denyDedupMaxEntries caps the dedup map so a long defend run with many distinct
// blocked destinations cannot grow it without bound. Stale entries (older than
// the window) are pruned opportunistically when the cap is exceeded.
const denyDedupMaxEntries = 4096

// denyDedupKey identifies one logical deny across hook families.
type denyDedupKey struct {
	tgid     uint32
	tid      uint32
	dst      string
	dport    uint16
	protocol string
}

type denyDedupEntry struct {
	family string
	nano   int64
}

type defendState struct {
	mu                     sync.Mutex
	mode                   string
	allowlistSize          int
	allowlistIPv6Size      int
	denyCountN             int
	denyCorroboratedN      int
	denyReserveFailuresN   int
	mapIntegrityFailures   int
	expectedEntries        int
	expectedIgnoredEntries int
	denyDedup              map[denyDedupKey]denyDedupEntry
}

type defendSnapshot struct {
	mode                 string
	allowlistSize        int
	allowlistIPv6Size    int
	denyCount            int
	denyCorroborated     int
	denyReserveFailures  int
	mapIntegrityFailures int
}

type defendBackendConfig struct {
	modeDefend bool
	haveLSM    bool
}

type defendBackendOutcome struct {
	backend string
}

const (
	defendBackendDetect = "detect"
	defendBackendLSM    = "lsm"
	defendBackendCgroup = "cgroup"

	defendModeLSM    = "defend+lsm"
	defendModeCgroup = "defend+cgroup"
)

func chooseDefendBackend(cfg defendBackendConfig, lsmAttachErr error) defendBackendOutcome {
	if !cfg.modeDefend {
		return defendBackendOutcome{backend: defendBackendDetect}
	}
	if cfg.haveLSM && lsmAttachErr == nil {
		return defendBackendOutcome{backend: defendBackendLSM}
	}
	return defendBackendOutcome{backend: defendBackendCgroup}
}

func defendModeForBackend(backend string) string {
	if backend == defendBackendLSM {
		return defendModeLSM
	}
	return defendModeCgroup
}

type defendDenyError struct {
	protocol string
	dst      string
	dport    uint16
	reason   string
}

func (e defendDenyError) Error() string {
	return fmt.Sprintf("defend deny: protocol=%s dst=%s dport=%d reason=%s", e.protocol, e.dst, e.dport, e.reason)
}

func newDefendDenyError(ev telemetry.DenyEvent) error {
	return defendDenyError{
		protocol: ev.Protocol,
		dst:      ev.Dst,
		dport:    ev.Dport,
		reason:   ev.Reason,
	}
}

func isDefendDenyError(err error) bool {
	var e defendDenyError
	return errors.As(err, &e)
}

func newDefendState() *defendState {
	return &defendState{}
}

func (s *defendState) setModeAndAllowlist(mode string, allowlistSize, ignoredSize int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
	s.allowlistSize = allowlistSize
	s.expectedEntries = allowlistSize
	s.expectedIgnoredEntries = ignoredSize
}

// downgradeMode replaces the mode label without disturbing allowlist
// counters. Used by the LSM-silent probe to flip `defend+lsm` to
// `defend+cgroup` after the fact when LSM attaches succeed but the kernel
// never dispatches to the hooks (Ubuntu 24.04 default `lsm=` boot chain).
func (s *defendState) downgradeMode(mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
}

// setIPv6AllowlistSize records the number of /128 entries written into the
// BPF allowed_ipv6 LPM trie at startup. Called from loadDefendMaps after
// populateAllowedIPv6Map. Zero means defend is in pure block-all IPv6
// posture (every non-loopback / non-link-local IPv6 destination denied).
func (s *defendState) setIPv6AllowlistSize(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowlistIPv6Size = n
}

func (s *defendState) addMapIntegrityFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mapIntegrityFailures++
}

func (s *defendState) mapIntegrityFailureCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mapIntegrityFailures
}

// shouldEmitDeny reports whether a decoded deny should be emitted (JSONL +
// counted) or treated as the cross-layer twin of a deny already emitted by the
// other hook family within denyDedupWindow. Returns true to emit, false to
// corroborate (the corroboration counter is bumped internally).
//
// A duplicate is recognized only across DIFFERENT hook families: cgroup/connect4
// and lsm/socket_connect both fire on the same connect() syscall. Two denies
// from the SAME family are genuine separate attempts (e.g. a retry loop) and
// always emit, so no traffic is hidden. A nil receiver always emits.
func (s *defendState) shouldEmitDeny(key denyDedupKey, family string, nowNano int64) bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.denyDedup == nil {
		s.denyDedup = make(map[denyDedupKey]denyDedupEntry)
	}
	prev, ok := s.denyDedup[key]
	fresh := ok && nowNano-prev.nano <= int64(denyDedupWindow)
	if fresh && prev.family != "" && family != "" && prev.family != family {
		// Cross-layer twin of a recently emitted deny: corroborate, don't
		// re-emit. Keep the original emitting family; refresh the timestamp so
		// a third hook family (e.g. sendpage) within the window also folds in.
		s.denyCorroboratedN++
		s.denyDedup[key] = denyDedupEntry{family: prev.family, nano: nowNano}
		return false
	}
	s.denyDedup[key] = denyDedupEntry{family: family, nano: nowNano}
	if len(s.denyDedup) > denyDedupMaxEntries {
		s.pruneDenyDedupLocked(nowNano)
	}
	return true
}

// pruneDenyDedupLocked drops dedup entries older than the window. Caller holds mu.
func (s *defendState) pruneDenyDedupLocked(nowNano int64) {
	for k, e := range s.denyDedup {
		if nowNano-e.nano > int64(denyDedupWindow) {
			delete(s.denyDedup, k)
		}
	}
}

// denyCorroborated returns the number of denies suppressed as cross-layer twins.
func (s *defendState) denyCorroborated() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.denyCorroboratedN
}

func (s *defendState) noteDeny() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denyCountN++
}

func (s *defendState) denyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.denyCountN
}

func (s *defendState) snapshot() defendSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := defendSnapshot{
		mode:                 s.mode,
		allowlistSize:        s.allowlistSize,
		allowlistIPv6Size:    s.allowlistIPv6Size,
		denyCount:            s.denyCountN,
		denyCorroborated:     s.denyCorroboratedN,
		denyReserveFailures:  s.denyReserveFailuresN,
		mapIntegrityFailures: s.mapIntegrityFailures,
	}
	return out
}

func (s *defendState) setDenyReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denyReserveFailuresN = n
}
