//go:build linux

package agent

import (
	"errors"
	"fmt"
	"sync"

	"github.com/coldstep-io/coldstep/internal/report"
	"github.com/coldstep-io/coldstep/internal/telemetry"
)

type defendState struct {
	mu                     sync.Mutex
	mode                   string
	allowlistSize          int
	denyCountN             int
	denyReserveFailuresN   int
	mapIntegrityFailures   int
	expectedEntries        int
	expectedIgnoredEntries int
	firstDenyRowV          *report.DenyDigestRow
}

type defendSnapshot struct {
	mode                 string
	allowlistSize        int
	denyCount            int
	denyReserveFailures  int
	mapIntegrityFailures int
	firstDeny            *report.DenyDigestRow
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

func (s *defendState) noteDeny(row report.DenyDigestRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denyCountN++
	if s.firstDenyRowV == nil {
		cp := row
		s.firstDenyRowV = &cp
	}
}

func (s *defendState) denyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.denyCountN
}

func (s *defendState) firstDeny() *report.DenyDigestRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.firstDenyRowV == nil {
		return nil
	}
	cp := *s.firstDenyRowV
	return &cp
}

func (s *defendState) snapshot() defendSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := defendSnapshot{
		mode:                 s.mode,
		allowlistSize:        s.allowlistSize,
		denyCount:            s.denyCountN,
		denyReserveFailures:  s.denyReserveFailuresN,
		mapIntegrityFailures: s.mapIntegrityFailures,
	}
	if s.firstDenyRowV != nil {
		cp := *s.firstDenyRowV
		out.firstDeny = &cp
	}
	return out
}

func (s *defendState) setDenyReserveFailures(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denyReserveFailuresN = n
}
