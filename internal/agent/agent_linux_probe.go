//go:build linux

package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// probeDefendDst is a TEST-NET-3 (RFC 5737) IPv4 address used as the destination of
// the post-attach self-test connect. TEST-NET-3 is documented as never routable on
// the public internet, so a probe to it has no side effects beyond invoking the
// cgroup connect4 BPF program.
var probeDefendDst = net.IPv4(203, 0, 113, 1)

const (
	probeDefendDport    uint16        = 1
	defaultProbeTimeout time.Duration = 5 * time.Second
	probeDialTimeout    time.Duration = 50 * time.Millisecond
	probeDialRetryEvery time.Duration = 50 * time.Millisecond
	// lsmProbeTimeout bounds how long probeLSMSilent waits for an LSM deny
	// event before declaring the LSM section attached-but-silent. Kept
	// shorter than defaultProbeTimeout because the dial loop's connects
	// also land in the cgroup ringbuf as background self-denies, and we do
	// not want to pile up more than a couple of seconds of those.
	lsmProbeTimeout time.Duration = 1500 * time.Millisecond
)

// probeDefendEnforcement verifies that the cgroup defend BPF program is actively
// enforcing — not merely attached — before the caller declares the agent ready.
//
// AttachCgroup returns success once the program is bound to the cgroup, but on
// GitHub-hosted ubuntu-latest runners the program is observed to not yet block
// connects from newly-created sockets for ~1-3s afterward. This caused the first
// connect after .coldstep-ready.json was written to slip through.
//
// The probe drives a TCP connect to a non-allowlisted destination (TEST-NET-3
// 203.0.113.1:1) and waits for the corresponding deny ringbuf event. Receiving the
// event proves: cgroup hook fires → deny ringbuf reserve succeeds → readable by
// userspace. The connect attempt is retried at ~50ms intervals so a slow initial
// subscribe does not miss the only event.
//
// Probe-originated deny events are drained inside this function. Other deny events
// (background egress) arriving during the probe window are also drained — at agent
// startup, before .coldstep-ready.json is written, no caller is yet reading the
// ringbuf, and the probe completes before any meaningful workload begins.
func probeDefendEnforcement(rd *ringbuf.Reader, timeout time.Duration) error {
	if rd == nil {
		return errors.New("probe: nil ringbuf reader")
	}
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	deadline := time.Now().Add(timeout)

	stop := make(chan struct{})
	defer close(stop)
	go runProbeDialLoop(stop, deadline)

	rd.SetDeadline(deadline)
	defer rd.SetDeadline(time.Time{})

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return fmt.Errorf("probe: no matching deny event within %s — cgroup BPF not enforcing for newly-created sockets", timeout)
			}
			return fmt.Errorf("probe: ringbuf read: %w", err)
		}
		if matchProbeDenyEvent(rec.RawSample) {
			return nil
		}
		// Non-probe deny event during startup — drain and keep waiting.
	}
}

// runProbeDialLoop fires repeated TCP connects to the probe destination until the
// deadline elapses or stop is closed. Each connect attempt is the BPF trigger; the
// first one to be denied causes probeDefendEnforcement to return.
func runProbeDialLoop(stop <-chan struct{}, deadline time.Time) {
	dialer := net.Dialer{Timeout: probeDialTimeout}
	addr := net.JoinHostPort(probeDefendDst.String(), fmt.Sprintf("%d", probeDefendDport))
	for {
		select {
		case <-stop:
			return
		default:
		}
		if time.Now().After(deadline) {
			return
		}
		conn, _ := dialer.Dial("tcp4", addr)
		if conn != nil {
			_ = conn.Close()
		}
		select {
		case <-stop:
			return
		case <-time.After(probeDialRetryEvery):
		}
	}
}

// probeLSMSilent mirrors probeDefendEnforcement's dial-loop-and-drain pattern
// against the LSM deny ringbuf. If no matching deny event arrives within
// timeout, the LSM programs are attached but the kernel never invokes them —
// returns true (silent).
//
// Ubuntu 24.04 ships with `lsm=lockdown,yama,apparmor` by default; `bpf` is
// missing from the boot chain, so AttachLSM succeeds but
// `security_socket_connect` / `security_socket_sendmsg` never dispatch to
// our SEC("lsm/...") programs. The cgroup `connect4` / `sendmsg4` hooks are
// unaffected — they remain the load-bearing enforcement path on these
// kernels. This probe lets the digest report that posture honestly via a
// `lsm_attached_but_silent` BPFStatus row and a `defend+cgroup` mode label
// instead of advertising LSM defense that does not exist. To restore LSM
// dispatch on these distros, the operator must boot with the `bpf` token
// in the kernel `lsm=` parameter (e.g.
// `lsm=lockdown,yama,bpf,apparmor`).
//
// The dial loop's connects that get denied by cgroup (because LSM is silent
// and cgroup is the one firing) land in the cgroup ringbuf and are processed
// by the main agent reader later as background self-denies; that noise is
// bounded by lsmProbeTimeout (≤ ~30 connects at the 50ms retry tick).
func probeLSMSilent(rd *ringbuf.Reader, timeout time.Duration) bool {
	if rd == nil {
		// No LSM ringbuf reader to observe — treat as silent so the caller
		// downgrades the label rather than claiming LSM defense.
		return true
	}
	if timeout <= 0 {
		timeout = lsmProbeTimeout
	}
	deadline := time.Now().Add(timeout)

	stop := make(chan struct{})
	defer close(stop)
	go runProbeDialLoop(stop, deadline)

	rd.SetDeadline(deadline)
	defer rd.SetDeadline(time.Time{})

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return true
			}
			// Reader error other than deadline (e.g. closed) — treat as
			// silent so the caller errs on the side of honesty about
			// LSM's contribution to enforcement.
			return true
		}
		if matchProbeDenyEvent(rec.RawSample) {
			return false
		}
		// Non-probe deny event during startup — drain and keep waiting,
		// matching probeDefendEnforcement's behaviour.
	}
}

// matchProbeDenyEvent reports whether a deny ringbuf payload corresponds to a
// probeDefendEnforcement probe (TCP, AF_INET, daddr=probeDefendDst, dport=probeDefendDport).
// Split out as a pure function so the matcher can be unit-tested without ringbuf infra.
func matchProbeDenyEvent(raw []byte) bool {
	if len(raw) < denyEventWireSize {
		return false
	}
	protocol := raw[24]
	af := raw[26]
	dport := binary.BigEndian.Uint16(raw[44:46])
	if protocol != denyProtoTCP || af != uint8(linuxAFInet) || dport != probeDefendDport {
		return false
	}
	ip4 := probeDefendDst.To4()
	return raw[28] == ip4[0] && raw[29] == ip4[1] && raw[30] == ip4[2] && raw[31] == ip4[3]
}
