//go:build linux

package defend

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// LoadResult carries non-error outcomes from LoadDefendObjectsForKernel that
// the caller needs to surface in telemetry — primarily that wantLSM=true was
// requested but the LSM section had to be stripped after a prog_load failure
// so the cgroup-only path could still load.
type LoadResult struct {
	// LSMFellBack is true when wantLSM=true was requested but prog_load
	// rejected the LSM section for a reason other than the kernel-6.5+
	// socket_sendpage removal (which is handled silently), so the loader
	// stripped all LSM programs and reloaded the cgroup-only collection.
	// Callers should set their local haveLSM bool to false in this case,
	// skip LSM attach, and emit a `lsm_load_failed_fallback_cgroup`
	// BPFStatus row so the digest records the degraded posture.
	LSMFellBack bool

	// LSMFallbackErr is the original prog_load error that triggered the
	// fallback. Empty when LSMFellBack is false.
	LSMFallbackErr error
}

// LoadDefendObjectsForKernel populates obj with the cgroup defend programs
// + shared/cgroup maps unconditionally, plus the LSM programs + LSM-only
// maps when wantLSM is true.
//
// On kernels without CONFIG_BPF_LSM the LSM section would be rejected at
// prog_load, so we strip those programs from the CollectionSpec first.
// We also strip the LSM-only maps in that case so we don't waste a 16 MiB
// ringbuf nobody reads from.
//
// The lsm/io_uring_cmd hook (H15) needs `security_uring_cmd` in the
// kernel BTF (added in Linux 5.19). When wantLSM is true but
// wantIOUringLSM is false, only that one program is stripped — the
// other LSM hooks still load. Callers should compute wantIOUringLSM via
// HaveIOUringLSM().
//
// Return contract: a nil error means obj is populated and ready to be
// closed by the caller. The returned LoadResult reports whether the LSM
// section had to be stripped after a prog_load failure (LSMFellBack); when
// true, the caller MUST treat haveLSM as false (do not attempt LSM attach)
// and emit a `lsm_load_failed_fallback_cgroup` BPFStatus row. A non-nil
// error means obj is untouched and the cgroup-only fallback could not be
// constructed either — defend cannot start.
//
// Caller is responsible for closing obj on shutdown.
func LoadDefendObjectsForKernel(obj *DefendObjects, wantLSM, wantIOUringLSM bool) (LoadResult, error) {
	spec, err := LoadDefend()
	if err != nil {
		return LoadResult{}, err
	}

	if !wantLSM {
		stripAllLSM(spec)
	} else {
		if !kernelHasLSMHook("socket_sendpage") {
			// Kernel 6.5+ removed the socket_sendpage LSM hook (proto_ops
			// ->sendpage and security_socket_sendpage were dropped together).
			// On those kernels sendfile(2)/splice(2) route through sendmsg
			// with MSG_SPLICE_PAGES, so cgroup/sendmsg4 + lsm/socket_sendmsg
			// already cover them. Leaving the program in the spec would fail
			// prog_load (ENOENT on the BTF attach target) and bring down the
			// whole defend collection. The sendpage_observed counter is also
			// stripped because nothing will write to it.
			delete(spec.Programs, "lsm_socket_sendpage")
			delete(spec.Maps, "sendpage_observed")
		}
		if !wantIOUringLSM {
			// Kernel has CONFIG_BPF_LSM but no security_uring_cmd BTF symbol
			// (pre-5.19) — drop just the io_uring_cmd program so prog_load
			// for the rest of the LSM section can still succeed. LSM-only
			// maps stay because lsm_socket_connect / lsm_socket_sendmsg
			// still use them.
			delete(spec.Programs, "lsm_io_uring_cmd")
		}
	}

	result := LoadResult{}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// Defensive fallback: BTF lookup may have succeeded but prog_load
		// still rejected sendpage for some other reason (BTF mismatch,
		// CONFIG_SECURITY_NETWORK off, etc.). Strip the program and retry
		// once so the rest of the LSM section still loads.
		if wantLSM && isSendpageLoadFailure(err) {
			spec2, err2 := LoadDefend()
			if err2 != nil {
				return LoadResult{}, err2
			}
			delete(spec2.Programs, "lsm_socket_sendpage")
			delete(spec2.Maps, "sendpage_observed")
			coll, err = ebpf.NewCollection(spec2)
		} else if wantLSM {
			// Non-sendpage LSM load failure (e.g. CONFIG_BPF_LSM absent
			// despite features.HaveProgramType(ebpf.LSM) returning ok,
			// `lsm=` boot chain without bpf, BTF mismatch on one of the
			// other LSM hooks). Before this fallback, any such failure
			// killed the whole defend collection and forced detect-mode-
			// only operation, even though the cgroup path is independent.
			// Strip every LSM section and reload — the cgroup connect4 /
			// sendmsg4 enforcement still works.
			origLoadErr := err
			spec2, err2 := LoadDefend()
			if err2 != nil {
				return LoadResult{}, err2
			}
			stripAllLSM(spec2)
			coll, err = ebpf.NewCollection(spec2)
			if err == nil {
				result.LSMFellBack = true
				result.LSMFallbackErr = origLoadErr
			}
		}
		if err != nil {
			return LoadResult{}, err
		}
	}
	success := false
	defer func() {
		if !success {
			coll.Close()
		}
	}()

	cgPrograms := []struct {
		name string
		dst  **ebpf.Program
	}{
		{"defend_connect4", &obj.DefendConnect4},
		{"defend_sendmsg4", &obj.DefendSendmsg4},
	}
	for _, p := range cgPrograms {
		if err := detachProgram(coll, p.name, p.dst); err != nil {
			return LoadResult{}, err
		}
	}

	// P0-1 Phase 1: IPv6 observe-only programs. Detach when present in the
	// generated spec; tolerate absence so kernels (or generated stubs)
	// without these sections still load the IPv4 path.
	// TODO: remove the missing-program tolerance once defend objects are
	// regenerated on Linux and the cgroup/connect6 + cgroup/sendmsg6
	// sections are guaranteed in the embedded ELF.
	cgIPv6Programs := []struct {
		name string
		dst  **ebpf.Program
	}{
		{"defend_cgroup_connect6", &obj.DefendCgroupConnect6},
		{"defend_cgroup_sendmsg6", &obj.DefendCgroupSendmsg6},
	}
	for _, p := range cgIPv6Programs {
		detachProgramIfPresent(coll, p.name, p.dst)
	}

	cgAndSharedMaps := []struct {
		name string
		dst  **ebpf.Map
	}{
		{"deny_events", &obj.DenyEvents},
		{"deny_reserve_failures", &obj.DenyReserveFailures},
		{"defend_cfg", &obj.DefendCfg},
		{"allowed_ipv4", &obj.AllowedIpv4},
		{"ignored_ipv4_lpm", &obj.IgnoredIpv4Lpm},
		{"allowed_domains", &obj.AllowedDomains},
		{"dns_cache", &obj.DnsCache},
	}
	for _, m := range cgAndSharedMaps {
		if err := detachMap(coll, m.name, m.dst); err != nil {
			return LoadResult{}, err
		}
	}

	// P0-1 Phase 1: IPv6 observe counters. Optional in older generated
	// stubs; tolerate absence so the cgroup IPv4 path keeps loading.
	// TODO: remove the missing-map tolerance once defend objects are
	// regenerated on Linux with bpf/trace_defend_cgroup.inc's
	// ipv6_connect_observed / ipv6_sendmsg_observed maps.
	cgIPv6Maps := []struct {
		name string
		dst  **ebpf.Map
	}{
		{"ipv6_connect_observed", &obj.Ipv6ConnectObserved},
		{"ipv6_sendmsg_observed", &obj.Ipv6SendmsgObserved},
	}
	for _, m := range cgIPv6Maps {
		detachMapIfPresent(coll, m.name, m.dst)
	}

	// P2-1 Phase 2: IPv6 allowlist LPM trie. Optional in older generated
	// stubs (same regeneration window as the connect6/sendmsg6 enforcement
	// path). When absent, defend mode still loads but cgroup/connect6 and
	// cgroup/sendmsg6 fall back to Phase 1 observe-only behaviour because
	// the bpf2go binding's defend_cgroup_connect6 program reference will
	// also be missing.
	// TODO: remove the missing-map tolerance once defend objects are
	// regenerated on Linux with bpf/trace_defend_cgroup.inc's
	// allowed_ipv6 map.
	detachMapIfPresent(coll, "allowed_ipv6", &obj.AllowedIpv6)

	// Sub-project A: tc/clsact egress backstop (observe-only). The program is
	// attached via TCX per-interface by the agent; here we just lift the program
	// + its maps out of the collection into obj. Optional (tolerate absence on
	// stubs predating the section) — the backstop is observe-only, never an
	// enforcement primitive, so a missing one degrades to "no backstop" rather
	// than failing defend startup.
	detachProgramIfPresent(coll, "defend_skb_egress", &obj.DefendSkbEgress)
	detachMapIfPresent(coll, "skb_backstop_events", &obj.SkbBackstopEvents)
	detachMapIfPresent(coll, "skb_backstop_reserve_failures", &obj.SkbBackstopReserveFailures)
	detachMapIfPresent(coll, "skb_backstop_seen", &obj.SkbBackstopSeen)

	// LSM section: present only when wantLSM was requested AND the fallback
	// reload did not strip it. After a fallback, every LSM program/map was
	// removed from the spec before NewCollection, so detachProgram would
	// fail with "missing program" — skip the whole block.
	if wantLSM && !result.LSMFellBack {
		lsmPrograms := []struct {
			name string
			dst  **ebpf.Program
		}{
			{"lsm_socket_connect", &obj.LsmSocketConnect},
			{"lsm_socket_sendmsg", &obj.LsmSocketSendmsg},
		}
		for _, p := range lsmPrograms {
			if err := detachProgram(coll, p.name, p.dst); err != nil {
				return LoadResult{}, err
			}
		}
		if wantIOUringLSM {
			if err := detachProgram(coll, "lsm_io_uring_cmd", &obj.LsmIoUringCmd); err != nil {
				return LoadResult{}, err
			}
		}
		lsmMaps := []struct {
			name string
			dst  **ebpf.Map
		}{
			{"lsm_deny_events", &obj.LsmDenyEvents},
			{"lsm_deny_reserve_failures", &obj.LsmDenyReserveFailures},
			{"lsm_defend_cfg", &obj.LsmDefendCfg},
			{"lsm_allowed_ipv4", &obj.LsmAllowedIpv4},
			{"lsm_ignored_ipv4_lpm", &obj.LsmIgnoredIpv4Lpm},
		}
		for _, m := range lsmMaps {
			if err := detachMap(coll, m.name, m.dst); err != nil {
				return LoadResult{}, err
			}
		}

		// Sendfile/splice gap (kernel 5.15): lsm/socket_sendpage and its
		// observe-only counter. Optional in older generated stubs; tolerate
		// absence so existing LSM-enabled kernels still load the connect +
		// sendmsg path.
		// TODO: remove the missing-program tolerance once defend objects are
		// regenerated on Linux with bpf/trace_lsm_defend_lsm.inc's
		// lsm_socket_sendpage section and sendpage_observed map.
		detachProgramIfPresent(coll, "lsm_socket_sendpage", &obj.LsmSocketSendpage)
		detachMapIfPresent(coll, "sendpage_observed", &obj.SendpageObserved)
	}

	success = true
	return result, nil
}

// stripAllLSM removes every LSM program and LSM-only map from the spec so
// the resulting collection loads on kernels without CONFIG_BPF_LSM (or with
// `lsm=` boot chains that omit bpf). Shared between the wantLSM=false
// initial path and the wantLSM=true post-load fallback.
func stripAllLSM(spec *ebpf.CollectionSpec) {
	delete(spec.Programs, "lsm_socket_connect")
	delete(spec.Programs, "lsm_socket_sendmsg")
	// lsm_socket_sendpage closes the sendfile/splice gap (kernel 5.15);
	// the program is only present after the BPF stubs have been
	// regenerated on Linux with the new SEC, hence the silent delete.
	delete(spec.Programs, "lsm_socket_sendpage")
	delete(spec.Programs, "lsm_io_uring_cmd")
	delete(spec.Maps, "lsm_deny_events")
	delete(spec.Maps, "lsm_deny_reserve_failures")
	delete(spec.Maps, "lsm_defend_cfg")
	delete(spec.Maps, "lsm_allowed_ipv4")
	delete(spec.Maps, "lsm_ignored_ipv4_lpm")
	// sendpage_observed lives in the LSM section; strip it when LSM is
	// disabled so we don't pin a per-cpu counter nobody reads.
	delete(spec.Maps, "sendpage_observed")
}

// HaveIOUringLSM reports whether the running kernel exposes the
// `bpf_lsm_io_uring_cmd` BPF LSM dispatch target — required by H15's
// SEC("lsm/io_uring_cmd") program for both prog_load and attach.
// Probing `bpf_lsm_<hook>` (rather than `security_uring_cmd` alone)
// covers kernels that have the C-side LSM hook in BTF but do not
// expose it to BPF LSM (CONFIG_BPF_LSM off or "bpf" missing from the
// kernel `lsm=` boot chain). Returns false on any BTF lookup failure
// so callers degrade safely to the older LSM hook set.
func HaveIOUringLSM() bool {
	return kernelHasLSMHook("io_uring_cmd")
}

func detachProgram(coll *ebpf.Collection, name string, dst **ebpf.Program) error {
	p, ok := coll.Programs[name]
	if !ok {
		return fmt.Errorf("missing program %q in defend collection", name)
	}
	*dst = p
	delete(coll.Programs, name)
	return nil
}

func detachMap(coll *ebpf.Collection, name string, dst **ebpf.Map) error {
	m, ok := coll.Maps[name]
	if !ok {
		return fmt.Errorf("missing map %q in defend collection", name)
	}
	*dst = m
	delete(coll.Maps, name)
	return nil
}

// detachProgramIfPresent moves a program out of the collection into dst
// when present. Missing programs are silently ignored — used for optional
// observe-only paths (e.g. IPv6 hooks) so a stub built without them still
// loads the rest of the defend collection.
func detachProgramIfPresent(coll *ebpf.Collection, name string, dst **ebpf.Program) {
	if p, ok := coll.Programs[name]; ok {
		*dst = p
		delete(coll.Programs, name)
	}
}

// detachMapIfPresent is the map analogue of detachProgramIfPresent.
func detachMapIfPresent(coll *ebpf.Collection, name string, dst **ebpf.Map) {
	if m, ok := coll.Maps[name]; ok {
		*dst = m
		delete(coll.Maps, name)
	}
}

// kernelHasLSMHook reports whether the running kernel's BTF declares
// bpf_lsm_<name>, indicating the LSM hook is attachable. Returns false
// when kernel BTF cannot be loaded or the symbol is absent — caller
// should treat false as "do not load this hook".
func kernelHasLSMHook(name string) bool {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return false
	}
	var fn *btf.Func
	return spec.TypeByName("bpf_lsm_"+name, &fn) == nil
}

// isSendpageLoadFailure detects an ebpf.NewCollection error that represents
// prog_load rejection of lsm_socket_sendpage specifically. Used as a
// defensive fallback when the BTF pre-check missed the kernel's removal of
// the hook.
//
// Two signals are required, not one:
//
//  1. The error chain names the sendpage program/hook. The failing program
//     name ("lsm_socket_sendpage") only appears in cilium/ebpf's
//     "program <name>: ..." wrap, so a substring check is the only way to
//     attribute the failure to this program rather than another LSM hook.
//
//  2. The error is a recognized structured load failure. On kernel 6.5+ the
//     missing bpf_lsm_socket_sendpage BTF target surfaces as btf.ErrNotFound
//     (prog_load fails at attach-target resolution before the verifier runs,
//     so it is NOT an *ebpf.VerifierError); a genuine verifier rejection
//     surfaces as *ebpf.VerifierError. Accept either.
//
// Requiring both guards against stripping sendpage on an unrelated error that
// merely happens to contain the substring, while still firing for the real
// 6.5+ removal case that pure VerifierError matching would miss.
func isSendpageLoadFailure(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	if !strings.Contains(s, "lsm_socket_sendpage") && !strings.Contains(s, "socket_sendpage") {
		return false
	}
	var ve *ebpf.VerifierError
	return errors.Is(err, btf.ErrNotFound) || errors.As(err, &ve)
}
