//go:build linux

package defend

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// LoadDefendObjectsForKernel populates obj with the cgroup defend programs
// + shared/cgroup maps unconditionally, plus the LSM programs + LSM-only
// maps when wantLSM is true.
//
// On kernels without CONFIG_BPF_LSM the LSM section would be rejected at
// prog_load, so we strip those programs from the CollectionSpec first.
// We also strip the LSM-only maps in that case so we don't waste a 16 MiB
// ringbuf nobody reads from.
//
// Caller is responsible for closing obj on shutdown.
func LoadDefendObjectsForKernel(obj *DefendObjects, wantLSM bool) error {
	spec, err := LoadDefend()
	if err != nil {
		return err
	}

	if !wantLSM {
		delete(spec.Programs, "lsm_socket_connect")
		delete(spec.Programs, "lsm_socket_sendmsg")
		delete(spec.Maps, "lsm_deny_events")
		delete(spec.Maps, "lsm_deny_reserve_failures")
		delete(spec.Maps, "lsm_defend_cfg")
		delete(spec.Maps, "lsm_allowed_ipv4")
		delete(spec.Maps, "lsm_ignored_ipv4_lpm")
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
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
			return err
		}
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
			return err
		}
	}

	if wantLSM {
		lsmPrograms := []struct {
			name string
			dst  **ebpf.Program
		}{
			{"lsm_socket_connect", &obj.LsmSocketConnect},
			{"lsm_socket_sendmsg", &obj.LsmSocketSendmsg},
		}
		for _, p := range lsmPrograms {
			if err := detachProgram(coll, p.name, p.dst); err != nil {
				return err
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
				return err
			}
		}
	}

	success = true
	return nil
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
