//go:build linux

package agent

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/coldstep-io/coldstep/internal/policy"
)

// autoAllowSystemResolvers must fold non-loopback resolv.conf nameservers into
// the compiled defend allowlist per family — this is the userspace half of the
// hosted-runner DNS fix (the BPF loopback bypass covers the 127.0.0.53 stub
// hop; this covers resolved's upstream hop to the platform resolver).
func TestAutoAllowSystemResolvers_MergesIntoCompiledSets(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "etc-resolv.conf")
	upstream := filepath.Join(dir, "resolved-resolv.conf")
	if err := os.WriteFile(stub, []byte("nameserver 127.0.0.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(upstream, []byte("nameserver 168.63.129.16\nnameserver 2620:fe::fe\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	compiled := policy.CompileResult{}
	v4, v6 := autoAllowSystemResolvers(&compiled, upstream, stub)

	if len(v4) != 1 || v4[0].String() != "168.63.129.16" {
		t.Errorf("v4 = %v, want [168.63.129.16] (loopback stub dropped)", v4)
	}
	if len(v6) != 1 || v6[0].String() != "2620:fe::fe" {
		t.Errorf("v6 = %v, want [2620:fe::fe]", v6)
	}
	if !compiled.AllowedIPv4.Contains(net.ParseIP("168.63.129.16")) {
		t.Error("AllowedIPv4 missing auto-allowed platform resolver 168.63.129.16")
	}
	if compiled.AllowedIPv4.Contains(net.ParseIP("127.0.0.53")) {
		t.Error("AllowedIPv4 must not contain the loopback stub (BPF bypasses loopback)")
	}
	if !compiled.AllowedIPv6.Contains(net.ParseIP("2620:fe::fe")) {
		t.Error("AllowedIPv6 missing auto-allowed IPv6 resolver")
	}
}

func TestAutoAllowSystemResolvers_NoFilesIsNoop(t *testing.T) {
	compiled := policy.CompileResult{}
	v4, v6 := autoAllowSystemResolvers(&compiled, filepath.Join(t.TempDir(), "missing.conf"))
	if len(v4)+len(v6) != 0 {
		t.Errorf("expected no resolvers, got v4=%v v6=%v", v4, v6)
	}
	if compiled.AllowedIPv4.Len() != 0 || compiled.AllowedIPv6.Len() != 0 {
		t.Errorf("compiled sets must stay empty, got v4=%d v6=%d", compiled.AllowedIPv4.Len(), compiled.AllowedIPv6.Len())
	}
}
