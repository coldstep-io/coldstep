package policy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeResolvConf(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// The hosted-runner shape: /etc/resolv.conf points at the systemd-resolved
// stub (loopback, dropped — BPF bypasses loopback) while the resolved
// upstream file carries the Azure platform resolver that must be allowed.
func TestSystemResolverIPs_HostedRunnerShape(t *testing.T) {
	etc := writeResolvConf(t, "etc-resolv.conf", strings.Join([]string{
		"# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).",
		"nameserver 127.0.0.53",
		"options edns0 trust-ad",
		"search example.internal",
	}, "\n"))
	upstream := writeResolvConf(t, "resolved-resolv.conf", strings.Join([]string{
		"nameserver 168.63.129.16",
		"search example.internal",
	}, "\n"))

	v4, v6 := SystemResolverIPs(upstream, etc)
	if got, want := ipStrings(v4), []string{"168.63.129.16"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("v4 = %v, want %v (stub 127.0.0.53 must be dropped)", got, want)
	}
	if len(v6) != 0 {
		t.Errorf("v6 = %v, want empty", ipStrings(v6))
	}
}

func TestSystemResolverIPs_DedupAcrossFilesAndFamilies(t *testing.T) {
	a := writeResolvConf(t, "a.conf", strings.Join([]string{
		"nameserver 10.0.0.2",
		"nameserver 2620:fe::fe",
		"; comment",
		"nameserver 10.0.0.2",
	}, "\n"))
	b := writeResolvConf(t, "b.conf", strings.Join([]string{
		"nameserver 10.0.0.2",
		"nameserver 192.168.1.1",
		"nameserver ::1",
	}, "\n"))

	v4, v6 := SystemResolverIPs(a, b)
	if got, want := ipStrings(v4), []string{"10.0.0.2", "192.168.1.1"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("v4 = %v, want %v", got, want)
	}
	if got, want := ipStrings(v6), []string{"2620:fe::fe"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("v6 = %v, want %v (::1 loopback must be dropped)", got, want)
	}
}

func TestSystemResolverIPs_SkipsGarbageAndMissingFiles(t *testing.T) {
	conf := writeResolvConf(t, "garbage.conf", strings.Join([]string{
		"nameserver",                  // missing address
		"nameserver not-an-ip",        // unparsable
		"nameserver fe80::1%eth0",     // zone suffix — rejected by ParseIP, link-local bypasses in BPF anyway
		"nameservers 8.8.8.8",         // wrong keyword
		"domain example.com",          //
		"nameserver 9.9.9.9 trailing", // extra fields tolerated
	}, "\n"))

	v4, v6 := SystemResolverIPs(filepath.Join(t.TempDir(), "missing.conf"), conf)
	if got, want := ipStrings(v4), []string{"9.9.9.9"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("v4 = %v, want %v", got, want)
	}
	if len(v6) != 0 {
		t.Errorf("v6 = %v, want empty", ipStrings(v6))
	}
}

func TestSystemResolverIPs_CapsEntries(t *testing.T) {
	lines := make([]string, 0, maxSystemResolvers+4)
	for i := 1; i <= maxSystemResolvers+4; i++ {
		lines = append(lines, fmt.Sprintf("nameserver 10.1.2.%d", i))
	}
	conf := writeResolvConf(t, "many.conf", strings.Join(lines, "\n"))

	v4, v6 := SystemResolverIPs(conf)
	if len(v4)+len(v6) != maxSystemResolvers {
		t.Errorf("got %d resolvers, want cap %d", len(v4)+len(v6), maxSystemResolvers)
	}
}
