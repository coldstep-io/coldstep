package policy

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// maxSystemResolvers bounds how many auto-allowed resolver addresses a
// resolv.conf scan can contribute. glibc honors at most 3 nameserver lines
// (MAXNS); systemd-resolved can list more upstreams. The cap keeps a
// hostile or pathological resolv.conf from inflating the defend allowlist.
const maxSystemResolvers = 8

// DefaultResolvConfPaths returns the resolv.conf files consulted by
// SystemResolverIPs, most-authoritative first. On systemd-resolved hosts
// (GitHub-hosted ubuntu runners) /etc/resolv.conf names only the local stub
// 127.0.0.53, while /run/systemd/resolve/resolv.conf lists the real
// upstreams the stub forwards to (the Azure platform resolver 168.63.129.16
// on hosted runners) — both hops must work for getaddrinfo to succeed in
// defend mode. Missing files are skipped by the parser.
func DefaultResolvConfPaths() []string {
	return []string{
		"/run/systemd/resolve/resolv.conf",
		"/etc/resolv.conf",
	}
}

// SystemResolverIPs parses resolv.conf-format files and returns the unique
// non-loopback nameserver addresses, split by family, in first-seen order.
// Loopback entries (the systemd-resolved stub 127.0.0.53, ::1) are dropped:
// the BPF defend hooks bypass loopback unconditionally, so allowlisting them
// is unnecessary. Unreadable files and unparsable lines are skipped — this
// feeds a best-effort auto-allow, not a hard requirement.
//
// Used by the agent in defend mode to treat the host's configured DNS
// resolvers as infrastructure: without their IPs in the allowlist every
// workload getaddrinfo fails with EAI_AGAIN on hosted runners, because the
// platform resolver is a public IP outside the default ignored nets and no
// documented allow: entry covers the stub-forwarding hop.
func SystemResolverIPs(paths ...string) (v4 []net.IP, v6 []net.IP) {
	seen := make(map[string]struct{})
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			// resolv.conf permits a %zone suffix on link-local v6
			// nameservers; net.ParseIP rejects it, which is fine —
			// link-local already bypasses enforcement in BPF.
			ip := net.ParseIP(fields[1])
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if _, dup := seen[ip.String()]; dup {
				continue
			}
			if len(seen) >= maxSystemResolvers {
				continue
			}
			seen[ip.String()] = struct{}{}
			if ip.To4() != nil {
				v4 = append(v4, ip)
			} else {
				v6 = append(v6, ip)
			}
		}
		_ = f.Close()
	}
	return v4, v6
}
