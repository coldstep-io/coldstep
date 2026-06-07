package policy

import (
	"net"
	"testing"
)

func TestEgressBackstopBypasses(t *testing.T) {
	cases := []struct {
		ip   string
		want bool // true => bypasses the backstop (loopback/link-local; never emitted)
	}{
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		{"::1", true},
		{"fe80::1", true},
		{"203.0.113.7", false},
		{"198.51.100.9", false},
		{"2606:4700:4700::1111", false},
	}
	for _, c := range cases {
		got := EgressBackstopBypasses(net.ParseIP(c.ip))
		if got != c.want {
			t.Errorf("EgressBackstopBypasses(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}
