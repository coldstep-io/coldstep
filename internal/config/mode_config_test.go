//go:build !windows

// Go tests are not built or run on Windows (out of scope; avoids Smart App Control blocking
// unsigned *.test.exe). Authoritative runs: GitHub Actions ubuntu-latest.

package config

import "testing"

func TestModeConfig_Defend(t *testing.T) {
	mc := Config{Mode: ModeDefend}.ModeConfig()
	if !mc.Defend {
		t.Fatalf("Defend = false, want true")
	}
	if mc.Detect {
		t.Fatalf("Detect = true, want false")
	}
	for name, got := range map[string]bool{
		"AllowlistEnforced": mc.AllowlistEnforced,
		"DenyEmitted":       mc.DenyEmitted,
		"DeferReadiness":    mc.DeferReadiness,
		"ResolverAutoAllow": mc.ResolverAutoAllow,
	} {
		if !got {
			t.Errorf("%s = false, want true in defend mode", name)
		}
	}
}

func TestModeConfig_Detect(t *testing.T) {
	mc := Config{Mode: ModeDetect}.ModeConfig()
	if mc.Defend {
		t.Fatalf("Defend = true, want false")
	}
	if !mc.Detect {
		t.Fatalf("Detect = false, want true")
	}
	for name, got := range map[string]bool{
		"AllowlistEnforced": mc.AllowlistEnforced,
		"DenyEmitted":       mc.DenyEmitted,
		"DeferReadiness":    mc.DeferReadiness,
		"ResolverAutoAllow": mc.ResolverAutoAllow,
	} {
		if got {
			t.Errorf("%s = true, want false in detect mode", name)
		}
	}
}

func TestModeConfig_ResolverAutoAllowOptOut(t *testing.T) {
	// Defend mode normally auto-allows resolver IPs; NoResolverAutoAllow opts out.
	mc := Config{Mode: ModeDefend, NoResolverAutoAllow: true}.ModeConfig()
	if !mc.Defend {
		t.Fatalf("Defend = false, want true")
	}
	if mc.ResolverAutoAllow {
		t.Errorf("ResolverAutoAllow = true, want false when NoResolverAutoAllow is set")
	}
	// Other defend flags are unaffected by the resolver opt-out.
	if !mc.AllowlistEnforced || !mc.DenyEmitted || !mc.DeferReadiness {
		t.Errorf("resolver opt-out must not disable enforcement flags: %+v", mc)
	}
}
