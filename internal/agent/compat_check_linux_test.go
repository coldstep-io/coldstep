//go:build linux

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

// TestCheckRunnerCompat_NoPanic is a basic smoke test: the public entry point
// must not panic on a normal CI runner, even when /sys/fs/cgroup, /.dockerenv,
// or /proc/1/cgroup are in unexpected states.
func TestCheckRunnerCompat_NoPanic(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CheckRunnerCompat panicked: %v", r)
		}
	}()
	_ = CheckRunnerCompat()
}

func TestCheckRunnerCompatAt_CgroupV1Warning(t *testing.T) {
	t.Parallel()
	// Pointing cgroupRoot at a tmp dir whose statfs reports tmpfs (not
	// cgroup2) is enough to trigger the cgroup_v1_detected branch.
	tmp := t.TempDir()
	got := checkRunnerCompatAt(compatPaths{
		cgroupRoot: tmp,
		dockerenv:  filepath.Join(tmp, "no-dockerenv-here"),
		init1CgroupFn: func() (string, error) {
			return "0::/\n", nil
		},
	})
	if !hasCompatCode(got, CompatCodeCgroupV1Detected) {
		t.Fatalf("expected %s warning, got %+v", CompatCodeCgroupV1Detected, got)
	}
}

func TestCheckRunnerCompatAt_ContainerNonDelegated(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	dockerenv := filepath.Join(tmp, ".dockerenv")
	if err := os.WriteFile(dockerenv, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got := checkRunnerCompatAt(compatPaths{
		cgroupRoot: tmp,
		dockerenv:  dockerenv,
		init1CgroupFn: func() (string, error) {
			return "0::/docker/abc123def456/runner.scope\n", nil
		},
	})
	if !hasCompatCode(got, CompatCodeCgroupNamespaceNonDeleg) {
		t.Fatalf("expected %s warning, got %+v", CompatCodeCgroupNamespaceNonDeleg, got)
	}
}

func TestCheckRunnerCompatAt_DeepNesting(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	got := checkRunnerCompatAt(compatPaths{
		cgroupRoot: tmp,
		dockerenv:  filepath.Join(tmp, "no-dockerenv-here"),
		init1CgroupFn: func() (string, error) {
			return "0::/a/b/c/d/e\n", nil
		},
	})
	if !hasCompatCode(got, CompatCodeDeepCgroupNesting) {
		t.Fatalf("expected %s warning, got %+v", CompatCodeDeepCgroupNesting, got)
	}
}

func TestCheckRunnerCompatAt_ContainerCgroupReadFails(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	dockerenv := filepath.Join(tmp, ".dockerenv")
	if err := os.WriteFile(dockerenv, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got := checkRunnerCompatAt(compatPaths{
		cgroupRoot: tmp,
		dockerenv:  dockerenv,
		init1CgroupFn: func() (string, error) {
			return "", errors.New("simulated read error")
		},
	})
	if !hasCompatCode(got, CompatCodeContainerCgroupDetection) {
		t.Fatalf("expected %s warning, got %+v", CompatCodeContainerCgroupDetection, got)
	}
}

func TestCgroupNamespaceDelegated(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"root", "0::/\n", true},
		{"init scope", "0::/init.scope\n", true},
		{"docker prefix", "0::/docker/abc/runner.scope\n", false},
		{"kubepods prefix", "0::/kubepods/burstable/podabc/container\n", false},
		{"system slice docker", "0::/system.slice/docker-abc.scope\n", false},
		{"lxc", "0::/lxc/container1\n", false},
		{"multi line one bad", "0::/\n1::cpu:/docker/abc/foo\n", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := cgroupNamespaceDelegated(tc.in)
			if got != tc.want {
				t.Fatalf("cgroupNamespaceDelegated(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestInit1CgroupMaxDepth(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{"root only", "0::/\n", 0},
		{"single level", "0::/foo\n", 1},
		{"trailing slash ignored", "0::/foo/bar/\n", 2},
		{"max across lines", "0::/a\n1::cpu:/x/y/z\n", 3},
		{"empty", "", 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := init1CgroupMaxDepth(func() (string, error) { return tc.content, nil })
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Fatalf("init1CgroupMaxDepth(%q) = %d, want %d", tc.content, got, tc.want)
			}
		})
	}
}

func hasCompatCode(ws []telemetry.CompatWarning, code string) bool {
	for _, w := range ws {
		if w.Code == code {
			return true
		}
	}
	return false
}
