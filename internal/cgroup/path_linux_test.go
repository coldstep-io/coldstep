//go:build linux

package cgroup

import (
	"path/filepath"
	"testing"
)

func TestAttachPath_linux_default(t *testing.T) {
	got, err := AttachPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("empty attach path")
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("want absolute path, got %q", got)
	}
}

// TestAttachPath_linux_root verifies that the default attach path is the cgroup v2
// root (/sys/fs/cgroup), not a sub-cgroup derived from /proc/self/cgroup.
// This ensures the BPF program covers ALL job-step processes on GitHub-hosted runners,
// which may run in different cgroups than the coldstep agent (root via sudo).
func TestAttachPath_linux_root(t *testing.T) {
	got, err := AttachPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/sys/fs/cgroup" {
		t.Fatalf("default attach path = %q, want /sys/fs/cgroup (root cgroup)", got)
	}
}

func TestAttachPath_linux_override(t *testing.T) {
	dir := t.TempDir()
	got, err := AttachPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, werr := filepath.Abs(dir)
	if werr != nil {
		t.Fatal(werr)
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
