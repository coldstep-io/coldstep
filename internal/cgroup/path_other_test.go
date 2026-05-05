//go:build !linux

package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAttachPath_nonLinux_default(t *testing.T) {
	p, err := AttachPath("")
	if err != nil {
		t.Fatal(err)
	}
	if p != "/sys/fs/cgroup" {
		t.Fatalf("got %q", p)
	}
}

func TestAttachPath_override(t *testing.T) {
	dir := t.TempDir()
	got, err := AttachPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.Abs(dir)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAttachPath_override_notDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AttachPath(file); err == nil {
		t.Fatal("expected error for non-directory override")
	}
}
