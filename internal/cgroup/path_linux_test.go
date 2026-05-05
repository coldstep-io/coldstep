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
