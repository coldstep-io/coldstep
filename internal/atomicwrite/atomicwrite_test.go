package atomicwrite

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBytesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.txt")
	if err := Bytes(p, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "hello\n" {
		t.Fatalf("got %q", raw)
	}
}

func TestBytesReplaceExisting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	if err := os.WriteFile(p, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Bytes(p, []byte("bb"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if string(raw) != "bb" {
		t.Fatalf("got %q", raw)
	}
}
