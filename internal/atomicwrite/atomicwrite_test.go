package atomicwrite

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestBytesEmptyPath(t *testing.T) {
	if err := Bytes("", []byte("x"), 0o644); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestBytesNonzeroPerm(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "perm.bin")
	if err := Bytes(p, []byte("data"), 0o640); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	// Windows does not preserve Unix chmod bits the same way as Linux.
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o777 != 0o640 {
		t.Fatalf("mode %v want 0640", st.Mode())
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
