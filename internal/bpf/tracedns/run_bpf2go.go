//go:build ignore

// run_bpf2go.go — generate-time helper for tracedns. See
// internal/bpf/traceconnect/run_bpf2go.go for the rationale (per-arch
// `-D__TARGET_ARCH_*` cflag derived from runtime.GOARCH that cannot be
// expressed concisely in a single `//go:generate` line).
package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	pkgDir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	repoRoot := filepath.Clean(filepath.Join(pkgDir, "..", "..", ".."))

	archFlag := "-D__TARGET_ARCH_x86"
	if runtime.GOARCH == "arm64" {
		archFlag = "-D__TARGET_ARCH_arm64"
	}

	cflags := archFlag +
		" -O2 -g -Wall -Werror" +
		" -I" + filepath.Join(repoRoot, "bpf") +
		" -I/usr/include/bpf"
	extra := []string{
		"-I" + filepath.Join(repoRoot, "bpf"),
		"-I/usr/include/bpf",
	}

	args := []string{
		"run", "github.com/cilium/ebpf/cmd/bpf2go@v0.21.0",
		"-cc", "clang",
		"-no-strip",
		"-target", "bpfel,bpfeb",
		"-cflags", cflags,
		"Tracedns",
		filepath.Join(repoRoot, "bpf", "trace_dns.bpf.c"),
		"--",
	}
	args = append(args, extra...)

	cmd := exec.Command("go", args...)
	cmd.Dir = pkgDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
