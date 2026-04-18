//go:build ignore

// run_bpf2go.go — generate-time helper for traceconnect.
//
// Why this file exists: bpf2go's `//go:generate` line cannot easily express a
// cflags string that depends on `runtime.GOARCH`. trace_connect.bpf.c (via
// trace_connect_obs.h) needs `-D__TARGET_ARCH_x86` or `-D__TARGET_ARCH_arm64`
// to select the correct syscall-number constants for the host architecture
// being generated for. We compute the right `-D` flag here, then exec
// bpf2go with the assembled cflags. The `//go:build ignore` tag keeps this
// file out of the regular build — it only runs under `go generate`.
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
		"Traceconnect",
		filepath.Join(repoRoot, "bpf", "trace_connect.bpf.c"),
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
