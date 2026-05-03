//go:build ignore

// run_bpf2go.go — generate-time helper for tracelsmenforce.
//
// trace_lsm_enforce.bpf.c includes bpf/trace_connect_obs.h (read_ipv4_sockaddr).
// That header keys syscall constants off bpf_target_* from bpf_tracing.h, which
// requires -D__TARGET_ARCH_x86 or -D__TARGET_ARCH_arm64 from the bpf2go clang flags.
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
		"Tracelsmenforce",
		filepath.Join(repoRoot, "bpf", "trace_lsm_enforce.bpf.c"),
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
