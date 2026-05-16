//go:build ignore

// bpfgen — shared generate-time helper for BPF probe packages whose .bpf.c
// dispatches on syscall numbers (NR_connect/NR_sendto/NR_bpf/…) declared
// behind `#if defined(bpf_target_arm64)` / `bpf_target_x86` macros in
// bpf/trace_connect_obs.h. Those macros key off __TARGET_ARCH_x86 /
// __TARGET_ARCH_arm64, which bpf2go cannot derive itself — a single
// `//go:generate` line cannot easily express a cflags string that depends
// on runtime.GOARCH, so each affected package invokes this helper instead.
//
// Probe packages that need it: traceconnect, tracedns, tracefs, tracebpfaudit,
// tracelsmenforce. Probes whose C source has no syscall-NR dispatch
// (traceenforce, traceexec, tracefork) keep the simpler direct `//go:generate`
// line in their own gen.go and do not call this helper.
//
// Invocation (from a probe package's gen.go):
//
//	//go:generate go run ../bpfgen/main.go <Target> <bpf-source-basename>
//
// Example: ../bpfgen/main.go Traceconnect trace_connect.bpf.c
//
// The //go:build ignore tag keeps this file out of regular `go build ./...`;
// `go run` resolves the explicit file path and runs main regardless.
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: go run bpfgen/main.go <Target> <bpf-source-basename>")
	}
	target := os.Args[1]
	bpfSrc := os.Args[2]

	pkgDir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	repoRoot := filepath.Clean(filepath.Join(pkgDir, "..", "..", ".."))

	archFlag := "-D__TARGET_ARCH_x86"
	if runtime.GOARCH == "arm64" {
		archFlag = "-D__TARGET_ARCH_arm64"
	}

	bpfInclude := filepath.Join(repoRoot, "bpf")
	cflags := fmt.Sprintf("%s -O2 -g -Wall -Werror -I%s -I/usr/include/bpf", archFlag, bpfInclude)

	args := []string{
		"run", "github.com/cilium/ebpf/cmd/bpf2go@v0.21.0",
		"-cc", "clang",
		"-no-strip",
		"-target", "bpfel,bpfeb",
		"-cflags", cflags,
		target,
		filepath.Join(bpfInclude, bpfSrc),
		"--",
		"-I" + bpfInclude,
		"-I/usr/include/bpf",
	}

	cmd := exec.Command("go", args...)
	cmd.Dir = pkgDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
