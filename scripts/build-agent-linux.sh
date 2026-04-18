#!/usr/bin/env bash
#
# build-agent-linux.sh — single source of truth for building the Coldstep
# agent on a Linux runner.
#
# Responsibilities (in order):
#   1. apt-get install clang/llvm/libbpf-dev — the BPF compile toolchain.
#   2. Generate bpf/vmlinux.h from /sys/kernel/btf/vmlinux via bpftool, but
#      only if bpf/vmlinux.h is missing or empty (committed copies are
#      reused as-is). bpftool is selected from /usr/lib/linux-tools/<krel>
#      because the Ubuntu /usr/bin/bpftool wrapper frequently fails on
#      GitHub-hosted Azure kernels until the kernel-matched linux-tools
#      package is installed.
#   3. `go generate ./internal/bpf/.../` for every BPF subpackage. This
#      invokes bpf2go (or run_bpf2go.go for traceconnect/tracedns/tracefs)
#      which compiles each .bpf.c into an embedded ELF + Go bindings.
#      Compile errors here include `_Static_assert` failures from PR-B,
#      so a struct-size drift on the BPF side fails the build immediately.
#   4. `go build` the cmd/coldstep agent.
#
# Run this script from CI or locally inside a Linux container that mounts
# the repo. Windows hosts cannot run BPF compile but can run this in
# Docker (see Dockerfile.deep-debug for a known-good image). The script
# does NOT need root — it uses sudo for apt-get when EUID != 0.
set -euo pipefail
ROOT="${1:?pass repository root as first argument}"
cd "$ROOT"

export DEBIAN_FRONTEND=noninteractive
if [[ "${EUID:-0}" -eq 0 ]]; then
	APTGET=(apt-get)
else
	APTGET=(sudo apt-get)
fi
"${APTGET[@]}" update -qq
"${APTGET[@]}" install -y -qq clang llvm libbpf-dev

mkdir -p bpf
if [[ ! -s bpf/vmlinux.h ]]; then
	if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
		echo "BTF at /sys/kernel/btf/vmlinux is required to generate bpf/vmlinux.h (kernel with CONFIG_DEBUG_INFO_BTF=y)" >&2
		exit 1
	fi

	# bpftool: install kernel-matched tools *before* the standalone `bpftool` package.
	# Ubuntu's /usr/bin/bpftool is often a wrapper that fails on GitHub Azure kernels
	# (exit 2, "bpftool not found for kernel …") unless linux-tools-<uname -r> is present.
	krel=$(uname -r)
	# Do not use `command -v bpftool` to skip installs: images may ship /usr/bin/bpftool
	# (wrapper) that breaks for the running kernel until linux-tools-<uname -r> is installed.
	if [[ ! -x "/usr/lib/linux-tools/${krel}/bpftool" ]]; then
		"${APTGET[@]}" install -y -qq "linux-tools-${krel}" 2>/dev/null || true
	fi
	if [[ ! -x "/usr/lib/linux-tools/${krel}/bpftool" ]]; then
		"${APTGET[@]}" install -y -qq "linux-cloud-tools-${krel}" 2>/dev/null || true
	fi
	if [[ ! -x "/usr/lib/linux-tools/${krel}/bpftool" ]]; then
		"${APTGET[@]}" install -y -qq linux-tools-azure 2>/dev/null || true
	fi
	if [[ ! -x "/usr/lib/linux-tools/${krel}/bpftool" ]]; then
		"${APTGET[@]}" install -y -qq linux-cloud-tools-azure 2>/dev/null || true
	fi
	if [[ ! -x "/usr/lib/linux-tools/${krel}/bpftool" ]]; then
		"${APTGET[@]}" install -y -qq linux-tools-common linux-tools-generic 2>/dev/null || true
	fi
	if [[ ! -x "/usr/lib/linux-tools/${krel}/bpftool" ]]; then
		"${APTGET[@]}" install -y -qq bpftool 2>/dev/null || true
	fi

	# Resolve a *concrete* bpftool binary. `linux-tools-azure` may install
	# linux-tools-6.17.0-(N+1)-azure while `uname -r` is still 6.17.0-N-azure; the
	# Ubuntu /usr/bin/bpftool wrapper then fails. Prefer exact krel dir, else the
	# newest version-sorted linux-tools/*/bpftool (never `find … | head -1`, which
	# can pick older HWE generic trees like 6.8.0-*).
	BPFTOOL=""
	if [[ -x "/usr/lib/linux-tools/${krel}/bpftool" ]]; then
		BPFTOOL="/usr/lib/linux-tools/${krel}/bpftool"
	else
		mapfile -t tool_dirs < <(find /usr/lib/linux-tools -mindepth 1 -maxdepth 1 -type d 2>/dev/null | LC_ALL=C sort -V)
		for ((i = ${#tool_dirs[@]} - 1; i >= 0; i--)); do
			if [[ -x "${tool_dirs[i]}/bpftool" ]]; then
				BPFTOOL="${tool_dirs[i]}/bpftool"
				break
			fi
		done
	fi
	if [[ -z "${BPFTOOL}" ]] && command -v bpftool >/dev/null 2>&1; then
		cand=$(command -v bpftool)
		# Skip the distro wrapper when possible (it keys off uname -r only).
		if [[ "${cand}" != /usr/bin/bpftool ]]; then
			BPFTOOL=${cand}
		fi
	fi
	if [[ -z "${BPFTOOL}" ]]; then
		echo "bpftool is required to dump /sys/kernel/btf/vmlinux into bpf/vmlinux.h (install linux-tools for this kernel)" >&2
		exit 1
	fi

	tmp=$(mktemp "${ROOT}/bpf/vmlinux.h.XXXXXX")
	trap 'rm -f "${tmp}"' EXIT
	"${BPFTOOL}" btf dump file /sys/kernel/btf/vmlinux format c >"${tmp}"
	mv "${tmp}" "${ROOT}/bpf/vmlinux.h"
	trap - EXIT
fi

go generate ./internal/bpf/traceexec/...
go generate ./internal/bpf/tracefork/...
go generate ./internal/bpf/traceconnect/...
go generate ./internal/bpf/traceenforce/...
go generate ./internal/bpf/tracedns/...
go generate ./internal/bpf/tracefs/...
go build -trimpath -ldflags="-s -w" -o bin/coldstep ./cmd/coldstep
