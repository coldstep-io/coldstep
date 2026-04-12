#!/usr/bin/env bash
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
