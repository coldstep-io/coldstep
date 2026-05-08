#!/usr/bin/env bash
#
# docker-deep-debug.sh — CI-like Ubuntu + privileged BPF debugging in Docker.
#
# Defaults mirror GitHub Actions matrix:
#   - Image: ubuntu:24.04 (same major as ubuntu-latest / ubuntu-24.04 runners on GHA).
#   - Go: go.mod toolchain via GOTOOLCHAIN=auto (matches setup-go 1.25.x behavior).
#
# Usage:
#   bash scripts/docker-deep-debug.sh [repo-root]
#
# Environment:
#   COLDSTEP_DOCKER_IMAGE          Override image (e.g. ubuntu:22.04 for jammy parity).
#   COLDSTEP_DOCKER_NO_INTEGRATION Set to 1 to skip integration tests (faster).
#   COLDSTEP_DOCKER_INTERACTIVE    Set to 1 for shell after deps + BPF build (manual bpftool/agent).
#   COLDSTEP_DOCKER_EXTRA_PKGS     Space-separated extra apt packages inside the container.
#   COLDSTEP_DOCKER_DEEP           Set to 0 to skip deep bug-hunt (default: 1): shuffle tests, govulncheck, cover summary.
#   COLDSTEP_DOCKER_RACE_FULL      Set to 1 to run go test -race ./... (slow; default: 0).
#
# Notes:
#   - Uses --privileged so cgroup/BPF attach behaves closer to CI sudo jobs.
#   - Kernel is still the host's (Docker Desktop / Linux host), not GitHub's Azure kernel.
#   - Git Bash on Windows: repo path is converted with cygpath; docker workdir uses //work (not /work).
#   - Integration: mounts tracefs/debugfs inside the container when missing (GitHub-hosted runners have these).
#   - Installs gcc for bpf/host_test C unit tests; bpftool may warn on WSL2 kernel mismatch — build still uses
#     committed bpf/vmlinux.h when present (same as CI).
#   - Integration tests skip some cases on WSL-like kernels; native Linux hosts match CI best.
#
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# Docker Desktop on Windows: Git Bash / MSYS passes Unix paths; convert for bind-mount reliability.
if [[ "${OSTYPE:-}" == msys* ]] || [[ "${OSTYPE:-}" == cygwin* ]]; then
	if command -v cygpath >/dev/null 2>&1; then
		ROOT="$(cygpath -aw "${ROOT}")"
	fi
fi
IMAGE="${COLDSTEP_DOCKER_IMAGE:-ubuntu:24.04}"
RUN_INTEGRATION=1
if [[ "${COLDSTEP_DOCKER_NO_INTEGRATION:-0}" == "1" ]]; then
	RUN_INTEGRATION=0
fi
INTERACTIVE="${COLDSTEP_DOCKER_INTERACTIVE:-0}"
EXTRA_PKGS="${COLDSTEP_DOCKER_EXTRA_PKGS:-}"
DOCKER_DEEP="${COLDSTEP_DOCKER_DEEP:-1}"
RACE_FULL="${COLDSTEP_DOCKER_RACE_FULL:-0}"

DOCKER_ARGS=(run --rm -i)
if [[ "${INTERACTIVE}" == "1" ]]; then
	DOCKER_ARGS+=(-t)
fi
DOCKER_ARGS+=(
	--privileged
	-v "${ROOT}:/work"
	-w //work
	-e GOTOOLCHAIN=auto
	-e DEBIAN_FRONTEND=noninteractive
	-e CI=1
	-e "RUN_INTEGRATION=${RUN_INTEGRATION}"
	-e "INTERACTIVE=${INTERACTIVE}"
	-e "EXTRA_PKGS=${EXTRA_PKGS}"
	-e "COLDSTEP_DOCKER_DEEP=${DOCKER_DEEP}"
	-e "COLDSTEP_DOCKER_RACE_FULL=${RACE_FULL}"
)

exec docker "${DOCKER_ARGS[@]}" "${IMAGE}" bash -s <<'EOS'
set -euo pipefail
export PATH="/usr/local/go/bin:${PATH}"

apt-get update -qq
install_pkgs=(
	golang-go
	gcc
	clang
	llvm
	libbpf-dev
	ca-certificates
	git
	curl
	sudo
	linux-tools-common
	linux-tools-generic
	python3
)
if [[ -n "${EXTRA_PKGS:-}" ]]; then
	# shellcheck disable=SC2206
	install_pkgs+=( ${EXTRA_PKGS} )
fi
apt-get install -y -qq --no-install-recommends "${install_pkgs[@]}"

echo "=== docker-deep-debug: kernel ==="
uname -a || true
echo "=== bpftool (linux-tools tree or PATH) ==="
BPFTOOL_BIN=""
command -v bpftool >/dev/null 2>&1 && BPFTOOL_BIN="$(command -v bpftool)"
if [[ -z "${BPFTOOL_BIN}" ]]; then
	BPFTOOL_BIN="$(find /usr/lib/linux-tools -maxdepth 2 -name bpftool -type f -executable 2>/dev/null | head -1)"
fi
if [[ -n "${BPFTOOL_BIN}" ]]; then
	"${BPFTOOL_BIN}" version || true
else
	echo "(bpftool not on PATH; build-agent-linux.sh resolves linux-tools/*/bpftool when needed)"
fi

bash scripts/build-agent-linux.sh /work

go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
export PATH="$(go env GOPATH)/bin:${PATH}"

go vet ./...
staticcheck ./...
go test ./... -count=1
go test -race -count=1 ./internal/agent/... -timeout 15m

if [[ "${RUN_INTEGRATION:-1}" == "1" ]]; then
	echo "=== tracefs/debugfs (integration tests attach tracepoints; minimal images omit mounts) ==="
	mkdir -p /sys/kernel/debug
	if command -v mountpoint >/dev/null 2>&1; then
		mountpoint -q /sys/kernel/debug 2>/dev/null || mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
	else
		mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
	fi
	mkdir -p /sys/kernel/tracing /sys/kernel/debug/tracing
	if command -v mountpoint >/dev/null 2>&1; then
		mountpoint -q /sys/kernel/tracing 2>/dev/null || mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
		mountpoint -q /sys/kernel/debug/tracing 2>/dev/null || mount -t tracefs tracefs /sys/kernel/debug/tracing 2>/dev/null || true
	else
		mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
		mount -t tracefs tracefs /sys/kernel/debug/tracing 2>/dev/null || true
	fi
	echo "=== integration (root inside privileged container) ==="
	env PATH="${PATH}" go test -tags=integration ./internal/agent/... -count=1 -parallel 1
else
	echo "=== integration skipped ==="
fi

if [[ "${COLDSTEP_DOCKER_DEEP:-1}" == "1" ]]; then
	echo "=== deep: shuffle go test (order-dependent / init bugs) ==="
	go test ./... -count=1 -shuffle=on -timeout 25m
	echo "=== deep: govulncheck (vulnerable dependency paths) ==="
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...
	echo "=== deep: coverage func summary (lowest stmt % first; full /tmp/coldstep-cover-func.txt) ==="
	go test ./... -count=1 -coverprofile=/tmp/coldstep-docker-cover.out -covermode=atomic -timeout 25m
	go tool cover -func=/tmp/coldstep-docker-cover.out >/tmp/coldstep-cover-func.txt
	grep '^total:' /tmp/coldstep-cover-func.txt || true
	awk '!/^total:/ {
		line = $0
		pct = $NF
		if (pct ~ /^[0-9.]+%$/) {
			gsub(/%/, "", pct)
			printf "%07.2f\t%s\n", pct + 0, line
		}
	}' /tmp/coldstep-cover-func.txt | sort | head -40 | cut -f2-
	echo "=== deep: coverage pass complete ==="
else
	echo "=== deep bug-hunt skipped (COLDSTEP_DOCKER_DEEP=0) ==="
fi

if [[ "${COLDSTEP_DOCKER_RACE_FULL:-0}" == "1" ]]; then
	echo "=== deep: full-module race (slow) ==="
	go test -race -count=1 ./... -timeout 45m
fi

echo "=== docker-deep-debug: automated steps OK ==="

if [[ "${INTERACTIVE:-0}" == "1" ]]; then
	echo "=== dropping to interactive shell (bpftool, ./bin/coldstep, etc.) ==="
	exec bash -il
fi
EOS
