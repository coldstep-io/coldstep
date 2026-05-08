#!/usr/bin/env bash
# Run the same Linux build + tests as CI (scripts/build-agent-linux.sh + go test ./...).
# Intended for hosts without a native Linux toolchain (e.g. Docker Desktop on Windows).
#
# Usage:
#   bash scripts/docker-linux-test.sh [repo-root]
#
# Notes:
# - Mounts repo root at /work; uses committed bpf/vmlinux.h when present (skips BTF dump).
# - ebpf map tests need CAP_BPF inside the container (matches unprivileged restrictions).
# - Default image: ubuntu:24.04 (matches GitHub ubuntu-latest / ubuntu-24.04 lineage). Installs golang-go + clang/llvm/libbpf-dev from apt;
#   newer Go from go.mod is fetched via GOTOOLCHAIN=auto when needed.
# - Override container engine: DOCKER=podman (default: docker).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=require-docker-daemon.sh
source "${SCRIPT_DIR}/require-docker-daemon.sh"
DOCKER="${DOCKER:-docker}"
coldstep_require_docker

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
if [[ "${OSTYPE:-}" == msys* ]] || [[ "${OSTYPE:-}" == cygwin* ]]; then
	if command -v cygpath >/dev/null 2>&1; then
		ROOT="$(cygpath -aw "${ROOT}")"
	fi
fi

exec "${DOCKER}" run --rm \
	--cap-add BPF \
	-v "${ROOT}:/work" \
	-w //work \
	-e GOTOOLCHAIN=auto \
	-e DEBIAN_FRONTEND=noninteractive \
	ubuntu:24.04 \
	bash -c 'apt-get update -qq && apt-get install -y -qq golang-go clang llvm libbpf-dev ca-certificates git && bash scripts/build-agent-linux.sh /work && go test ./...'
