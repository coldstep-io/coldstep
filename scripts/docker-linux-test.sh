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
# - Default image: ubuntu:noble (24.04 LTS). Installs golang-go + clang/llvm/libbpf-dev from apt;
#   newer Go from go.mod is fetched via GOTOOLCHAIN=auto when needed.

set -euo pipefail

ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"

exec docker run --rm \
	--cap-add BPF \
	-v "${ROOT}:/work" \
	-w /work \
	-e GOTOOLCHAIN=auto \
	-e DEBIAN_FRONTEND=noninteractive \
	ubuntu:noble \
	bash -c 'apt-get update -qq && apt-get install -y -qq golang-go clang llvm libbpf-dev ca-certificates git && bash scripts/build-agent-linux.sh /work && go test ./...'
