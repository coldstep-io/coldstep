#!/usr/bin/env bash
# Build only the coldstep-report CLI (no BPF / full agent compile).
# Use when workflows supply the agent via GitHub Release + release-path but still need
# report-model / JSONL diff steps (same flags as build-agent-linux.sh for this binary).
set -euo pipefail
ROOT="${1:-${GITHUB_WORKSPACE:-.}}"
cd "${ROOT}"
mkdir -p bin
go build -trimpath -ldflags="-s -w" -o bin/coldstep-report ./cmd/coldstep-report
