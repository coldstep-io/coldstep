#!/usr/bin/env bash
# Run public_scripts/check-gofmt.sh inside the official golang Docker image so formatting
# matches Linux CI regardless of host OS/editor (Windows CRLF, etc.).
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${ROOT}" ]]; then
	echo "docker_gofmt_check.sh: must run inside a git checkout (git rev-parse failed)" >&2
	exit 1
fi

IMAGE="${COLDSTEP_GOFMT_IMAGE:-golang:1.25-bookworm}"
echo "docker_gofmt_check: image=${IMAGE}"

if ! command -v docker >/dev/null 2>&1; then
	echo "docker_gofmt_check: docker not found in PATH" >&2
	exit 1
fi

docker run --rm \
	-v "${ROOT}:/workspace" \
	-w /workspace \
	-e CI="${CI:-}" \
	-e GITHUB_ACTIONS="${GITHUB_ACTIONS:-}" \
	"${IMAGE}" \
	bash -c '
set -euo pipefail
# Login shells (-l) can drop /usr/local/go/bin from PATH in this image; gofmt lives next to go.
export PATH="/usr/local/go/bin:${PATH}"
cd /workspace
if ! command -v gofmt >/dev/null 2>&1; then
	echo "docker_gofmt_check: gofmt not found after PATH=${PATH}" >&2
	exit 1
fi
export DEBIAN_FRONTEND=noninteractive
if ! command -v git >/dev/null 2>&1; then
	apt-get update -qq
	apt-get install -y -qq git ca-certificates >/dev/null
fi
git config --global --add safe.directory /workspace
exec bash public_scripts/check-gofmt.sh
'
