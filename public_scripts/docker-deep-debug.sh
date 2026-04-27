#!/usr/bin/env bash
# Run deep-debug.sh inside Dockerfile.deep-debug. Repo root mounted at /workspace.
# Usage: ./public_scripts/docker-deep-debug.sh [--privileged] [--] [args passed to deep-debug.sh]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${DEEP_DEBUG_IMAGE:-coldstep-deep-debug:local}"
if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "Building ${IMAGE}..." >&2
  docker build -f Dockerfile.deep-debug -t "${IMAGE}" "${ROOT}"
fi

PRIV=()
if [[ "${1:-}" == "--privileged" ]]; then
  PRIV=(--privileged)
  shift
fi

exec docker run --rm -i "${PRIV[@]}" \
  -v "${ROOT}:/workspace:rw" \
  -w /workspace \
  -e GOTOOLCHAIN=auto \
  -e DEEP_DEBUG_IN_DOCKER=1 \
  "${IMAGE}" \
  bash public_scripts/deep-debug.sh "$@"
