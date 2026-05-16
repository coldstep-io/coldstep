#!/usr/bin/env bash
# Ensure the Docker daemon is reachable before build/run (clear error vs noisy failures).
#
# Usage:
#   source "$(dirname "$0")/require-docker-daemon.sh"   # from scripts/foo.sh
#   coldstep_require_docker
#
#   Or run directly:
#     bash scripts/require-docker-daemon.sh
#
# Override client binary:
#   DOCKER=podman bash scripts/require-docker-daemon.sh

coldstep_require_docker() {
	local bin="${DOCKER:-docker}"
	if ! "${bin}" info >/dev/null 2>&1; then
		echo "error: '${bin}' daemon is not running or not reachable" >&2
		return 1
	fi
	return 0
}

if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
	set -euo pipefail
	coldstep_require_docker
fi
