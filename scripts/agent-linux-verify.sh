#!/usr/bin/env bash
#
# agent-linux-verify.sh -- one Linux oracle for agent fix-loops (local CI analogue).
#
# Windows without bash on PATH: powershell -NoProfile -File scripts/agent-linux-verify.ps1 [-VerifyMode fast]
# or: python scripts/agent_linux_verify.py [--mode fast]
#
# Runs docker-linux-test (quick BPF + go test) or docker-deep-debug (runner-like),
# saves the full transcript, and prints a structured bundle for assistants.
#
# Usage (from repo root):
#   bash scripts/agent-linux-verify.sh [repo-root]
#
# Environment:
#   COLDSTEP_VERIFY_MODE     quick | deep | fast (default: deep)
#       quick -- scripts/docker-linux-test.sh only.
#       deep  -- scripts/docker-deep-debug.sh (honors existing COLDSTEP_DOCKER_*).
#       fast  -- deep with COLDSTEP_DOCKER_DEEP=0 and COLDSTEP_DOCKER_NO_INTEGRATION=1 (inner loop).
#   COLDSTEP_VERIFY_TAIL     Lines of transcript tail for the bundle (default: 140).
#   COLDSTEP_VERIFY_LOG      Transcript path (default: REPO_ROOT/.coldstep-verify-last.log).
#
# Agent loop etiquette:
#   1. Fix toward the first hard error in the tail; avoid unrelated churn.
#   2. For BPF verifier / codegen issues, sync knowledge vault (see AGENTS.md and obsidian-cli skill).
#   3. Re-run this same command until exit 0.
#   4. If the same primary error survives two unrelated fix attempts, stop and open an RCA memo.
#

set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
if [[ "${OSTYPE:-}" == msys* ]] || [[ "${OSTYPE:-}" == cygwin* ]]; then
	if command -v cygpath >/dev/null 2>&1; then
		ROOT="$(cygpath -aw "${ROOT}")"
	fi
fi

MODE="${COLDSTEP_VERIFY_MODE:-deep}"
case "${MODE}" in
quick | deep | fast) ;;
*)
	echo "COLDSTEP_VERIFY_MODE must be quick, deep, or fast (got: ${MODE})" >&2
	exit 2
	;;
esac

TAIL_N="${COLDSTEP_VERIFY_TAIL:-140}"
LOG="${COLDSTEP_VERIFY_LOG:-${ROOT}/.coldstep-verify-last.log}"

if ! command -v docker >/dev/null 2>&1; then
	echo "docker not found on PATH; install Docker Desktop (Windows) or docker.io (Linux)." >&2
	exit 127
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INVOKED=""

dump_bundle() {
	local code="$1"
	local ts
	ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '%s' 'UTC')"

	echo ""
	echo "--- COLDSTEP_AGENT_VERIFY_BUNDLE_BEGIN ---"
	echo "utc_timestamp: ${ts}"
	echo "exit_code: ${code}"
	echo "mode: ${MODE}"
	echo "log_file: ${LOG}"
	echo "invoked:"
	echo "${INVOKED}"
	echo ""
	echo "## Tail (last ${TAIL_N} lines of transcript)"
	echo ""
	if [[ -f "${LOG}" ]]; then
		tail -n "${TAIL_N}" "${LOG}"
	else
		echo "(missing log)"
	fi
	echo ""
	echo "## NEXT (for assistants)"
	echo "- Locate the earliest failing step (build-agent-linux.sh, go vet, staticcheck, go test, integration, deep shuffle, govulncheck)."
	echo "- Prefer the smallest reproducible patch; run gofmt on edited Go sources."
	echo "- BPF/verifier: treat Linux Docker output as authoritative; capture kernel line from transcript if Present."
	echo "- Re-run from repo root: bash scripts/agent-linux-verify.sh \"${ROOT}\""
	echo "- Repeat until exit_code is 0, or halt if the dominant error persists after two materially different fixes (then document in knowledge vault RCA)."
	echo "--- COLDSTEP_AGENT_VERIFY_BUNDLE_END ---"
}

set +e
INVOKED="# quick: docker-linux-test"
if [[ "${MODE}" == quick ]]; then
	(
		set -o pipefail
		bash "${SCRIPT_DIR}/docker-linux-test.sh" "${ROOT}" 2>&1 | tee "${LOG}"
	)
	CODE="${PIPESTATUS[0]}"
elif [[ "${MODE}" == fast ]]; then
	export COLDSTEP_DOCKER_DEEP=0
	export COLDSTEP_DOCKER_NO_INTEGRATION=1
	INVOKED="# fast: docker-deep-debug (COLDSTEP_DOCKER_DEEP=0, COLDSTEP_DOCKER_NO_INTEGRATION=1)"
	if [[ -n "${COLDSTEP_DOCKER_IMAGE:-}" ]]; then
		INVOKED="${INVOKED}"$'\n'"# image: ${COLDSTEP_DOCKER_IMAGE}"
	fi
	(
		set -o pipefail
		bash "${SCRIPT_DIR}/docker-deep-debug.sh" "${ROOT}" 2>&1 | tee "${LOG}"
	)
	CODE="${PIPESTATUS[0]}"
else
	INVOKED="# deep: docker-deep-debug"
	if [[ -n "${COLDSTEP_DOCKER_NO_INTEGRATION:-}" ]]; then
		INVOKED="${INVOKED}"$'\n'"# COLDSTEP_DOCKER_NO_INTEGRATION=${COLDSTEP_DOCKER_NO_INTEGRATION}"
	fi
	if [[ -n "${COLDSTEP_DOCKER_DEEP:-}" ]]; then
		INVOKED="${INVOKED}"$'\n'"# COLDSTEP_DOCKER_DEEP=${COLDSTEP_DOCKER_DEEP}"
	fi
	if [[ -n "${COLDSTEP_DOCKER_IMAGE:-}" ]]; then
		INVOKED="${INVOKED}"$'\n'"# image: ${COLDSTEP_DOCKER_IMAGE}"
	fi
	(
		set -o pipefail
		bash "${SCRIPT_DIR}/docker-deep-debug.sh" "${ROOT}" 2>&1 | tee "${LOG}"
	)
	CODE="${PIPESTATUS[0]}"
fi
set -e

dump_bundle "${CODE}"
exit "${CODE}"
