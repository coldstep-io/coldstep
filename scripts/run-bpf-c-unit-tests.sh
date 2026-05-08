#!/usr/bin/env bash
#
# run-bpf-c-unit-tests.sh — compile and run host-side C tests for BPF helpers.
#
# Full *.bpf.c objects are exercised indirectly via bpf2go / scripts/build-agent-linux.sh
# (clang -target bpf). This script covers portable logic extracted to bpf/coldstep_pure.h
# and wire-layout guards that include bpf/deny_event.h.
#
# Usage: bash scripts/run-bpf-c-unit-tests.sh <repository-root>
set -euo pipefail

ROOT="${1:?pass repository root as first argument}"
cd "$ROOT"

CC="${CC:-gcc}"
CFLAGS=( -std=c11 -Wall -Wextra -Werror -O2 )

compile_run() {
	local src="$1"
	local name

	name=$(basename "$src" .c)
	local out
	out=$(mktemp "${TMPDIR:-/tmp}/coldstep-${name}-XXXXXX")
	"${CC}" "${CFLAGS[@]}" -o "${out}" "${src}"
	"${out}"
	rm -f "${out}"
}

compile_run "bpf/host_test/test_coldstep_pure.c"
compile_run "bpf/host_test/test_deny_event_wire.c"

echo "bpf C unit tests: OK"
