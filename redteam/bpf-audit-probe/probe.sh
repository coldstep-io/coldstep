#!/usr/bin/env bash
# Red-team case: BPF audit probe.
#
# Enumerates loaded BPF maps/programs with bpftool. coldstep's bpf-audit hook
# should surface these privileged BPF introspection syscalls. Prefers the real
# bpftool binary path so the recorded comm is `bpftool` (not a shell wrapper),
# which the integrity canaries match on.
set -euo pipefail

echo "--- BPF AUDIT PROBE ---"
# Prefer real binary path so comm=bpftool matches integrity canaries (not a shell wrapper).
BPFTOOL_BIN="$(command -v bpftool || true)"
if [[ -z "${BPFTOOL_BIN}" && -x /usr/sbin/bpftool ]]; then BPFTOOL_BIN=/usr/sbin/bpftool; fi
if [[ -n "${BPFTOOL_BIN}" ]]; then
	sudo "${BPFTOOL_BIN}" map show >/dev/null 2>&1 || echo "bpftool map show failed; best effort audit signal"
	sudo "${BPFTOOL_BIN}" prog show >/dev/null 2>&1 || echo "bpftool prog show failed; best effort audit signal"
	sudo "${BPFTOOL_BIN}" map show >/dev/null 2>&1 || true
else
	echo "bpftool not found; skipping bpf audit probe"
fi
