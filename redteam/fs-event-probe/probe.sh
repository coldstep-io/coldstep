#!/usr/bin/env bash
# Red-team case: filesystem event probe.
#
# Creates a temp file and chmods it. glibc's chmod uses fchmodat, which
# coldstep's trace_fs hook captures as an fs_event. Exercises the fs_event
# JSONL stream (enhanced detect profile).
set -euo pipefail

echo "--- FS EVENT PROBE ---"
# Filesystem events (glibc chmod uses fchmodat, which trace_fs hooks).
TMP_F=$(mktemp)
echo "redteam" > "${TMP_F}"
/bin/chmod 400 "${TMP_F}"
rm "${TMP_F}"
