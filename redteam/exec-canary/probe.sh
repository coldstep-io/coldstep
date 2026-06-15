#!/usr/bin/env bash
# Red-team case: exec canary.
#
# Generates process-exec activity that coldstep's exec tracepoint must capture
# as `exec` JSONL events. The `redteam-bash-canary` line is an integrity canary
# matched on the predicate comm=bash by `coldstep assert-integrity`.
set -euo pipefail

echo "--- EXEC CANARY ---"
# Standard exec activity.
ls /etc/passwd >/dev/null
# Integrity canary: JSONL exec events must match predicate comm=bash.
bash -c 'echo "redteam-bash-canary" >/dev/null'
