#!/usr/bin/env bash
# runner-compat-assert.sh — per-variant assertion for coldstep-runner-compat.yml.
#
# Asserts that an agent run produced an events JSONL with at least one line,
# that the readiness probe reported ok:true, and surfaces (without failing)
# any telemetry.json BPF entries with ok=false and any compat_warnings.
#
# Usage: runner-compat-assert.sh <variant-name>

set -euo pipefail

variant="${1:-unknown}"
ws="${GITHUB_WORKSPACE:-$PWD}"
j="${ws}/.coldstep-events.jsonl"
r="${ws}/.coldstep-ready.json"
t="${ws}/.coldstep-telemetry.json"

if [[ ! -f "$j" ]]; then
  echo "::error::variant=${variant} missing .coldstep-events.jsonl"
  exit 1
fi
if [[ ! -s "$j" ]]; then
  echo "::error::variant=${variant} .coldstep-events.jsonl is empty (no events captured)"
  exit 1
fi

if [[ -f "$r" ]]; then
  if ! grep -q '"ok":true' "$r"; then
    echo "::error::variant=${variant} coldstep-ready.json missing ok:true"
    cat "$r"
    exit 1
  fi
else
  echo "::warning::variant=${variant} .coldstep-ready.json not present (fail-on-error path may have skipped readiness write)"
fi

if [[ -f "$t" ]]; then
  if grep -Eq '"ok":false' "$t"; then
    echo "::warning::variant=${variant} reports at least one BPF program with ok=false"
    grep -E '"name":|"ok":|"detail":' "$t" || true
  fi
  if grep -q '"compat_warnings"' "$t"; then
    echo "::notice::variant=${variant} runner_compat_warnings present:"
    grep -E '"code":|"detail":' "$t" || true
  fi
fi

echo "variant=${variant} assertions passed"
