#!/usr/bin/env bash
# Contract smoke test for scripts/ci_coldstep_jsonl_traffic_diff.py summary markers used by
# .github/workflows/coldstep-ci-runner.yml (detect-mode prev-diff step). Mirrors DiffScriptTests
# unavailable-diff cases without requiring GitHub Actions. Second phase (C-SR-03): unclassified
# totals appear on successful diffs when unknown event types are present.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
cleanup() {
	rm -rf "${WORKDIR:?}"
}
trap cleanup EXIT

export NS_SUMMARY="${WORKDIR}/summary.md"
export NS_BASELINE="${WORKDIR}/baseline.jsonl"
export NS_CURRENT="${WORKDIR}/current.jsonl"
MARKER="${NS_MARKER:-coldstep-prev-diff}"
export NS_MARKER="${MARKER}"

touch "${NS_SUMMARY}"
echo '{"type":"tcp"}' >"${NS_BASELINE}"
echo 'not-json' >"${NS_CURRENT}"

export COLDSTEP_DIFF_STRICT=0
python3 "${ROOT}/scripts/ci_coldstep_jsonl_traffic_diff.py"
grep -Fq "${MARKER}.policy=relaxed" "${NS_SUMMARY}"

export COLDSTEP_DIFF_STRICT=1
: >"${NS_SUMMARY}"
set +e
python3 "${ROOT}/scripts/ci_coldstep_jsonl_traffic_diff.py"
rc_strict=$?
set -e
if [[ "${rc_strict}" -eq 0 ]]; then
	echo "expected non-zero exit when unavailable and strict" >&2
	exit 1
fi
if grep -Fq "policy=relaxed" "${NS_SUMMARY}"; then
	echo "unexpected policy=relaxed while COLDSTEP_DIFF_STRICT=1" >&2
	exit 1
fi

echo "ok: workflow diff markers (relaxed unavailable vs strict unavailable)"

# --- C-SR-03: unclassified.base_total / unclassified.current_total markers ---
export NS_SUMMARY="${WORKDIR}/summary_unclassified.md"
touch "${NS_SUMMARY}"
echo '{"type":"tcp","dst":"1.1.1.1","dport":443}' >"${NS_BASELINE}"
{
	echo '{"type":"tcp","dst":"1.1.1.1","dport":443}'
	echo '{"type":"phantom_shell_contract"}'
} >"${NS_CURRENT}"
export COLDSTEP_DIFF_STRICT=0
python3 "${ROOT}/scripts/ci_coldstep_jsonl_traffic_diff.py"
grep -Fq "${MARKER}.unclassified.base_total=0" "${NS_SUMMARY}"
grep -Fq "${MARKER}.unclassified.current_total=1" "${NS_SUMMARY}"

echo "ok: workflow diff unclassified markers (C-SR-03)"
