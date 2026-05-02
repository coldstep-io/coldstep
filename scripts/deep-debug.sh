#!/usr/bin/env bash
# Deep debug pass — stages aligned with coldstep-ci-runner + coldstep-ci-nightly.
# Invoke via workflow_dispatch on .github/workflows/coldstep-deep-debug.yml (ubuntu-latest).
# Design: .github/design/2026-04-18-deep-debug-pass-design.md
#
# Environment:
#   DEEP_DEBUG_OUT          Output root (default: REPO_ROOT/.coldstep-deep-debug)
#   DEEP_DEBUG_RUN_3B       Run stage 3b shuffle/govulncheck/race_full (default: 1)
#   DEEP_DEBUG_RUN_4        Run sudo integration tests (default: 0)
#   DEEP_DEBUG_GOVULNCHECK  Include govulncheck in 3b (default: 1)
#   DEEP_DEBUG_SHUFFLE      Include go test -shuffle in 3b (default: 1)
#   DEEP_DEBUG_RACE_FULL    Full-module race in 3b (default: 0)
#   DEEP_DEBUG_CI           Set to 1 when run from GitHub Actions (informational)
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${DEEP_DEBUG_OUT:-$ROOT/.coldstep-deep-debug}"
mkdir -p "$OUT"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOGDIR="$OUT/run-$TS"
mkdir -p "$LOGDIR"
REPORT="$LOGDIR/report.md"

DEEP_DEBUG_RUN_3B="${DEEP_DEBUG_RUN_3B:-1}"
DEEP_DEBUG_RUN_4="${DEEP_DEBUG_RUN_4:-0}"
DEEP_DEBUG_GOVULNCHECK="${DEEP_DEBUG_GOVULNCHECK:-1}"
DEEP_DEBUG_SHUFFLE="${DEEP_DEBUG_SHUFFLE:-1}"
DEEP_DEBUG_RACE_FULL="${DEEP_DEBUG_RACE_FULL:-0}"

P0_FAIL=0
FAIL_3A=0
S3B_ANY=0
S4_ANY=0

append_report() {
  printf '%s\n' "$1" >>"$REPORT"
}

run_cmd() {
  local stage="$1" label="$2"
  shift 2
  local logfile="$LOGDIR/${stage}-${label}.log"
  append_report "### ${stage} ${label}"
  append_report ""
  append_report '```text'
  set +e
  "$@" 2>&1 | tee -a "$logfile"
  local ec=${PIPESTATUS[0]}
  set +e
  append_report "(exit ${ec})"
  append_report '```'
  append_report ""
  if [[ "${ec}" -ne 0 ]]; then
    echo "FAIL: stage ${stage} ${label} (exit ${ec})" >&2
  fi
  return "${ec}"
}

# --- Stage 0 ---
S0_OK=0
run_cmd 0 utf8             python3 public_scripts/assert_utf8_text.py                 || S0_OK=1
run_cmd 0 pins           python3 public_scripts/check_workflow_action_pins.py         || S0_OK=1
run_cmd 0 unittest       python3 -m unittest discover -s scripts -p "test_*.py" -v || S0_OK=1
run_cmd 0 shell_markers  bash public_scripts/test_workflow_diff_markers.sh            || S0_OK=1
[[ "$S0_OK" -eq 0 ]] || P0_FAIL=1

# --- Stage 1 ---
S1_OK=0
if [[ "$P0_FAIL" -eq 0 ]]; then
  run_cmd 1 npm_ci       npm ci                                              || S1_OK=1
  run_cmd 1 typecheck    npm run typecheck                                   || S1_OK=1
  run_cmd 1 build        npm run build                                       || S1_OK=1
  [[ "$S1_OK" -eq 0 ]] || P0_FAIL=1
else
  append_report "### Stage 1 skipped (P0 failure earlier)"
  append_report ""
fi

# --- Stage 2 ---
S2_OK=0
if [[ "$P0_FAIL" -eq 0 ]]; then
  run_cmd 2 gofmt        bash public_scripts/check-gofmt.sh                         || S2_OK=1
  run_cmd 2 bpf_build    bash public_scripts/build-agent-linux.sh "$ROOT"           || S2_OK=1
  run_cmd 2 vet          go vet ./...                                       || S2_OK=1
  # bash -lc drops Go toolchain PATH on some images; keep explicit /usr/local/go/bin.
  run_cmd 2 staticcheck bash -c 'export PATH="/usr/local/go/bin:${PATH}" && export PATH="$(go env GOPATH)/bin:${PATH}" && go install honnef.co/go/tools/cmd/staticcheck@v0.7.0 && staticcheck ./...' || S2_OK=1
  [[ "$S2_OK" -eq 0 ]] || P0_FAIL=1
else
  append_report "### Stage 2 skipped (P0 failure earlier)"
  append_report ""
fi

# --- Stage 3a ---
S3A_OK=0
if [[ "$P0_FAIL" -eq 0 ]]; then
  run_cmd 3a unit_tests  go test ./... -count=1                             || S3A_OK=1
  run_cmd 3a race_agent  go test -race -count=1 ./internal/agent/... -timeout 15m || S3A_OK=1
  [[ "$S3A_OK" -eq 0 ]] || FAIL_3A=1
else
  append_report "### Stage 3a skipped (P0 failure earlier)"
  append_report ""
fi

# --- Stage 3b (optional) ---
if [[ "$P0_FAIL" -eq 0 && "$FAIL_3A" -eq 0 && "$DEEP_DEBUG_RUN_3B" == "1" ]]; then
  if [[ "$DEEP_DEBUG_SHUFFLE" == "1" ]]; then
    run_cmd 3b shuffle go test ./... -count=1 -shuffle=on -timeout 20m || S3B_ANY=1
  fi
  if [[ "$DEEP_DEBUG_GOVULNCHECK" == "1" ]]; then
    run_cmd 3b govulncheck bash -c 'export PATH="/usr/local/go/bin:${PATH}" && export PATH="$(go env GOPATH)/bin:${PATH}" && go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...' || S3B_ANY=1
  fi
  if [[ "$DEEP_DEBUG_RACE_FULL" == "1" ]]; then
    run_cmd 3b race_full go test -race -count=1 ./... -timeout 45m || S3B_ANY=1
  fi
elif [[ "$P0_FAIL" -eq 0 && "$FAIL_3A" -ne 0 ]]; then
  append_report "### Stage 3b skipped (stage 3a failed)"
  append_report ""
fi

# --- Stage 4 (optional integration, requires sudo + BPF-capable environment) ---
if [[ "$P0_FAIL" -eq 0 && "$FAIL_3A" -eq 0 && "$DEEP_DEBUG_RUN_4" == "1" ]]; then
  run_cmd 4 integration sudo env "PATH=$PATH" go test -tags=integration ./internal/agent/... -count=1 || S4_ANY=1
else
  if [[ "${DEEP_DEBUG_RUN_4:-}" == "1" && ("$P0_FAIL" -ne 0 || "$FAIL_3A" -ne 0) ]]; then
    append_report "### Stage 4 skipped (earlier gate)"
    append_report ""
  fi
fi

# --- Summary header (prepend by rewriting report) ---
SUMMARY_FILE="$LOGDIR/summary.tmp"
if [[ "$P0_FAIL" -ne 0 || "$FAIL_3A" -ne 0 || "$DEEP_DEBUG_RUN_3B" != "1" ]]; then
  LABEL_3B="SKIP"
elif [[ "$S3B_ANY" -eq 0 ]]; then
  LABEL_3B="OK"
else
  LABEL_3B="FAIL"
fi
if [[ "$DEEP_DEBUG_RUN_4" != "1" ]]; then
  LABEL_4="SKIP"
elif [[ "$P0_FAIL" -ne 0 || "$FAIL_3A" -ne 0 ]]; then
  LABEL_4="SKIP"
elif [[ "$S4_ANY" -eq 0 ]]; then
  LABEL_4="OK"
else
  LABEL_4="FAIL"
fi
{
  echo "# Deep debug report"
  echo ""
  echo "| Field | Value |"
  echo "| ----- | ----- |"
  echo "| Timestamp (UTC) | $TS |"
  echo "| Commit | $(git rev-parse HEAD 2>/dev/null || echo unknown) |"
  echo "| P0 gate | $([[ "$P0_FAIL" -eq 0 ]] && echo OK || echo FAIL) |"
  echo "| Stage 3a | $([[ "$FAIL_3A" -eq 0 ]] && echo OK || echo FAIL) |"
  echo "| Stage 3b | ${LABEL_3B} |"
  echo "| Stage 4 | ${LABEL_4} |"
  echo "| Output dir | $LOGDIR |"
  echo ""
} >"$SUMMARY_FILE"
cat "$REPORT" >>"$SUMMARY_FILE"
mv "$SUMMARY_FILE" "$REPORT"

echo "Report: $REPORT" >&2
FAIL_ANY=0
[[ "$P0_FAIL" -eq 0 ]] || FAIL_ANY=1
[[ "$FAIL_3A" -eq 0 ]] || FAIL_ANY=1
[[ "$S3B_ANY" -eq 0 ]] || FAIL_ANY=1
[[ "$S4_ANY" -eq 0 ]] || FAIL_ANY=1
exit "$FAIL_ANY"
