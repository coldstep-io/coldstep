# Deep debug pass — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a repeatable local Docker deep-debug driver, CI confirmation workflow, output directory ignored by git, and Markdown triage report matching [.github/design/2026-04-18-deep-debug-pass-design.md](2026-04-18-deep-debug-pass-design.md).

**Architecture:** One **`scripts/deep-debug.sh`** implements ordered stages (0 → 4), exhaustive commands per stage, hybrid gating (P0 stops stages 3+; 3a failures skip 3b and 4), and writes **`report-*.md`** plus per-stage logs under **`.coldstep-deep-debug/`**. **`Dockerfile.deep-debug`** provides Ubuntu + Go 1.24 + Node 24 + Python + apt deps so **`build-agent-linux.sh`** can run against the **host kernel’s** `/sys` when the repo is bind-mounted (`--privileged` optional for stage 4). **`.github/workflows/coldstep-deep-debug.yml`** runs the same script on `workflow_dispatch` with inputs mirroring optional stages.

**Tech stack:** Bash 5+, Docker, GitHub Actions, Go 1.24.x, Node 24, Python 3.

---

## File map

| File | Responsibility |
| ---- | -------------- |
| `.gitignore` | Ignore `.coldstep-deep-debug/` |
| `Dockerfile.deep-debug` | Local reproducible Linux image for running `deep-debug.sh` |
| `scripts/deep-debug.sh` | Stage orchestration, logs, triage Markdown report |
| `scripts/docker-deep-debug.sh` | **`docker build` + `docker run`** wrapper (cwd = repo root) |
| `.github/workflows/coldstep-deep-debug.yml` | `workflow_dispatch`; installs toolchains like CI; invokes `deep-debug.sh` |

---

### Task 1: Ignore deep-debug artifacts

**Files:**
- Modify: `.gitignore`
- Test: `git check-ignore -v .coldstep-deep-debug/foo`

- [ ] **Step 1: Append ignore rule**

After the `/docs/` block (or near other tooling artifacts), add:

```
# Local deep-debug pass output (scripts/deep-debug.sh)
.coldstep-deep-debug/
```

- [ ] **Step 2: Verify**

Run: `git check-ignore -v .coldstep-deep-debug/x.md`  
Expected: `.gitignore:<line>:.coldstep-deep-debug/`

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -S -m "chore: gitignore deep-debug output directory"
```

---

### Task 2: Dockerfile for local runs

**Files:**
- Create: `Dockerfile.deep-debug`
- Test: `docker build -f Dockerfile.deep-debug -t coldstep-deep-debug:local .`

Debian-based Go image avoids fighting Ubuntu’s default Go package; Node 24 via NodeSource matches workflows.

- [ ] **Step 1: Add Dockerfile**

Create `Dockerfile.deep-debug`:

```dockerfile
# Local deep-debug driver image (not used by CI; mirrors toolchain versions).
FROM golang:1.24-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq \
  && apt-get install -y -qq --no-install-recommends \
    ca-certificates \
    curl \
    git \
    python3 \
    sudo \
    unzip \
  && rm -rf /var/lib/apt/lists/*

# Node.js 24 (align with action.yml / workflows).
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
  && apt-get install -y -qq nodejs \
  && rm -rf /var/lib/apt/lists/*

# clang/llvm/libbpf + generic linux tools — build-agent-linux.sh adds kernel-matched tools at runtime.
RUN apt-get update -qq \
  && apt-get install -y -qq --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    make \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
ENV GOTOOLCHAIN=auto
```

- [ ] **Step 2: Build image**

Run: `docker build -f Dockerfile.deep-debug -t coldstep-deep-debug:local .`  
Expected: image builds without error.

- [ ] **Step 3: Commit**

```bash
git add Dockerfile.deep-debug
git commit -S -m "build: add Dockerfile for local deep-debug pass"
```

---

### Task 3: `scripts/docker-deep-debug.sh` wrapper

**Files:**
- Create: `scripts/docker-deep-debug.sh`
- Test: Run from repo root on a machine with Docker; expect script to start container (may fail later if kernel has no BTF — that is environmental, not a script bug).

- [ ] **Step 1: Create wrapper**

Create `scripts/docker-deep-debug.sh`:

```bash
#!/usr/bin/env bash
# Run deep-debug.sh inside Dockerfile.deep-debug. Repo root mounted at /workspace.
# Usage: ./scripts/docker-deep-debug.sh [--privileged] [--] [extra args passed to deep-debug.sh]
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
  bash scripts/deep-debug.sh "$@"
```

Run: `chmod +x scripts/docker-deep-debug.sh`

- [ ] **Step 2: Smoke test**

Run: `bash scripts/docker-deep-debug.sh -- --help` only after Task 4 adds `--help` to `deep-debug.sh`; until then run: `docker run --rm coldstep-deep-debug:local bash -lc 'ls /workspace'` with manual mount — or defer this step until Task 4 completes.

Re-order note: Task 4 creates `deep-debug.sh` first; **move smoke test** to after Task 4 or combine Task 3 commit after Task 4.

**Adjusted order:** Implement Task 4 next, then return to mark Task 3 Step 2 complete with `bash scripts/docker-deep-debug.sh` running stages 0 only (`DEEP_DEBUG_ONLY_STAGE=0` if implemented).

- [ ] **Step 3: Commit** (after Task 4 exists)

```bash
git add scripts/docker-deep-debug.sh
chmod +x scripts/docker-deep-debug.sh
git commit -S -m "build: docker wrapper for deep-debug pass"
```

---

### Task 4: `scripts/deep-debug.sh` (core)

**Files:**
- Create: `scripts/deep-debug.sh`
- Modify: (none yet)
- Test: `DEEP_DEBUG_STAGES=max bash scripts/deep-debug.sh` inside container after image build

**Environment variables (document in script header):**

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `DEEP_DEBUG_OUT` | `$REPO_ROOT/.coldstep-deep-debug` | Log and report directory |
| `DEEP_DEBUG_RUN_3B` | `1` | Run nightly-style stage 3b (shuffle, govulncheck, full race) |
| `DEEP_DEBUG_RUN_4` | `0` | Run sudo integration tests (requires privileged + host BTF) |
| `DEEP_DEBUG_GOVULNCHECK` | `1` | Sub-toggle for govulncheck inside 3b |
| `DEEP_DEBUG_SHUFFLE` | `1` | Sub-toggle for `go test -shuffle` |
| `DEEP_DEBUG_RACE_FULL` | `0` | Full-module race (slow; matches nightly manual default) |
| `DEEP_DEBUG_CI` | unset / `1` | Set by workflow to skip comments about Docker-only paths |

- [ ] **Step 1: Create `scripts/deep-debug.sh`**

Create the full script below (single file).

```bash
#!/usr/bin/env bash
# Deep debug pass — stages aligned with coldstep-ci-runner + coldstep-ci-nightly.
# See .github/design/2026-04-18-deep-debug-pass-design.md
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
run_cmd 0 utf8             python3 scripts/assert_utf8_text.py                 || S0_OK=1
run_cmd 0 pins           python3 scripts/check_workflow_action_pins.py         || S0_OK=1
run_cmd 0 unittest       python3 -m unittest discover -s scripts -p "test_*.py" -v || S0_OK=1
run_cmd 0 shell_markers  bash scripts/test_workflow_diff_markers.sh            || S0_OK=1
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
  run_cmd 2 gofmt        bash scripts/check-gofmt.sh                         || S2_OK=1
  run_cmd 2 bpf_build    bash scripts/build-agent-linux.sh "$ROOT"           || S2_OK=1
  run_cmd 2 vet          go vet ./...                                       || S2_OK=1
  run_cmd 2 staticcheck  bash -lc 'go install honnef.co/go/tools/cmd/staticcheck@v0.7.0 && "$(go env GOPATH)/bin/staticcheck" ./...' || S2_OK=1
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
    run_cmd 3b govulncheck bash -lc 'go install golang.org/x/vuln/cmd/govulncheck@latest && "$(go env GOPATH)/bin/govulncheck" ./...' || S3B_ANY=1
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
{
  echo "# Deep debug report"
  echo ""
  echo "| Field | Value |"
  echo "| ----- | ----- |"
  echo "| Timestamp (UTC) | $TS |"
  echo "| Commit | $(git rev-parse HEAD 2>/dev/null || echo unknown) |"
  echo "| P0 gate | $([[ "$P0_FAIL" -eq 0 ]] && echo OK || echo FAIL) |"
  echo "| Stage 3a | $([[ "$FAIL_3A" -eq 0 ]] && echo OK || echo FAIL) |"
  echo "| Output dir | $LOGDIR |"
  echo ""
} >"$SUMMARY_FILE"
cat "$REPORT" >>"$SUMMARY_FILE"
mv "$SUMMARY_FILE" "$REPORT"

echo "Report: $REPORT" >&2
FAIL_ANY=0
[[ "$P0_FAIL" -eq 0 ]] || FAIL_ANY=1
[[ "$FAIL_3A" -eq 0 ]] || FAIL_ANY=1
[[ "${S3B_ANY:-0}" -eq 0 ]] || FAIL_ANY=1
[[ "${S4_ANY:-0}" -eq 0 ]] || FAIL_ANY=1
exit "$FAIL_ANY"
```

**Implementation notes:** Script uses **`set -u` only** (no global `set -e`) so each stage runs all commands. **`run_cmd`** captures **`${PIPESTATUS[0]}`** after `tee`. Do **not** enable **`set -e`** in `run_cmd` (would leak into caller in some Bash builds). Initialize **`S3B_ANY`** / **`S4_ANY`** with the other counters so skipped stages do not trip `set -u`.

- [ ] **Step 2: chmod +x**

```bash
chmod +x scripts/deep-debug.sh
```

- [ ] **Step 3: Run locally (Docker)**

```bash
docker build -f Dockerfile.deep-debug -t coldstep-deep-debug:local .
docker run --rm -v "${PWD}:/workspace" -w /workspace golang:1.24-bookworm bash -lc 'apt-get update && apt-get install -y git && git config --global --add safe.directory /workspace && bash scripts/deep-debug.sh'
```

Use full image `coldstep-deep-debug:local` once built. Expect possible **stage 2 / BTF** failure in environments without `/sys/kernel/btf/vmlinux` — document in report under P3.

- [ ] **Step 4: Commit**

```bash
git add scripts/deep-debug.sh
git commit -S -m "feat: deep-debug staged check driver with markdown report"
```

---

### Task 5: GitHub Actions workflow `coldstep-deep-debug.yml`

**Files:**
- Create: `.github/workflows/coldstep-deep-debug.yml`
- Test: Push branch and run **workflow_dispatch** manually in Actions UI

- [ ] **Step 1: Add workflow**

Create `.github/workflows/coldstep-deep-debug.yml`:

```yaml
name: coldstep deep-debug

on:
  workflow_dispatch:
    inputs:
      run_3b:
        description: Run nightly-style checks (shuffle, govulncheck; optional full race)
        type: boolean
        default: true
      govulncheck:
        description: Include govulncheck in 3b
        type: boolean
        default: true
      shuffle:
        description: Include go test -shuffle in 3b
        type: boolean
        default: true
      race_full:
        description: Full-module race (slow)
        type: boolean
        default: false
      run_4_integration:
        description: Run sudo integration tests (BPF; may fail on some runners)
        type: boolean
        default: false

permissions:
  contents: read

env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true
  GOTOOLCHAIN: auto

jobs:
  deep-debug:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    steps:
      - uses: actions/checkout@v6

      - uses: actions/setup-go@v6
        with:
          go-version: '1.24.x'

      - uses: actions/setup-node@v6
        with:
          node-version: '24'
          cache: npm

      - name: Upload deep-debug report
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: coldstep-deep-debug-${{ github.run_id }}
          path: .coldstep-deep-debug/
          if-no-files-found: warn

      - name: Run deep-debug script
        env:
          DEEP_DEBUG_CI: '1'
          DEEP_DEBUG_RUN_3B: ${{ inputs.run_3b && '1' || '0' }}
          DEEP_DEBUG_GOVULNCHECK: ${{ inputs.govulncheck && '1' || '0' }}
          DEEP_DEBUG_SHUFFLE: ${{ inputs.shuffle && '1' || '0' }}
          DEEP_DEBUG_RACE_FULL: ${{ inputs.race_full && '1' || '0' }}
          DEEP_DEBUG_RUN_4: ${{ inputs.run_4_integration && '1' || '0' }}
        run: bash scripts/deep-debug.sh
```

**Implementation fix:** Move **checkout/setup** before **run script**, and move **upload-artifact** after **run** (artifact must capture completed logs). Correct order:

1. checkout  
2. setup-go  
3. setup-node  
4. `npm ci` is **inside** `deep-debug.sh` stage 1 — OK  
5. run `bash scripts/deep-debug.sh`  
6. upload-artifact  

Rewrite Step 1 accordingly.

- [ ] **Step 2: Fix step order** — ensure `upload-artifact` runs **after** `Run deep-debug script`, not before.

Corrected snippet for job steps:

```yaml
    steps:
      - uses: actions/checkout@v6

      - uses: actions/setup-go@v6
        with:
          go-version: '1.24.x'

      - uses: actions/setup-node@v6
        with:
          node-version: '24'
          cache: npm

      - name: Run deep-debug script
        env:
          DEEP_DEBUG_CI: '1'
          DEEP_DEBUG_RUN_3B: ${{ inputs.run_3b && '1' || '0' }}
          DEEP_DEBUG_GOVULNCHECK: ${{ inputs.govulncheck && '1' || '0' }}
          DEEP_DEBUG_SHUFFLE: ${{ inputs.shuffle && '1' || '0' }}
          DEEP_DEBUG_RACE_FULL: ${{ inputs.race_full && '1' || '0' }}
          DEEP_DEBUG_RUN_4: ${{ inputs.run_4_integration && '1' || '0' }}
        run: bash scripts/deep-debug.sh

      - name: Upload deep-debug output
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: coldstep-deep-debug-${{ github.run_id }}
          path: .coldstep-deep-debug/
          if-no-files-found: warn
```

- [ ] **Step 3: Manual dispatch**

Push branch → Actions → **coldstep deep-debug** → Run workflow → Confirm job completes or fails with logs.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/coldstep-deep-debug.yml
git commit -S -m "ci: add workflow_dispatch deep-debug pass"
```

---

### Task 6: Wire Task 3 smoke test + README pointer

**Files:**
- Modify: `README.md` (optional one paragraph — user preference: minimal; **prefer** adding a single line under an existing “Development” area if present)

- [ ] **Step 1: Search README for a suitable anchor**

If no dev section exists, add a short **“Local deep-debug”** bullet under **GitHub Actions** or **Contributing** pointer:

```markdown
- **Deep debug pass (optional):** see `scripts/deep-debug.sh` and `Dockerfile.deep-debug`; CI: workflow **coldstep deep-debug** (`workflow_dispatch`).
```

- [ ] **Step 2: Final smoke**

`bash scripts/docker-deep-debug.sh` from repo root (Linux/macOS Docker) or document PowerShell:

```powershell
docker build -f Dockerfile.deep-debug -t coldstep-deep-debug:local .
docker run --rm -v "${PWD}:C:/workspace" ...  # prefer Git Bash path for volume on Windows
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -S -m "docs: mention deep-debug pass entry points"
```

Skip README commit if maintaining zero README churn — then **omit Task 6** per YAGNI.

---

## Plan self-review

| Spec section | Covered by tasks |
| ------------ | ---------------- |
| Docker local run | Task 2, 3, 4 |
| CI confirmation | Task 5 |
| Triage report | Task 4 (`report.md`) |
| `.coldstep-deep-debug/` | Task 1 |
| P0 / 3a gating | Task 4 logic |
| Parity / same script on CI | Task 5 calls `scripts/deep-debug.sh` |

**Placeholder scan:** No TBD — note Task 4 requires tightening 3b failure accounting in implementation (called out inline).

**Gaps addressed:** Workflow step order corrected; Docker wrapper committed after `deep-debug.sh` exists.

---

## Execution handoff

**Plan complete** and saved to **`.github/design/2026-04-18-deep-debug-pass-implementation-plan.md`** (tracked path; `docs/superpowers/plans/` is gitignored in this repo).

**Two execution options:**

1. **Subagent-driven (recommended)** — dispatch a fresh subagent per task, review between tasks.  
2. **Inline execution** — run tasks in this session with **executing-plans**, batching with checkpoints.

**Which approach do you want?**
