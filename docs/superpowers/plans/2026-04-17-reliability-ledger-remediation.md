# Reliability ledger remediation — Implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Deprecation note:** The Cursor command `/write-plan` is deprecated; this plan was produced using the **superpowers writing-plans** skill.

**Goal:** Close or verify the 12 findings (`B-SR-01` … `D-SR-02`) in [`knowledge/reports/2026-04-17-reliability-code-review-findings.md`](../../../knowledge/reports/2026-04-17-reliability-code-review-findings.md) against the **current** `dev`/`main` tree, then implement **remaining** tests and behaviour so observability and CI contracts match the ledger.

**Architecture:** Work in **finding-ID order** from the ledger’s fix sequence (§ Fix sequencing recommendation): diff script contracts first (broad CI blast radius), then agent ring/digest signalling, then workflow summary contracts, then lower-severity polish. Each task ends with **Docker-based** verification per `AGENTS.md` (Linux toolchain), **signed commits** on `dev` only.

**Tech stack:** Go 1.24.x, Python 3.12+ (`unittest`), GitHub Actions reusable workflows, `coldstep-ci-runner.yml`.

**P0 / PR CI (must be green before reliability tasks):** As of 2026-04-17, **PR #21** / `coldstep-ci` fails on **`hosted-linux / integration (ubuntu-22.04)`** and **`(ubuntu-22.04-arm)`** only; other matrix legs pass. Log pattern:

`field HandleRawSysEnter: program handle_raw_sys_enter: load program: permission denied: … call bpf_probe_read_user#112: R2 min value is negative, either use unsigned or 'var &= const'`

**Cause:** Strict eBPF verifiers on those images reject **chained** `bpf_probe_read_user` calls at **userspace base + small offset** (e.g. `(void *)(msg_hdr_ptr + 16)` in **sendmsg** path), even after **sockaddr** and **HTTP/TLS** mitigations.

**Fix (landed same session as this plan update):** [`bpf/trace_udp_sendmsg.inc`](../../../bpf/trace_udp_sendmsg.inc) — read **one 32-byte** slab from the userspace `struct msghdr` (`coldstep_read_msghdr_head32`), then **`__builtin_memcpy`** fields at offsets **0 / 8 / 16 / 24** (LP64 layout). No `msg_hdr_ptr + N` probe sources.

Knowledge cross-links: [[reports/2026-04-17-ci-matrix-bpf-verifier-ubuntu2204]](../../../knowledge/reports/2026-04-17-ci-matrix-bpf-verifier-ubuntu2204.md), [[wiki/ebpf-linux-prerequisites]](../../../knowledge/wiki/ebpf-linux-prerequisites.md).

---

## File structure (planned touch surface)

| Area | Primary files |
| --- | --- |
| JSONL diff / CI summaries | [`scripts/ci_coldstep_jsonl_traffic_diff.py`](../../../scripts/ci_coldstep_jsonl_traffic_diff.py), [`scripts/test_ci_coldstep_jsonl_traffic_diff.py`](../../../scripts/test_ci_coldstep_jsonl_traffic_diff.py) |
| Agent telemetry + digest | [`internal/agent/agent_linux.go`](../../../internal/agent/agent_linux.go), [`internal/agent/agent_linux_test.go`](../../../internal/agent/agent_linux_test.go), [`internal/report/digest.go`](../../../internal/report/digest.go), [`internal/telemetry/telemetry.go`](../../../internal/telemetry/telemetry.go) |
| Composite action | [`src/main.ts`](../../../src/main.ts), [`src/post.ts`](../../../src/post.ts), [`tests/` action tests if present](../../../tests) |
| Workflows | [`.github/workflows/coldstep-ci-runner.yml`](../../../.github/workflows/coldstep-ci-runner.yml), demo workflows |
| **P0 BPF / CI unblock** | [`bpf/trace_udp_sendmsg.inc`](../../../bpf/trace_udp_sendmsg.inc), [`bpf/trace_connect_obs.h`](../../../bpf/trace_connect_obs.h), [`bpf/trace_http_obs.inc`](../../../bpf/trace_http_obs.inc), [`bpf/trace_tls_write.inc`](../../../bpf/trace_tls_write.inc) |

---

### Task 0: P0 — Unblock PR (`integration` on `ubuntu-22.04` / `ubuntu-22.04-arm`)

**Blocks:** Reliability remediation work should not proceed on a permanently red **`coldstep-ci`** integration matrix.

**Files:**
- Modify: [`bpf/trace_udp_sendmsg.inc`](../../../bpf/trace_udp_sendmsg.inc) — **single** `bpf_probe_read_user(..., 32, msg_hdr_ptr)` for LP64 `msghdr` head; remove `msg_hdr_ptr + 8/+16/+24` probe targets.
- Verify: `bash scripts/build-agent-linux.sh` (Linux Docker image with clang/libbpf).

- [ ] **Step 1: Implement msghdr head read** (pattern above; align with merged `dev`).

- [ ] **Step 2: Docker build**

```bash
docker run --rm -v "$REPO:/src" -w /src golang:1.24-bookworm bash -c \
  'apt-get update -qq && apt-get install -y -qq clang llvm libelf-dev libbpf-dev >/dev/null && bash scripts/build-agent-linux.sh /src'
```

Expected: exit **0**.

- [ ] **Step 3: Docker integration tests (optional but recommended before push)**

```bash
docker run --rm -v "$REPO:/src" -w /src --privileged golang:1.24-bookworm bash -c \
  'apt-get update -qq && apt-get install -y -qq clang llvm libelf-dev libbpf-dev sudo >/dev/null && \
   go test -tags=integration ./internal/agent/... -count=1'
```

- [ ] **Step 4: Confirm GitHub PR checks**

```bash
gh pr checks 21
```

Expected: **`integration (ubuntu-22.04)`** and **`integration (ubuntu-22.04-arm)`** → **pass** (or re-open verifier log if still failing).

- [ ] **Step 5: Commit + push `dev` (signed)**

```bash
git add bpf/trace_udp_sendmsg.inc
git commit -S -m "fix(bpf): read msghdr head in one probe for ubuntu-22.04 verifier"
git push origin dev
```

---

### Task 1: Ledger reconciliation vs repository (no code change)

**Files:**
- Read-only: [`knowledge/reports/2026-04-17-reliability-code-review-findings.md`](../../../knowledge/reports/2026-04-17-reliability-code-review-findings.md)
- Read-only: [`scripts/ci_coldstep_jsonl_traffic_diff.py`](../../../scripts/ci_coldstep_jsonl_traffic_diff.py), [`internal/agent/agent_linux.go`](../../../internal/agent/agent_linux.go)

- [ ] **Step 1: Build a mapping table**

For each finding ID, record **Implemented / Partial / Open** with one evidence line (function name or workflow env var). **Current tree hints:** `traffic_fingerprint` already includes `path_hash` for HTTP; `main()` emits `parse.*` markers and `strict_mode` exit `1` when invalid lines exist **and** both sides parsed non-empty events; `DroppedCounts` exists on meta/digest paths.

- [ ] **Step 2: Document gaps**

List only IDs still **Open** or **Partial** after Step 1; these drive Tasks 2–6.

**Verification:** Produce a short markdown subsection (can live in Task 1 PR description) — no automated test.

---

### Task 2: `C-SR-01` — JSONL diff strict + empty baseline/current contract

**Finding:** Parser health vs **exit code** when files are missing, empty after parse, or malformed-heavy.

**Files:**
- Modify: [`scripts/ci_coldstep_jsonl_traffic_diff.py`](../../../scripts/ci_coldstep_jsonl_traffic_diff.py) — only if Step 1 shows gap vs desired contract
- Modify: [`scripts/test_ci_coldstep_jsonl_traffic_diff.py`](../../../scripts/test_ci_coldstep_jsonl_traffic_diff.py)

- [ ] **Step 1: Write failing tests for the exact contract**

Add tests under `DiffScriptTests` that cover:

1. Both inputs parse to **non-empty** events but **both** have `invalid>0` → expect `parse.health=degraded` and exit `1` when `COLDSTEP_DIFF_STRICT=1`.
2. **Empty after parse** path (`not base_ev or not cur_ev`) → expect markers `parse.base_invalid`, `parse.health`, exit `1` iff strict.

Example skeleton (adjust assertions to match current `main()`):

```python
def test_strict_fails_when_decode_errors_with_nonempty_events(self):
    import os, tempfile
    # baseline: one valid line + one invalid
    # current: same
    # env: COLDSTEP_DIFF_STRICT=1, NS_SUMMARY, NS_BASELINE, NS_CURRENT, NS_MARKER
    # assert exit code 1 and summary contains parse.health=degraded
```

- [ ] **Step 2: Run tests — expect FAIL until logic matches**

```bash
docker run --rm -v "c:/GitHub/coldstep:/src" -w /src/scripts python:3.12-bookworm \
  python -m unittest test_ci_coldstep_jsonl_traffic_diff -v
```

- [ ] **Step 3: Minimal script changes**

Only adjust branching if Step 1 proved a gap (e.g. strict should fail when `invalid>0` even if drift tables empty).

- [ ] **Step 4: Re-run unittest — PASS**

- [ ] **Step 5: Commit (signed)**

```bash
git add scripts/ci_coldstep_jsonl_traffic_diff.py scripts/test_ci_coldstep_jsonl_traffic_diff.py
git commit -S -m "fix(diff): tighten C-SR-01 strict parse-health contract tests"
```

---

### Task 3: `B-SR-01` — dropped-event surfaces + threshold policy

**Finding:** Ring decode / JSONL append failures must not be **silent** beyond warn logs.

**Files:**
- Modify: [`internal/agent/agent_linux.go`](../../../internal/agent/agent_linux.go) — ensure every drop path calls `runStats.addDropped(kind)` with stable `kind` strings
- Modify: [`internal/report/digest.go`](../../../internal/report/digest.go) — ensure digest renders non-zero dropped totals when present
- Modify: [`internal/agent/agent_linux_test.go`](../../../internal/agent/agent_linux_test.go)

- [ ] **Step 1: Audit `addDropped` coverage**

`rg -n "addDropped|addDropped\\(" internal/agent/agent_linux.go` — list each ring reader error branch; any path that `continue` without `addDropped` is a bug candidate.

- [ ] **Step 2: Write integration-style unit test**

Extend [`TestRun_BuildsDigestInputWithDroppedSignals`](../../../internal/agent/agent_linux_test.go) (or add parallel test) to assert **each** simulated drop kind appears in `DigestInput.DroppedCounts` after controlled decode failure fixtures.

Minimal pattern (pseudo — use real helpers from file):

```go
func TestRun_DroppedCounts_AllRingKinds(t *testing.T) {
    // Build minimal stats / digest input using same helpers as TestRun_BuildsDigestInput...
    // For each kind in []string{"udp_decode", "http_decode", ...} verify digest template includes counts
}
```

- [ ] **Step 3: Implement missing `addDropped` calls**

One commit per subsystem if large; else single commit.

- [ ] **Step 4: Docker Go test**

```bash
docker run --rm -v "c:/GitHub/coldstep:/src" -w /src golang:1.24-bookworm \
  go test ./internal/agent/... ./internal/report/... -count=1
```

- [ ] **Step 5: Commit (signed)**

---

### Task 4: `D-SR-01` — workflow summary contract for strict vs relaxed

**Finding:** When diff is unavailable, summaries must state **policy=relaxed** vs strict failure clearly.

**Files:**
- Read-only: [`.github/workflows/coldstep-ci-runner.yml`](../../../.github/workflows/coldstep-ci-runner.yml) (`detect-mode` bash + Python env)
- Modify (if needed): same file — only marker text / step summary links

- [ ] **Step 1: Grep markers**

`rg -n "coldstep-prev-diff|COLDSTEP_DIFF_STRICT|NS_MARKER" .github/workflows/coldstep-ci-runner.yml`

- [ ] **Step 2: Add a shell-level contract test OR document checklist**

Because full GHA is hard to unit-test locally, add **`scripts/test_workflow_diff_markers.sh`** (bash) that exports fake env and asserts stdout contains `policy=relaxed` when strict off:

```bash
#!/usr/bin/env bash
set -euo pipefail
export NS_SUMMARY="$(mktemp)"
export NS_BASELINE="$(mktemp)"
export NS_CURRENT="$(mktemp)"
echo '{"type":"tcp"}' > "$NS_BASELINE"
echo '{"type":"tcp"}' > "$NS_CURRENT"
export COLDSTEP_DIFF_STRICT=0
python3 scripts/ci_coldstep_jsonl_traffic_diff.py || true
grep -q "policy=relaxed" "$NS_SUMMARY"
```

- [ ] **Step 3: Run in Docker**

```bash
docker run --rm -v "c:/GitHub/coldstep:/src" -w /src ubuntu:22.04 bash scripts/test_workflow_diff_markers.sh
```

- [ ] **Step 4: Commit (signed)**

---

### Task 5: `C-SR-03` — unclassified totals in workflow visibility

**Finding:** Unclassified event types must be visible in summary decisions.

**Files:**
- Likely already partially in [`scripts/ci_coldstep_jsonl_traffic_diff.py`](../../../scripts/ci_coldstep_jsonl_traffic_diff.py) (`unclassified.base_total`)

- [ ] **Step 1: Verify markers exist** in successful diff path (`grep unclassified`).

- [ ] **Step 2: Add unittest** that fixtures with only `type: "unknown_event"` produce non-zero `unclassified` counters and optional `changed` result.

- [ ] **Step 3: Commit (signed)**

---

### Task 6: `C-SR-02` — long HTTP path drift (verify hash tail)

**Files:**
- [`scripts/ci_coldstep_jsonl_traffic_diff.py`](../../../scripts/ci_coldstep_jsonl_traffic_diff.py) (`traffic_fingerprint` http branch)

- [ ] **Step 1: Write unittest** two HTTP events identical except path differs after char 121 — expect **different** fingerprints (hash diverges).

```python
def test_http_paths_differ_after_truncation_have_distinct_fp(self):
    prefix = "/api/" + "a" * 130
    ev1 = {"type": "http", "dst": "1.1.1.1", "dport": 80, "host": "x", "method": "GET", "path": prefix + "X"}
    ev2 = {"type": "http", "dst": "1.1.1.1", "dport": 80, "host": "x", "method": "GET", "path": prefix + "Y"}
    assert MOD.traffic_fingerprint(ev1) != MOD.traffic_fingerprint(ev2)
```

- [ ] **Step 2: Run unittest** — if FAIL, adjust fingerprint (should not happen if hash present).

- [ ] **Step 3: Commit (signed)**

---

### Task 7: `B-SR-02` — enforce deny vs cancellation precedence

**Files:**
- [`internal/agent/agent_linux.go`](../../../internal/agent/agent_linux.go) (`preferRunError`, `readDenyRing`, `Run` err aggregation)
- [`internal/agent/prefer_run_error_test.go`](../../../internal/agent/prefer_run_error_test.go)

- [ ] **Step 1: Extend table tests** for cancellation + synthetic deny errors (already started in `prefer_run_error_test.go`).

- [ ] **Step 2: Run race detector in Docker**

```bash
docker run --rm -v "c:/GitHub/coldstep:/src" -w /src golang:1.24-bookworm \
  go test -race -count=1 ./internal/agent/... -timeout 15m -run 'PreferRun|Deny'
```

- [ ] **Step 3: Commit (signed)** only if code changes.

---

### Task 8: `B-SR-03` / `B-SR-04` — optional map failures + LPM error wrap

**Files:**
- [`internal/agent/agent_linux.go`](../../../internal/agent/agent_linux.go) (`TlsAgentCfg.Update`, `FsAgentCfg.Update`, `loadIgnoredLPMMap`)
- Tests: [`internal/agent/agent_linux_test.go`](../../../internal/agent/agent_linux_test.go)

- [ ] **Step 1: Fault-injection tests** using ebpf map update mocks if available; else skip with documented **deferred** in ledger.

- [ ] **Step 2: Wrap `loadIgnoredLPMMap` errors** consistently if test proves raw passthrough (`B-SR-04`).

---

### Task 9: `C-SR-04`, `C-SR-05`, `A-SR-01`, `D-SR-02` — lower priority

- [ ] **`C-SR-04`:** Add normalization tests for volatile `other_fingerprint` fields if noise persists.
- [ ] **`C-SR-05`:** Golden test for `multiset_diff` sort order (may already exist — verify).
- [ ] **`A-SR-01`:** Add Vitest/Node tests for `src/main.ts` input validation if gaps found.
- [ ] **`D-SR-02`:** Inventory `uses:` pins; optional SHA pinning for high-impact actions.

---

## Self-review (writing-plans checklist)

| Check | Status |
| --- | --- |
| Spec coverage | Each ledger finding maps to Task 1–9 |
| Placeholders | No `TBD` implementation — deferred items explicitly “verify first” |
| Type/consistency | Finding IDs match ledger |

---

## Execution handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-17-reliability-ledger-remediation.md`.**

**Two execution options:**

1. **Subagent-driven (recommended)** — Dispatch a fresh subagent per task; review between tasks.
2. **Inline execution** — Run tasks in this session with `executing-plans` checkpoints.

**Which approach do you want?**
