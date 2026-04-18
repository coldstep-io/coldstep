# Coldstep CI reliability + eBPF hardening + second brain — implementation program

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Status (2026-04-18):** **Task 10** regression tests landed via **PR #26** (`test(telemetry): ringbuf reserve fields in summary JSON`). Remaining tasks below are open unless marked.

**Goal:** Drive GitHub Actions workflows to **green** where failures are product/CI defects; advance **eBPF observability/enforce** along a verifier-safe roadmap; maintain **honest threat-model** alignment with literature; and **mandatorily** capture research and decisions in the local **`knowledge/`** vault (“second brain”) before and after substantive changes.

**Architecture:** Treat work as **ordered streams** with a **brain gate**: (1) **inventory + vault search** → (2) **CI stabilization** (`coldstep-ci-runner.yml` jobs: `action_manifest`, `unit`, `unit-arm64`, `integration`, `action_bundle`, `detect-mode`, `prevent-mode`; plus `coldstep-ci-nightly.yml`) → (3) **BPF tranches** aligned to hook-class map (trace vs cgroup enforce) → (4) **telemetry/digest honesty** (loss signals; ringbuf reserve counters in **`telemetry.Summary`**) → (5) **vault synthesis reports** per milestone. **YAGNI:** do not expand IPv6 enforce or new syscall surfaces until prior tranche is green on PR CI + documented.

**Tech stack:** Go **1.25.x** (`go.mod` / `toolchain`), **cilium/ebpf**, BPF C under **`bpf/`**, GitHub Actions **`ubuntu-latest`** / matrix OS labels, **`gh` CLI** for run inventory, local **`knowledge/`** Obsidian pipeline (`records/` → `raw/` → `wiki/` → `reports/` → `Index.md`).

**Plan location (canonical):** **`docs/design/2026-04-20-coldstep-ci-ebpf-second-brain-program-implementation-plan.md`** — tracked in Git.

---

## File / area map (what may change)

| Area | Paths | Responsibility |
| ---- | ----- | -------------- |
| CI orchestration | `.github/workflows/coldstep-ci.yml`, `coldstep-ci-runner.yml`, `coldstep-ci-nightly.yml`, demo workflows | Job graph, timeouts, matrix, permissions |
| CI scripts | `scripts/check-gofmt.sh`, `scripts/build-agent-linux.sh`, `scripts/check_workflow_action_pins.py`, `scripts/ci_coldstep_jsonl_traffic_diff.py`, `scripts/test_*.py` | Preconditions for jobs |
| Agent + BPF | `internal/agent/agent_linux.go`, `bpf/*.bpf.c`, `bpf/*.inc`, `internal/bpf/**` | Load, ringbuf readers, enforce programs |
| Telemetry JSON | `internal/telemetry/*.go`, `.coldstep-telemetry.json` consumer contract | Loss counters / stats export |
| Product docs | `README.md`, `SECURITY.md` | Consumer honesty |
| Second brain (local) | `knowledge/README.md`, `knowledge/wiki/*`, `knowledge/raw/*`, `knowledge/records/*`, `knowledge/reports/*`, `knowledge/Index.md` | Research persistence (not git) |

---

### Task 1: Second brain — mandatory preflight (before any CI/BPF edit)

**Files:**
- Read: `knowledge/README.md`
- Search: `knowledge/wiki/`, `knowledge/raw/`, `knowledge/records/` (grep or Obsidian)

- [ ] **Step 1:** Open **`knowledge/README.md`** and **`knowledge/Index.md`**.

- [ ] **Step 2:** Search existing research (PowerShell from repo root):

```powershell
Select-String -Path "knowledge\wiki\*.md","knowledge\raw\*.md","knowledge\records\*.md" -Pattern "enforce|ringbuf|govulncheck|workflow|detect-mode|prevent" -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 40
```

- [ ] **Step 3:** Do **not** `git add` under `knowledge/` (vault stays local).

---

### Task 2: Second brain — CI failure inventory report (local)

**Files:**
- Create: `knowledge/reports/YYYY-MM-DD-ci-actions-inventory.md`

- [ ] **Step 1:** `gh run list --repo coldstep-io/coldstep --limit 40 --json databaseId,conclusion,displayTitle,workflowName,headBranch,url` — filter non-success.

- [ ] **Step 2:** For each failure, `gh run view <ID> --log-failed` — capture job name + first error line.

- [ ] **Step 3:** Link from **`knowledge/Index.md`**.

---

### Task 3: Fix stream — `action_manifest` job

- [ ] Reproduce: `python3 scripts/assert_utf8_text.py`, `python3 scripts/check_workflow_action_pins.py`, `python3 -m unittest discover -s scripts -p "test_*.py" -v`, `bash scripts/test_workflow_diff_markers.sh`

- [ ] Fix + signed commit + vault note in inventory report.

---

### Task 4: Fix stream — `unit` / `unit-arm64` (Go + BPF codegen)

- [ ] Docker (matches CI): `bash scripts/check-gofmt.sh`, `bash scripts/build-agent-linux.sh /workspace`, `go vet ./...`, `staticcheck ./...`, `go test ./...`, `go test -race ./internal/agent/...`

---

### Task 5: Fix stream — `integration` job (sudo + BPF)

- [ ] Privileged Docker: `sudo -E env "PATH=$PATH" go test -tags=integration ./internal/agent/... -count=1`

---

### Task 6: Fix stream — `action_bundle` (Node 24)

- [ ] `npm ci`, `npm run typecheck`, `npm run build` — commit **`dist/`** if TS changed.

---

### Task 7: Fix stream — `detect-mode` / diff baseline

- [ ] Triage JSONL assertions vs **`COLDSTEP_DIFF_STRICT`** / artifact upload.

---

### Task 8: Fix stream — `prevent-mode` (enforce)

- [ ] Verifier timeout vs deny JSONL assertions; align **`bpf/trace_enforce.bpf.c`** + policy.

---

### Task 9: Nightly — `coldstep-ci-nightly.yml`

- [ ] `govulncheck`, `-shuffle`, optional full `-race`; bump **`go.mod`** toolchain if scanner requires.

---

### Task 10: BPF tranche **E** — ringbuf reserve visibility

**Done (PR #26):** Regression test **`TestWriteSummaryIncludesRingbufReserveFields`** in **`internal/telemetry/telemetry_test.go`** locks JSON for **`udp_ringbuf_reserve_failures`** / **`dns_ringbuf_reserve_failures`**.

**Still optional:**
- [ ] Add **`connect_events` / `http_events`** ringbuf reserve failure maps (mirror UDP/DNS) **only** if product needs symmetry — document defer in **`knowledge/reports/`** if skipping.

---

### Task 11: BPF tranche **A** — UDP path coverage (`sendmsg` / connected UDP)

- [ ] Document hooks in **`knowledge/wiki/ebpf-coldstep-bpf-c.md`** (`bpf/trace_udp_sendmsg.inc`, **`trace_connect.bpf.c`**).
- [ ] Add **`integration`** scenario where feasible.

---

### Task 12: BPF tranche **D** — DNS / TLS visibility counters

- [ ] Prefer userspace counters from existing ringbuf parses before new BPF probes.

---

### Task 13: BPF tranche **B** — IPv6 cgroup enforce

- [ ] **Defer** unless README/product expands scope — record in **`knowledge/reports/`**.

---

### Task 14: BPF tranche **C** — cgroup attach / job scoping

- [ ] Validate with **`internal/cgroup/path_linux.go`** + vault note.

---

### Task 15: Adversarial honesty — docs

- [ ] **`SECURITY.md`** language stays aligned with literature (no universal-coverage claims).

---

### Task 16: Program closure

- [ ] Milestone report in **`knowledge/reports/`** + PR to **`main`** per policy.

---

## Execution handoff

**Two execution options:** (1) Subagent-driven per task. (2) **executing-plans** inline with checkpoints.
