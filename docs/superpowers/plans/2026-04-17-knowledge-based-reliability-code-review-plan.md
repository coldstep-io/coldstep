# Knowledge-Based Reliability Code Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute a full-application, reliability-first bug-finding review using the knowledge base plus targeted Docker verification, and produce a prioritized evidence-backed backlog.

**Architecture:** Review runs in four tracks (B -> C -> A -> D) with a shared loop: knowledge hypotheses, static review, targeted runtime checks, and structured finding output. Every finding must meet evidence standards and include a minimal fix direction plus test-gap annotation.

**Tech Stack:** Go, eBPF, TypeScript/Node, GitHub Actions workflows, Docker, markdown knowledge vault.

---

## File Map (planned outputs and touched artifacts)

- Create: `knowledge/reports/2026-04-17-reliability-code-review-findings.md` (master findings report)
- Modify: `knowledge/wiki/ebpf-debugging-testing-security-telemetry.md` (if new reliability references are used)
- Modify: `knowledge/wiki/secure-code-sre-testing.md` (if new testing/reliability references are used)
- Modify: `knowledge/raw/*.md` (only for new canonical URLs consulted)
- Modify: `knowledge/records/*.md` (source-cache entries for new consulted URLs)
- Test/verify via commands (no production code edits in this plan)

### Task 1: Establish review workspace and baseline evidence

**Files:**
- Modify: `knowledge/reports/2026-04-17-reliability-code-review-findings.md` (create initial structure)

- [ ] **Step 1: Create findings report skeleton**

Create file with sections:
- Scope and success criteria
- Track status board
- Findings table (ID, severity, confidence, repro, component)
- Per-finding detail blocks
- Test-gap inventory
- Fix sequencing recommendation

- [ ] **Step 2: Capture repository state snapshot**

Run: `git status --short`
Expected: no destructive actions; snapshot copied into report "Baseline".

- [ ] **Step 3: Capture available validation commands from workflows**

Run: `rg "go test|go vet|staticcheck|npm run|vitest|jest|workflow_dispatch|coldstep_diff" .github/workflows scripts -n`
Expected: command inventory lines for later targeted verification.

- [ ] **Step 4: Record baseline in report**

Add:
- Timestamp
- Current branch
- Candidate verification commands list

---

### Task 2: Build knowledge-grounded hypothesis list per track

**Files:**
- Modify: `knowledge/reports/2026-04-17-reliability-code-review-findings.md`

- [ ] **Step 1: Extract Track B hypotheses (agent/eBPF lifecycle)**

Read and summarize failure modes from:
- `knowledge/wiki/ebpf-coldstep-bpf-c.md`
- `knowledge/wiki/ebpf-debugging-testing-security-telemetry.md`
- `knowledge/reports/2026-04-16-fix-exec-ringbuf-early-exit-leak.md`

Expected: 5-10 concrete hypotheses (e.g., cleanup ordering, attach/read lifecycle).

- [ ] **Step 2: Extract Track C hypotheses (telemetry/report integrity)**

Read and summarize from:
- `knowledge/wiki/secure-code-sre-testing.md`
- `knowledge/wiki/ebpf-github-actions.md`

Expected: 5-10 concrete hypotheses (parse robustness, aggregation drift, diff integrity).

- [ ] **Step 3: Extract Track A hypotheses (Action runtime)**

Read and summarize from:
- `knowledge/wiki/github-actions-security.md`
- `knowledge/raw/github-actions-security-hardening.md`

Expected: 3-8 reliability hypotheses (input handling, post-step assumptions, state handoff).

- [ ] **Step 4: Extract Track D hypotheses (workflow/scripts)**

Read and summarize from:
- `.github/workflows/*.yml`
- `scripts/ci_coldstep_jsonl_traffic_diff.py`

Expected: 3-8 hypotheses (false-green pathways, baseline artifact assumptions, strict mode behavior).

---

### Task 3: Execute static review for Track B (Go agent + eBPF)

**Files:**
- Modify: `knowledge/reports/2026-04-17-reliability-code-review-findings.md`

- [ ] **Step 1: Inspect lifecycle-critical code paths**

Run:
- `rg "NewReader|Close\\(|Attach|link\\.|defer|return retErr|context|cancel" internal/agent internal/bpf bpf -n`
Expected: list of lifecycle hotspots logged in report.

- [ ] **Step 2: Trace error propagation paths**

Run:
- `rg "if err != nil|errors\\.Join|fmt\\.Errorf|return .*err" internal/agent internal/bpf -n`
Expected: explicit list of potential swallowed/misclassified errors.

- [ ] **Step 3: Evaluate concurrency and shared-state assumptions**

Run:
- `rg "go func|chan|mutex|atomic|select\\s*\\{|WaitGroup" internal/agent internal/telemetry -n`
Expected: concurrency hotspots with candidate race/deadlock hypotheses.

- [ ] **Step 4: Write candidate findings**

For each candidate, add to report:
- ID
- hypothesis
- code locations
- expected failure mode
- planned runtime check

---

### Task 4: Run targeted Docker verification for Track B candidates

**Files:**
- Modify: `knowledge/reports/2026-04-17-reliability-code-review-findings.md`

- [ ] **Step 1: Select top 3-5 high-confidence Track B hypotheses**

Expected: ranked list by blast radius + reproducibility.

- [ ] **Step 2: Execute focused containerized checks**

Run (adapt from existing scripts/workflows):
- `docker build ...` (project-standard image if available)
- `docker run ... go test ./...` (scoped package targets first)
- `docker run ... go test -race ./...` (scoped targets when feasible)

Expected: pass/fail evidence captured with exact command and output excerpts.

- [ ] **Step 3: Promote candidates to validated findings**

Update report:
- observed vs expected
- confidence
- repro status
- minimal fix direction
- missing test

---

### Task 5: Execute Track C review (telemetry/report correctness)

**Files:**
- Modify: `knowledge/reports/2026-04-17-reliability-code-review-findings.md`

- [ ] **Step 1: Static parse/transform audit**

Run:
- `rg "parse|sanitize|marshal|unmarshal|json|digest|summary|diff|baseline" internal/telemetry internal/report scripts -n`
Expected: parser/integrity hotspots and edge-case map.

- [ ] **Step 2: Validate assumptions against negative cases**

Run targeted checks in Docker for selected components/scripts (smallest command set needed).
Expected: evidence for malformed input handling and deterministic output behavior.

- [ ] **Step 3: Record validated findings and non-findings**

Expected: updated findings table and explicit "tested-no-bug" notes for major hypotheses.

---

### Task 6: Execute Track A and Track D review (Action runtime + workflows)

**Files:**
- Modify: `knowledge/reports/2026-04-17-reliability-code-review-findings.md`

- [ ] **Step 1: Action runtime static audit**

Run:
- `rg "core\\.|getInput|setFailed|saveState|getState|process\\.env|try|catch" src action.yml -n`
Expected: input/state/error-path reliability map.

- [ ] **Step 2: Workflow gate audit**

Run:
- `rg "if:|needs:|continue-on-error|permissions:|COLDSTEP_DIFF|upload-artifact|download-artifact" .github/workflows -n`
Expected: candidate false-green and orchestration reliability risks.

- [ ] **Step 3: Targeted runtime checks for top workflow hypotheses**

Run containerized or script-level checks where feasible.
Expected: documented evidence for each promoted finding.

---

### Task 7: Finalize backlog quality, sequencing, and handoff

**Files:**
- Modify: `knowledge/reports/2026-04-17-reliability-code-review-findings.md`

- [ ] **Step 1: Normalize all finding entries to required schema**

Each finding must include:
- Severity
- Confidence
- Repro
- Evidence
- Minimal fix direction
- Test gap

- [ ] **Step 2: Build fix sequence**

Order findings by:
1) blast radius
2) reproducibility
3) confidence
4) implementation complexity

- [ ] **Step 3: Add execution-ready summary**

Include:
- Top 5 issues to patch first
- Tests to add first
- Risks if deferred

- [ ] **Step 4: Final consistency check**

Run: `rg "TODO|TBD|placeholder|later" knowledge/reports/2026-04-17-reliability-code-review-findings.md -n`
Expected: no placeholder output.

---

## Spec Coverage Check

- Covered: 4-track architecture (B -> C -> A -> D).
- Covered: evidence standard (repro/observed-vs-expected/confidence/artifacts/fix/test-gap).
- Covered: knowledge-driven hypothesis generation.
- Covered: Docker-targeted runtime verification.
- Covered: final prioritized backlog and fix sequencing.

No uncovered spec requirements identified.

## Placeholder Scan

- No `TBD`, `TODO`, or ambiguous "implement later" directives in plan steps.

## Type/Name Consistency Check

- Track names and order remain consistent with design spec.
- Output artifact path remains consistent across tasks.
