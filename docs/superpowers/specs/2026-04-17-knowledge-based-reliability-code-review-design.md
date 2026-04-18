# Knowledge-Based Reliability Code Review Design

Date: 2026-04-17  
Scope: Entire coldstep application, reliability/correctness-first bug discovery, with targeted Docker verification.

## 1) Goal and Success Criteria

Primary objective:
- Find high-impact reliability/correctness bugs across the full application.

Success criteria:
- Produce a prioritized bug backlog with reproducible evidence or deterministic code-trace reasoning.
- Maximize findings that are patch-ready and testable.
- Keep review bounded to actionable reliability issues (avoid broad refactor drift).

Non-goals:
- Full feature redesign/refactor.
- Security-only deep audit as primary axis (security findings still captured if found).

## 2) Review Architecture

Use a four-track review model with a shared loop per track.

Shared loop:
1. Knowledge-grounded hypothesis pass
   - Derive likely failure modes from `knowledge/wiki/*`, `knowledge/raw/*`, and `knowledge/records/*`.
2. Static correctness review
   - Inspect control flow, lifecycle management, error propagation, state transitions, and concurrency assumptions.
3. Targeted Docker verification
   - Run only the checks needed to validate/refute highest-signal hypotheses.
4. Finding classification
   - Severity, reproducibility, confidence, impact scope, fix direction, and test gap.

Tracks:
- Track A: TypeScript Action runtime (`src/main.ts`, `src/post.ts`, `action.yml`)
- Track B: Go agent + eBPF load/attach lifecycle (`internal/agent`, `internal/bpf`, `bpf/`)
- Track C: Telemetry/report correctness (`internal/telemetry`, `internal/report`, diff scripts)
- Track D: Workflow/scripts reliability gates (`.github/workflows`, `scripts/`)

## 3) Reliability Bug Model

A finding is prioritized when it indicates one or more of:
- Lifecycle breakage (leaks, missed cleanup, resource ownership faults)
- State correctness faults (stale/incorrect state transitions, nondeterminism)
- Error-handling faults (swallowed errors, false-success, retry path instability)
- Concurrency hazards (race, deadlock, unsafe shared mutation)
- Data integrity faults (invalid parse/transform/report outputs)
- Workflow reliability regressions (false-green, flaky assumptions, missing gates)

## 4) Evidence Standard

Each finding must include:
- Repro path (runtime) or deterministic reasoning path (static-only case)
- Observed behavior vs expected behavior
- Impact scope (single-run/local vs recurring/systemic)
- Confidence (`high`, `medium`, `low`)
- Verification artifact (Docker output, failing assertion, or explicit code trace)
- Minimal fix direction and test coverage gap

## 5) Execution Plan and Order

Planned order:
1. Track B (Go agent + eBPF lifecycle)
2. Track C (telemetry/report trustworthiness)
3. Track A (Action runtime behavior)
4. Track D (workflow and scripts reliability)

Rationale:
- Start where lifecycle/resource failures have highest runtime blast radius.
- Validate telemetry/report correctness early so downstream findings remain trustworthy.

## 6) Deliverables

Per track:
- Hypothesis list (knowledge-grounded)
- Validated findings with evidence
- Missed-test inventory
- Patch-ready recommendation (smallest safe fix + tests)

Final artifact:
- `knowledge/reports/<date>-reliability-code-review-findings.md`
  - Prioritized reliability backlog
  - Repro status and confidence
  - Recommended fix sequence

## 7) Boundaries and Guardrails

- Keep scope focused on reliability/correctness bugs.
- Avoid unrelated code cleanups.
- Prefer smallest safe fix directions to reduce regression risk.
- Run runtime checks in Docker to keep host-independent reproducibility.

## 8) Risks and Mitigations

Risks:
- “Entire app” scope can become unbounded.
- Runtime environment differences may hide or overstate failures.
- Noise from lower-confidence hypotheses may dilute review quality.

Mitigations:
- Strict track decomposition and execution order.
- Hypothesis triage before running checks.
- Confidence labeling and evidence gates for every finding.

## 9) Output Format for Findings

Each finding entry:
- ID
- Title
- Severity
- Component/track
- Repro status
- Confidence
- Evidence
- Root-cause hypothesis
- Minimal fix direction
- Test gap and recommended test

## 10) Approval and Next Step

After this design is approved, next step is a writing-plans pass to create a concrete, stepwise implementation/review plan for executing the review.
