# UDP/HTTP Empty-State + Capture Diagnostics Design

**Repository state (2026-04-12):** Digest empty-state / degraded-hook messaging and related tests are **on `main`**. Plan: **`docs/superpowers/plans/2026-04-10-udp-http-capture-and-empty-state.md`**.

## Goal

Make missing UDP/HTTP output understandable at a glance while preserving detect-only behavior and existing JSONL schema.

## Scope

- Improve digest UX when UDP/HTTP rows are empty.
- Surface runtime capture state needed to explain why sections are empty.
- Keep existing positive-path nightstalker-demo assertions for observed UDP/HTTP events.
- Add regression tests so sections never appear as ambiguous header-only tables.

Out of scope:

- Policy enforcement behavior changes.
- TLS decryption or new HTTP protocol decoding.
- New JSONL event types or schema-version bumps.

## Current Problem

The detect digest currently renders UDP and HTTP sections even when no rows are present. In that state, tables can appear empty without clear explanation, which looks like missing telemetry rather than an explicit "no data / degraded" condition.

## Proposed Approach (C)

Combine reporting UX and capture diagnostics:

1. **Section-level explicit reasons** in digest for UDP/HTTP when row sets are empty.
2. **Runtime status plumbing** from agent run state into digest input for each section.
3. **nightstalker-demo + unit test hardening** so empty-state rendering remains explicit.

## Design

### 1) Digest input extensions

Extend `internal/report/digest.go` `DigestInput` with minimal per-section status for UDP/HTTP:

- hook attached / healthy
- reader errors observed (bool or count)
- events observed totals (already available via totals; reused for reason text)

This metadata is additive and internal to digest generation.

### 2) Empty-state rendering rules

For UDP and HTTP sections:

- If rows exist: render current table rows unchanged.
- If no rows and hook degraded: render a single reason row indicating hook disabled/degraded and direct readers to BPF status.
- If no rows and reader errors seen: render a reason row indicating reader errors were observed (details remain in logs/BPF detail).
- If no rows and hook healthy with no reader errors: render a reason row indicating no events observed in this run.

Reason rows should be concise and deterministic so tests can assert exact substrings.

### 3) Agent data flow

In `internal/agent/agent_linux.go`:

- Reuse existing BPF attach status and runtime counters.
- Track per-signal reader error state for UDP and HTTP ring processing.
- Pass the new section-state fields into `report.DigestInput` at shutdown.

No changes to JSONL event structures are required.

### 4) nightstalker-demo expectations

Keep all existing positive assertions for real UDP/HTTP production in `nightstalker-demo.yml`.

Add one regression assertion that digest output for UDP/HTTP is never ambiguous header-only content when rows are absent (validated via unit tests; workflow remains focused on real traffic path checks).

## Error Handling

- Do not dump raw internal errors into table cells.
- Keep detailed diagnostics in logs and existing BPF status detail.
- Keep digest reason text user-facing, stable, and short.

## Testing Plan

### Unit (`internal/report/digest_test.go`)

Add/extend tests for:

- UDP empty + healthy hook => "no events observed".
- UDP empty + degraded hook => "disabled/degraded".
- UDP empty + reader errors => "reader errors observed".
- Same matrix for HTTP.
- Existing non-empty row rendering remains unchanged.

### Agent unit (`internal/agent`)

Add/extend tests proving run-state -> `DigestInput` mapping for UDP/HTTP section status.

### Existing CI/nightstalker-demo

- Retain current nightstalker-demo checks for UDP/HTTP JSONL volume and shape.
- Retain digest keyword checks (`UDP sendto`, `HTTP/1 cleartext`, etc.).

## Risks and Mitigations

- **Risk:** Reason precedence ambiguity when multiple conditions apply.
  - **Mitigation:** Define precedence order: degraded hook > reader errors > no events.
- **Risk:** Overly noisy digest text.
  - **Mitigation:** Single-line reason rows with fixed wording.
- **Risk:** Regressing current real-traffic output.
  - **Mitigation:** Keep non-empty row path unchanged and covered by existing tests.

## Acceptance Criteria

- UDP/HTTP sections always explain empty states explicitly.
- Populated UDP/HTTP tables remain unchanged.
- No JSONL schema changes are introduced.
- Unit tests cover empty-state reasons and precedence.
- nightstalker-demo positive-path UDP/HTTP assertions continue to pass.
