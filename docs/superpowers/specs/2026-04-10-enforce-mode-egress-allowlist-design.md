# Enforce-Mode Egress Allowlist Design

**Repository state (2026-04-12):** **`mode=enforce`**, deny JSONL, digest enforcement, and **`bpf/trace_enforce.bpf.c`** are **on `main`**. Plan: **`docs/superpowers/plans/2026-04-10-enforce-mode-egress-allowlist.md`**.

## Goal

Add a strict `enforce` mode that blocks non-allowlisted TCP/UDP egress in-kernel using eBPF, fails fast on first deny, and reports denied actions in JSONL and Job Summary.

## Scope

- Add mode switch: `detect|enforce` (default `detect`).
- Add allowlist domains input for egress policy.
- Enforce TCP/UDP egress only in v1.
- Fail fast on first deny.
- Include denied action evidence in report outputs.

Out of scope:

- TLS decryption.
- HTTP-layer status code extraction from encrypted HTTPS.
- Full protocol coverage beyond TCP/UDP in v1.
- Silent degrade from `enforce` to `detect` on hook failure.

## Product Semantics

### Mode behavior

- `detect` mode:
  - Current behavior remains unchanged: observe and report, no blocking.
- `enforce` mode:
  - Non-allowlisted TCP/UDP attempts are blocked by eBPF verdict path.
  - First denied action causes immediate run failure.
  - Denied action is still recorded in telemetry/report artifacts before exit.

### Hook failure behavior

- In `enforce` mode, inability to attach enforcement hooks is a hard operational failure.
- In `detect` mode, existing best-effort attach/degraded reporting remains.

## Architecture

### 1) Policy inputs and normalization

New action inputs:

- `mode` (`detect` or `enforce`)
- `allowed-domains` (newline/comma-separated domains)

Userspace policy compiler:

- normalize and dedupe domains
- resolve domains to IPv4 set using bounded retries
- produce a BPF allowlist map keyed by destination IP (v1 IP-based enforcement)
- preserve domain->IP provenance for reporting context

### 2) eBPF enforcement path

Add a verdict-capable enforcement program path for TCP/UDP egress decision points.

Enforcement decision:

- destination IP in allowlist map -> allow
- destination IP not in allowlist map -> deny and emit deny event

Keep existing detect telemetry collection for observability of allowed traffic.

### 3) Userspace runtime behavior

In `enforce` mode:

- load allowlist map into BPF
- validate enforcement attach success before continuing
- on first deny event:
  - append deny event to JSONL
  - include deny context in summary state
  - terminate with non-zero status

In `detect` mode:

- skip enforce verdict path, keep current detect behavior.

## Data Model

### JSONL

Add deny event record type (additive schema):

- `type: "deny"`
- timestamp
- pid/tid/comm
- protocol (`tcp` or `udp`)
- destination ip and port
- reason (`not_allowlisted`)
- policy context (mode, matched domain if any, allowlist source summary)

Existing `meta`, `exec`, `tcp`, `udp`, `http` remain unchanged.

### Job Summary

Add enforcement section:

- mode
- allowlist domains count
- denied events count
- first denied action details (protocol + dst + reason)

Detect KPI and existing sections remain, with deny signal surfaced clearly.

## Error Handling

- Invalid allowlist input in `enforce` mode -> fail start with actionable error.
- Empty effective allowlist in `enforce` mode -> fail start.
- DNS resolution partial failures:
  - report unresolved domains
  - fail start in `enforce` mode if policy cannot be safely enforced.
- BPF load/attach/map failures in `enforce` mode -> fail start.

## Security + Safety Constraints

- Enforcement is explicit opt-in by mode switch.
- No silent fallback to detect in enforce mode.
- Block decision occurs before userspace race windows wherever hook semantics support it.
- Reporting avoids secrets; only network and process metadata already in scope.

## Validation Strategy

### Unit tests

- mode parsing and defaults (`detect` default)
- allowlist parser normalization/dedup
- policy compiler behavior for empty/invalid domains
- deny event serialization and summary rendering

### Integration tests (Linux/root)

- enforce mode with allowlisted destination -> allowed traffic succeeds
- enforce mode with non-allowlisted destination -> blocked and run fails fast
- deny event emitted with expected protocol/dst/reason

### nightstalker-demo workflow

Add enforce scenario in addition to existing detect scenario:

- generate real TCP/UDP traffic to allowed and disallowed destinations
- assert:
  - disallowed egress causes non-zero outcome
  - JSONL includes deny event(s)
  - summary includes enforcement mode + deny details
  - detect-only flow still works independently

## Risks and Mitigations

- **Kernel hook compatibility risk**
  - Mitigation: target ubuntu-latest-supported hook path only; fail fast in enforce if unavailable.
- **DNS/IP drift risk for domain allowlist**
  - Mitigation: bounded resolution window and explicit unresolved-domain failure in enforce mode.
- **CI flakiness from external network**
  - Mitigation: bounded retries and deterministic assertions on deny semantics rather than exact traffic counts.

## Acceptance Criteria

- `mode=enforce` blocks non-allowlisted TCP/UDP egress attempts.
- First deny fails the run immediately.
- Denied actions appear in JSONL and Job Summary.
- `mode=detect` behavior remains unchanged.
- nightstalker-demo includes real-world enforce validation and passes reliably on ubuntu-latest.
