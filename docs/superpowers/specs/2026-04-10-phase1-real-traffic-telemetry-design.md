# Phase 1 Real-Traffic Telemetry Design

**Repository state (2026-04-12):** nightstalker-demo real-traffic validation and digest/KPI behavior described here are **on `main`**. Plan: **`docs/superpowers/plans/2026-04-10-phase1-real-traffic-telemetry.md`**.

## Goal

Produce screenshot-aligned telemetry value in detect mode by improving UDP/TCP/HTTP reporting clarity and requiring real-world traffic generation in nightstalker-demo validation.

## Scope

- Keep detect-only behavior.
- Improve UDP/HTTP section clarity when events are absent.
- Ensure nightstalker-demo generates and validates real TCP, UDP, and HTTP traffic.
- Preserve existing JSONL schema compatibility.

Out of scope:

- TLS decryption.
- Exact HTTPS response status capture from encrypted payloads.
- Policy-enforcement mode changes.

## Desired Outcome

The job summary and JSONL should consistently show:

- HTTP rows from real cleartext traffic (`GET`, host, path summary).
- TCP/UDP rows from real egress activity.
- Explicit reason rows when UDP/HTTP have zero events, so empty tables are never ambiguous.

## Approach

### 1) Digest UX upgrades (reporting)

For UDP and HTTP sections:

- Render normal tables when rows exist.
- Render a single explicit reason row when rows are empty.
- Use deterministic precedence for reason text:
  1. Hook degraded/disabled
  2. Reader errors observed
  3. No events observed in this run

This avoids silent header-only sections and makes operator interpretation immediate.

### 2) Runtime section-state metadata (agent)

Plumb minimal section state from runtime to digest input:

- Hook status for syscall egress probe.
- Reader/decode error signal for UDP and HTTP ring readers.
- Event totals already tracked in runtime stats.

No JSONL shape changes are required for this phase.

### 3) Real-traffic nightstalker-demo requirements (validation)

nightstalker-demo must generate true outbound traffic, not synthetic-only placeholders:

- **TCP:** real connect attempts (`/dev/tcp` and/or `nc`).
- **UDP:** real datagrams (resolver path + explicit UDP send path).
- **HTTP:** real HTTP/1.1 cleartext requests (`curl --http1.1` + raw `GET` through `nc`).

nightstalker-demo assertions must verify both **presence** and **shape**:

- JSONL includes `type=tcp|udp|http`.
- Protocol-specific fields/ports exist (`dport` checks, method/path hints).
- Digest includes representative row evidence (not only section/KPI labels).

### 4) HTTPS expectation handling

Because TLS payloads are encrypted in this architecture:

- Keep explicit footnote/status text that HTTPS response status codes are unavailable in phase 1.
- Do not imply parity with tools that use proxy/MITM collection.

## Data Flow

1. nightstalker-demo step emits real TCP/UDP/HTTP traffic.
2. BPF probes capture syscall/network signals.
3. Agent emits JSONL events and digest markdown.
4. Digest builder renders rows or explicit empty-state reason rows.
5. nightstalker-demo verification checks counts + field shape + digest evidence.

## Testing Strategy

### Unit tests

- `internal/report/digest_test.go`
  - UDP/HTTP empty reason rows for each precedence branch.
  - Existing populated-row behavior unchanged.
- `internal/agent/*_test.go`
  - Runtime state maps correctly to digest reason inputs.

### Integration / workflow validation

- Keep and strengthen nightstalker-demo checks for:
  - UDP/HTTP event volume (`>=` thresholds)
  - UDP/HTTP shape constraints (`dport`, method markers)
  - digest evidence checks for real row content
- Ensure job fails if traffic generation regresses to non-real/insufficient output.

## Risks and Mitigations

- **Risk:** Traffic flakiness in CI network.
  - **Mitigation:** bounded retries and multi-domain attempts; assert minimum volume not exact counts.
- **Risk:** Over-reporting confidence for HTTPS.
  - **Mitigation:** explicit detect-only/TLS limitation text in digest footnotes.
- **Risk:** Ambiguous empty state returns.
  - **Mitigation:** deterministic reason precedence and unit coverage.

## Acceptance Criteria

- UDP/HTTP sections are never silently empty.
- nightstalker-demo actively emits real TCP/UDP/HTTP traffic each run.
- nightstalker-demo validates protocol-specific JSONL/digest evidence, not label-only checks.
- Existing detect-only behavior and schema compatibility are preserved.
