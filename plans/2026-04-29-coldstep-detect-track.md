# Plan — Coldstep **detect** track

**Owner skill:** `skills/coldstep-detect-track/SKILL.md`  
**Purpose:** Improve and prove **observation-only** egress telemetry (`mode: detect`) on GitHub-hosted Linux CI — without claiming blocking guarantees.

**Success criteria (rolling):**

- **`VALIDATION.md`** stays an honest contract: every “proof” claim ties to a test or workflow assertion.
- Detect artifacts remain **best-effort but measurable**: drops/degrades visible in digest/KPI or telemetry summary where architecture supports it.
- Knowledge vault accumulates **fresh** BPF/detect research via the pipeline in **`knowledge/README.md`** (not chat-only dumps).

---

## Phase 0 — Baseline (always-on)

| Task | Output |
| ---- | ------ |
| Map detect hot paths | Short inventory in vault or inline PR notes: agent attach order → trace BPF → ring readers → JSONL → report |
| Align language | README / QUICK_START / VALIDATION use **detect** vs **defend** consistently |

---

## Phase 1 — Telemetry reliability & honesty

| ID | Task | Notes |
| -- | ------ | ----- |
| D1 | Ringbuf / reader **metrics** in telemetry summary or digest KPI | Tie to local vault hub `knowledge/wiki/ebpf-reliability-ci-runners.md` |
| D2 | Audit **degraded hook** surfacing for raw_tp multiplex | Digest already flags; ensure JSONL drop kinds match reality |
| D3 | Document **ordering limits** (exec vs network) if correlating | Datadog-style reorder window only if product requires |
| D4 | CI: keep **`detect-mode`** job green on `ubuntu-latest`; extend matrix only when justified in VALIDATION |

---

## Phase 2 — Coverage (syscall / UDP / DNS / TLS gates)

| ID | Task | Notes |
| -- | ------ | ----- |
| D5 | UDP coverage gaps (`sendmsg`, connected UDP) | Align with ebpf-github-runner-egress skill |
| D6 | DNS / TLS **visibility** feature gates | Bounded BPF cost; document partial visibility |
| D7 | **Integrity gate** regression tests | Don’t weaken anti-blindness checks |

---

## Phase 3 — Operator signal (reports)

| ID | Task | Notes |
| -- | ------ | ----- |
| D8 | Tier-1 / Tier-2 report fidelity | `public_scripts/coldstep_detect_report`, `coldstep-report` CLI |
| D9 | Baseline JSONL diff workflow | STRICT semantics documented |

---

## Phase 4 — Continuous research (vault)

**Standing rule:** Any substantive external URL or lesson learned during detect work → **`knowledge/raw/`** + **`knowledge/records/`** (+ wiki hub / Index when cross-cutting). Prefer **WebFetch** or official docs over stale chat summary.

**Quarterly:** Refresh `knowledge/records/2026-04-29-ebpf-reliability-research-synthesis.md` (or successor) with new kernel/ebpf.io citations.

---

## Out of scope (v1 track)

- IPv6 egress enforcement (project scope).
- Self-hosted runner matrices unless **`VALIDATION.md`** updated deliberately.
