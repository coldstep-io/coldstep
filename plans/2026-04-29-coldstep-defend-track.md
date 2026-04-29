# Plan — Coldstep **defend** track

**Owner skill:** `skills/coldstep-defend-track/SKILL.md`  
**Purpose:** Improve **blocking** egress posture (`mode: defend`, internal **`enforce`**) — allowlists, cgroup/LSM programs, deny telemetry, CI **`defend-mode`**, and supply-chain alignment.

**Success criteria (rolling):**

- Defend smoke CI (**`defend-mode`**) remains reproducible on **`ubuntu-latest`** with documented variance (`defend_deny_jsonl_strict`).
- Policy startup semantics stay predictable: non-empty effective allowlist; IPv4-focused contracts per README.
- Vault captures **production-grade** cgroup/BPF enforcement research, not only internal tribal knowledge.

---

## Phase 0 — Baseline (always-on)

| Task | Output |
| ---- | ------ |
| Trace defend load path | bpf enforce → maps → cgroup/LSM attach → deny ring → JSONL `deny.mode` / digest |
| Naming | User-facing **defend** only; consumer **`enforce`** spelling removed (see **CHANGELOG** / **README** At a glance) |

---

## Phase 1 — Policy & correctness

| ID | Task | Notes |
| -- | ------ | ----- |
| F1 | Allowlist compile — domains → IPv4 A records; literals/CIDR | `internal/policy/` |
| F2 | File inputs + bootstrap merge order | `action.yml`, `allowlist_files.go` |
| F3 | Startup failure modes — empty effective allowlist, bad paths | Match digest/errors to UX |

---

## Phase 2 — Enforcement BPF reliability

| ID | Task | Notes |
| -- | ------ | ----- |
| F4 | Cgroup attach flags vs **multi-tenant** runners | Research → vault; align with kernel docs |
| F5 | Deny ring **reserve failure** semantics | Fail-open vs fail-closed — explicit product decision |
| F6 | LSM vs cgroup path — verifier latency readiness | CI timeouts already generous; document |

---

## Phase 3 — CI & strict gates

| ID | Task | Notes |
| -- | ------ | ----- |
| F7 | **`defend_deny_jsonl_strict`** dispatch | Optional strict gate; default variance-tolerant |
| F8 | Demo workflows **`mode: defend`** | `coldstep-demo`, `coldstep-demo-enforce` |
| F9 | Supply-chain tarball includes bootstrap + licenses | `supply-chain-attest.yml` |

---

## Phase 4 — Integrity & tamper resistance

| ID | Task | Notes |
| -- | ------ | ----- |
| F10 | Map integrity / heartbeat paths | See `knowledge/reports/2026-04-28-coldstep-telemetry-integrity-hardening.md` |
| F11 | Signing / JSONL verification hooks | Don’t regress verification story |

---

## Phase 5 — Continuous research (vault)

**Standing rule:** External URLs on cgroup BPF, LSM, enforcement at scale → **`knowledge/raw/`** + **`knowledge/records/`** + update [[wiki/ebpf-reliability-ci-runners]] when reliability guidance changes.

**Quarterly:** Add a dated synthesis record under `knowledge/records/` if kernel major or GitHub runner kernel shifts materially.

---

## Out of scope (v1 track)

- IPv6 defend path (explicit non-goal today).
- Replacing cgroup design with TC/XDP without architecture decision.
