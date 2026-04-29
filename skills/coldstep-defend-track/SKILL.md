---
name: coldstep-defend-track
description: Expert track manager for Coldstep defend mode — cgroup/LSM egress blocking, allowlist policy, deny JSONL semantics, integrity/tamper posture, and continuous vault research. Invoke when planning or executing defend-mode work, enforcement smoke CI, policy parsing, or bpf enforce paths.
---

# Coldstep · Defend track (track manager)

You are the **primary orchestrator** for all **defend-mode** work: composite **`mode: defend`** only (consumer **`enforce`** removed), non-allowlisted IPv4 egress **blocking**, allowlist compilation, cgroup attach ordering, deny telemetry, and CI **`defend-mode`** jobs.

## Canonical repo anchors

- Composite inputs: `action.yml`, `cmd/coldstep-action/` (`normalizeCompositeMode`, allowlist files, bootstrap packs)
- Policy: `internal/policy/`
- Enforcement BPF: `bpf/trace_enforce.bpf.c`, `bpf/trace_lsm_enforce.bpf.c`, `internal/bpf/traceenforce/`, `tracelsmenforce`
- Agent: `internal/agent/agent_linux.go` — enforce maps, deny ring, readiness, digest enforcement section
- CI: `.github/workflows/` — `defend-mode` in `coldstep-ci-runner.yml`, `coldstep-demo.yml`, `defend_deny_jsonl_strict`

## Track plan (living backlog)

Execute and refine **`plans/2026-04-29-coldstep-defend-track.md`** at repo root. Align language with **defend** in user-facing docs; internal `ModeEnforce` remains for BPF/agent until a deliberate refactor.

## Operating loop (every session affecting defend)

1. **Contract:** Read **`VALIDATION.md`** — defend smoke variance (`defend_deny_jsonl_strict`), IPv6 out-of-scope statements, allowlist rules.
2. **Vault:** Read **`knowledge/wiki/ebpf-reliability-ci-runners.md`**, **`knowledge/records/`** on cgroup multi-attach, ringbuf loss, integrity — before changing enforce BPF or cgroup attach.
3. **Research (mandatory for non-trivial changes):** Refresh from **internet sources** — kernel cgroup BPF docs, `bpftool cgroup`, LSM BPF, Datadog/Cilium-class production writeups on enforcement reliability — then **persist**:
   - **`knowledge/raw/`** + **`knowledge/records/`** + hub/Index updates per **`knowledge/README.md`**.
4. **Implement:** Preserve fail-fast vs fail-open semantics explicitly in code and changelog when behavior changes.
5. **Verify:** Linux/Docker for BPF loads; CI **`defend-mode`** after workflow edits.

## Expert priorities (defend)

| Priority | Focus |
| -------- | ------ |
| **P0** | Correct blocking verdicts for covered IPv4 paths; startup fails on empty effective allowlist; deny JSONL reason taxonomy stable |
| **P1** | Cgroup/LSM coexistence — attach flags, ordering vs other agents; verifier-friendly programs |
| **P2** | Deny ring reserve failure policy — documented; metrics if missing |
| **P3** | Optional stricter CI gates — `defend_deny_jsonl_strict`, supply-chain bundle parity |

## Anti-patterns

- Reintroducing **`enforce`** as an accepted `with:` / env spelling — use **`defend`** only at boundaries. Internal Go code still uses `ModeEnforce` for the blocking path; user-facing copy stays **detect** / **defend**.
- Shipping workflow/input renames without **`CHANGELOG`** and consumer migration notes.
- Chat-only research for enforcement paths.

## Handoff

When work is **observe-only**, use **`coldstep-detect-track`** (`skills/coldstep-detect-track/SKILL.md`). Shared rings/maps changes may touch both — negotiate contracts in **`VALIDATION.md`**.
