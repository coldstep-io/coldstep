# GitHub-Hosted Runner eBPF Enhancements — Master Roadmap

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans per child plan task-by-task.

**Goal:** Deliver options **A–E** (UDP coverage, IPv6 enforcement/telemetry, job-level cgroup noise isolation, DNS/TLS visibility, BPF operational counters) as **separate shipped increments**, each with tests and Docker verification.

**Architecture:** Treat each child plan as an independent vertical slice touching `bpf/*.bpf.c`, `internal/bpf/*`, `internal/agent/*`, and telemetry JSONL/digest surfaces where needed. Respect **IPv4-first v1** defaults; widen scope only behind explicit maps/programs.

**Tech Stack:** BPF CO-RE (`vmlinux.h`), `bpf2go`, Go agent, GitHub Actions `ubuntu-latest`, Docker toolchains per `scripts/build-agent-linux.sh`.

---

## Child plans (canonical filenames)

| ID | Topic | Plan file |
| -- | ----- | --------- |
| **A** | UDP `sendmsg` / connected-socket UDP coverage | `docs/superpowers/plans/2026-04-18-runner-udp-sendmsg-coverage.md` |
| **B** | IPv6 observability + enforce (`connect6` / `sendmsg6`) | `docs/superpowers/plans/2026-04-18-runner-enforce-ipv6.md` |
| **C** | Job cgroup scoping (reduce shared-runner noise) | `docs/superpowers/plans/2026-04-18-runner-cgroup-job-scoping.md` |
| **D** | DNS/TLS visibility (bounded extras) | `docs/superpowers/plans/2026-04-18-runner-dns-tls-visibility.md` |
| **E** | BPF operational counters / attach health | `docs/superpowers/plans/2026-04-18-runner-bpf-observability-counters.md` |

---

## Suggested execution order

1. **Plan E** — surfaces drops and failure counters first; stabilizes debugging for A–D.
2. **Plan A** — closes the largest **detect-mode** blind spot (`sendto`-only UDP) without policy/compiler explosion.
3. **Plan D** — narrow protocol increments (still bounded verifier work).
4. **Plan B** — largest userspace + BPF surface (maps, deny events, config); do after patterns from A/E are proven.
5. **Plan C** — depends on runtime/cgroup discovery research; may ship as **phase 1: metrics + attach path logging** before true scoped attach.

---

## Cross-cutting verification (every child plan)

- Rebuild BPF: `docker` + `scripts/build-agent-linux.sh` (per `AGENTS.md`).
- `go test ./...` inside Docker `golang:1.24-bookworm`.
- Work on branch **`dev`** only for agent pushes; signed commits.

---

## Self-review

- Each row maps to a concrete child plan file (no orphan scope).
- Order is dependency-aware (E → A → D → B → C).
