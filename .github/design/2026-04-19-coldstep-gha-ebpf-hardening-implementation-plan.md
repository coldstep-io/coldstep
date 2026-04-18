# Coldstep GHA eBPF mitigations — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the **brainstormed** GitHub Actions–centric mitigation story (enforce / detectability / ops pillars, non-goals, phased enhancement) as **tracked design + SECURITY.md consumer guidance**, using branch **`ebpf_testing`** for this line of work.

**Architecture:** **Documentation-first deliverable** — no mandatory BPF/Go logic change in this plan; align public **SECURITY.md** with the agreed threat model and residual bypass classes, persist the **design spec** next to other `.github/design/` artifacts, and record a **short enhancement backlog** inside the design doc for follow-up PRs (separate from this workflow).

**Tech stack:** Markdown, Git (`ebpf_testing`), existing CI conventions (`ubuntu-latest`, pinned composite tags).

**Branch policy (this workflow):** All commits for this plan happen on **`ebpf_testing`**. Integrate to **`dev`** / **`main`** via normal PR process after review; do not mix unrelated feature work on this branch.

---

## File map

| File | Responsibility |
| ---- | -------------- |
| `.github/design/2026-04-19-coldstep-gha-ebpf-mitigations-design.md` | Frozen brainstorm spec (threat model, pillars, non-goals, verification) |
| `SECURITY.md` | New section: GHA consumer threat model, mitigations, residual risks, references |
| `README.md` | Optional one-line pointer to SECURITY (only if Task 4 executed) |

---

### Task 1: Branch hygiene (`ebpf_testing`)

**Files:** (none yet)

- [x] **Step 1: Ensure you are on the integration branch for this work**

```bash
cd /path/to/coldstep
git fetch origin
git checkout ebpf_testing
```

If **`ebpf_testing` does not exist locally** but exists on `origin`:

```bash
git checkout -b ebpf_testing origin/ebpf_testing
```

If it **does not exist anywhere**, create it from current **`dev`** (or **`main`** if `dev` is unavailable), then publish:

```bash
git checkout dev
git pull origin dev
git checkout -b ebpf_testing
git push -u origin ebpf_testing
```

- [x] **Step 2: Confirm clean tree before edits**

```bash
git status
```

Expected: working tree clean or only intentional changes.

- [x] **Step 3: Commit** — only after completing Tasks 2–4 if you bundle; otherwise skip.

---

### Task 2: Add frozen design spec

**Files:**
- Create: `.github/design/2026-04-19-coldstep-gha-ebpf-mitigations-design.md`

- [x] **Step 1: Create the file with exactly this content**

```markdown
# Coldstep on GitHub Actions — eBPF monitoring limits & mitigations (design)

**Status:** Approved specification (brainstorm 2026-04-19)  
**Scope:** Coldstep on **GitHub Actions** / **`ubuntu-latest`** — **egress telemetry** and **enforce-mode**; not a general Linux IDS treatise.

## 1. Threat model

- **Tenant:** One **workflow job** is one logical boundary — all `run:` steps share the cgroup/session Coldstep attaches to. The typical “attacker” is **untrusted workflow code**, not an external SSH operator (cf. Teleport-style session recording).
- **Trust:** Runners are **GitHub-managed**. Coldstep requires **`sudo`** to load BPF as today. **Kernel or hypervisor compromise** is **out of scope** for userland mitigations.
- **Residual classes:** Bypasses that rely on **uninstrumented paths**, **IPv6 / non–connect/sendmsg egress**, **telemetry overload/drops**, or **same-job FD reuse** are addressed by **documentation + honesty in outputs** before code expansion.

## 2. Three pillars (balanced; enhance over time)

| Pillar | Now | Later |
| ------ | --- | ----- |
| **Enforce** | Stay within **documented IPv4** cgroup **connect4** / **sendmsg4** semantics and allowlist compilation (see README). | Incremental hook/policy work **only** where verifier + CI prove sustainable. |
| **Detectability** | Rely on **`.coldstep-events.jsonl`**, **`.coldstep-telemetry.json`**, digest — surface BPF attach health and workload signals already implemented. | Richer **loss/limit** signaling when product prioritizes it. |
| **Ops / CI** | Pin **`coldstep-io/coldstep@v…`**, **`ubuntu-latest`**, **`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24`**, minimal workflow **permissions**. | Stricter templates / optional enterprise modes as needed. |

## 3. Non-goals

- Primary optimization for **Teleport-like SSH cgroup orphan** tricks — **secondary** on ephemeral runners.
- **IPv6 enforcement** in **v1** — remains **out of scope** per README unless product scope changes.
- Global claim to **prevent all eBPF bypass literature** — rejected; observability stacks remain **lossy** by design (see external literature on evasion and pitfalls).

## 4. Verification & evolution

- **CI:** PR + nightly workflows remain the **supported proof path** (`govulncheck`, race, shuffle as stress — not red-team bypass simulation).
- **Knowledge:** Vault hub **`[[wiki/ebpf-monitoring-evasion]]`** (local) links external references; update when mitigations ship.
- **Backlog:** Track enforce vs telemetry vs docs improvements as **separate small PRs** after this documentation lands.

## 5. References (external)

- [Doyensec — On Bypassing eBPF Security Monitoring](https://blog.doyensec.com/2022/10/11/ebpf-bypass-security-monitoring.html)
- [Trail of Bits — Pitfalls of relying on eBPF for security monitoring](https://blog.trailofbits.com/2023/09/25/pitfalls-of-relying-on-ebpf-for-security-monitoring-and-some-solutions/)
- [Brendan Gregg — eBPF observability tools are not security tools](https://www.brendangregg.com/blog/2023-04-28/ebpf-security-issues.html)
```

- [x] **Step 2: Stage**

```bash
git add .github/design/2026-04-19-coldstep-gha-ebpf-mitigations-design.md
```

- [x] **Step 3: Commit (signed)**

```bash
git commit -S -m "docs: GHA eBPF mitigations design spec"
```

---

### Task 3: Extend `SECURITY.md` (consumer mitigations)

**Files:**
- Modify: `SECURITY.md`

- [x] **Step 1: Append this section before the final newline** (keep existing sections intact)

```markdown

## GitHub Actions: threat model and mitigations

Coldstep is commonly used in **GitHub-hosted Ubuntu** jobs. This section summarizes **what the composite action can and cannot guarantee** for consumers hardening CI egress visibility or **enforce** mode.

### What a job adversary can do

Workflow steps run with the **same privileges** as the job (modulo `sudo` elevation for the agent per action design). A malicious or compromised step can attempt **egress**, **binary execution**, or **tampering** patterns similar to those discussed in public literature on **eBPF monitoring limits** (instrumentation gaps, overload/drops, cgroup scope). Coldstep’s **v1 enforce** path is **IPv4-only** for cgroup **connect** / **sendmsg** hooks; **IPv6** and other syscall surfaces are **explicitly out of scope** for v1 — see **README** → Requirements.

### Mitigations consumers should apply

| Mitigation | Detail |
| ---------- | ------ |
| **Pin the action** | Use **`coldstep-io/coldstep@<tag>`** (not **`@main`**) for reproducible behavior. |
| **Runner label** | Use **`ubuntu-latest`** (x64) as documented until additional labels are officially supported. |
| **Node alignment** | Set **`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`** so the composite matches **`node24`** in `action.yml`. |
| **Workflow permissions** | Grant **`contents: read`** (and other scopes) minimally; follow GitHub hardening guidance for your org. |
| **Interpret outputs** | Treat **`.coldstep-telemetry.json`** and JSONL as **best-effort telemetry** — design assumes **possible loss** under extreme event rates, consistent with industry guidance on eBPF-based monitoring. |

### Residual risk (honest scope)

No userland agent can promise **complete** observation of every kernel path on every kernel revision. Consumers needing **audit-grade non-repudiation** must combine Coldstep with **organizational controls** (locked-down workflows, secrets policies, optional additional LSM / host controls outside this project).

### Further reading

Design spec: **`.github/design/2026-04-19-coldstep-gha-ebpf-mitigations-design.md`** in this repository.
```

- [x] **Step 2: Preview diff**

```bash
git diff SECURITY.md
```

- [x] **Step 3: Commit (signed)**

```bash
git add SECURITY.md
git commit -S -m "docs(security): GHA threat model and consumer mitigations"
```

---

### Task 4 (optional): README pointer

**Files:**
- Modify: `README.md`

Skip if you want zero README churn; otherwise add **one bullet** under **Requirements** table or a single sentence after the **Requirements** section pointing readers to **`SECURITY.md`** for the GHA threat model.

Example insertion after the Requirements table (after the `| **Node** | ... |` row block):

```markdown

For **security posture on GitHub Actions** (threat model, residual risk, pins), see **[SECURITY.md](SECURITY.md)** — *GitHub Actions: threat model and mitigations*.
```

- [x] **Step 1: Edit, then**

```bash
git add README.md
git commit -S -m "docs: link SECURITY.md for GHA eBPF mitigations"
```

---

### Task 5: Push branch `ebpf_testing`

**Files:** —

- [x] **Step 1: Push to origin**

```bash
git push -u origin ebpf_testing
```

Expected: remote updates with new commits; open a **PR** targeting **`dev`** (or your team’s integration branch) per repository policy.

---

## Plan self-review vs design spec

| Spec section | Task |
| ------------ | ---- |
| §1 Threat model | Task 3 (`SECURITY.md`) + Task 2 (design file) |
| §2 Three pillars | Task 2 + Task 3 table |
| §3 Non-goals | Task 2 + Task 3 |
| §4 Verification / evolution | Task 2 + existing CI (no change required here) |

**Placeholder scan:** None — all pasted sections are complete.

---

## Execution handoff

**Plan complete and saved to** `.github/design/2026-04-19-coldstep-gha-ebpf-hardening-implementation-plan.md` **(not** `docs/superpowers/plans/` — that path is gitignored in this repo).

**Two execution options:**

1. **Subagent-driven (recommended)** — fresh subagent per task, review between tasks.  
2. **Inline execution** — run tasks in this session with **executing-plans**, batching with checkpoints.

**Which approach?**
