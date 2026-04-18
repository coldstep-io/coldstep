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
