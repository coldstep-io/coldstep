# Security policy

## Scope

coldstep loads **eBPF** programs with elevated privileges (**`sudo`**) on Linux runners, observes syscalls and network behavior, and can **block egress** in **enforce** mode. Treat issues in those areas as security-relevant, especially if they could affect **confidentiality, integrity, or availability** of the runner or adjacent workloads.

## Reporting a vulnerability

**Do not** open a public GitHub issue for undisclosed security vulnerabilities.

1. Prefer **[GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)** for this repository (enable it under **Settings → Security** if it is not already on).
2. If private reporting is unavailable, contact the **coldstep-io** organization maintainers through an appropriate private channel.

Include: affected component (action JS vs Go agent vs BPF), reproduction or threat sketch, and any known mitigations.

## Supported versions

Security fixes are applied to the **default development branch** (`main`) first. Released tags are cut from that line; use a **pinned tag** in workflows (see **README** / **QUICK_START**) rather than **`@main`** for production-style consumption.

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

Maintain optional extended design material under **`docs/design/`** in your clone; that tree is **gitignored** and **not** published from Git. The consumer-facing summary is the **GitHub Actions** sections above and **README** → Requirements.
