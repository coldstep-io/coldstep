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
