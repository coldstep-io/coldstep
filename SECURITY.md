# Security policy

## Scope

coldstep loads **eBPF** programs with elevated privileges (**`sudo`**) on Linux runners, observes syscalls and network behavior, and can **block egress** in **defend** (blocking) mode. Treat issues in those areas as security-relevant, especially if they could affect **confidentiality, integrity, or availability** of the runner or adjacent workloads.

## Reporting a vulnerability

**Do not** open a public GitHub issue for undisclosed security vulnerabilities.

1. Prefer **[GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)** for this repository (enable it under **Settings → Security** if it is not already on).
2. If private reporting is unavailable, contact the **coldstep-io** organization maintainers through an appropriate private channel.

Include: affected component (composite shell / Go agent vs BPF), reproduction or threat sketch, and any known mitigations.

## Supported versions

Security fixes are applied to the **default development branch** (`main`) first. Released tags are cut from that line; use a **pinned tag** in workflows (see **README** / **QUICK_START**) rather than **`@main`** for production-style consumption.

## Coverage Boundaries

coldstep observes and enforces a **deliberately scoped** subset of egress. Trust decisions — promoting detect output to a defend allowlist, treating a clean digest as proof of no exfiltration, gating a release on a passing defend run — must account for the boundaries below. **Absence of evidence is not evidence of absence.**

| Traffic class | Detect (observe) | Defend (block) | Notes |
|:---|:---:|:---:|:---|
| IPv4 TCP | ✓ | ✓ | Via `connect4` tracepoint + cgroup hook |
| IPv4 UDP (`sendmsg`) | ✓ | ✓ | Via `sendmsg4` tracepoint + cgroup hook |
| IPv4 UDP (`write` on connected socket) | partial | ✓ | `write(2)` on a connected UDP socket may not emit a per-message event; cgroup `sendmsg4` still enforces |
| IPv6 (all) | ✗ | ✗ | No IPv6 hooks; silent bypass in all modes |
| QUIC / HTTP3 (UDP/443) | UDP event only | ✓ (port/IP) | Inner QUIC framing not inspected; SNI not extracted |
| TLS via io_uring | partial (enhanced) | ✗ | io_uring detection gated behind `detect-profile: enhanced` (raw_tp/io_uring_submit_sqe); the sysctl `io-uring-disable` remains the primary defense |
| Unix domain sockets | ✗ | ✗ | AF_UNIX not tracked |
| Docker-in-Docker inner containers | ✗ | ✗ | Separate cgroup/network namespace |
| GitHub Actions service containers | ✗ | ✗ | Docker networking, separate namespace |

**Why IPv4-only.** Defend hooks attach to the kernel-side BPF program types `cgroup/connect4` and `cgroup/sendmsg4`. These hook types are address-family-specific by ABI — the analogous `connect6` / `sendmsg6` slots would have to be implemented, attached, and verified separately, and require parallel IPv6 LPM map machinery on the userspace side. Until those land, IPv6 egress is not observed by coldstep tracepoints and is not gated by coldstep cgroup hooks. Treat any IPv6-capable destination as an uncovered path.

**Operational implications.**

- **Detect-mode allowlist promotion** (`suggested-allow` output) reflects IPv4 destinations only. A workload that exfiltrates over IPv6, QUIC inner payload, or AF_UNIX → host-proxy will appear clean in detect and will not contribute to the suggested allowlist.
- **Defend-mode enforcement** does not bar IPv6 destinations even when an IPv4 entry of the "same" host exists; if the runner resolves AAAA and prefers IPv6, the connection is unenforced.
- **Service containers and DinD** run in separate network namespaces from the job's primary cgroup. Egress originating inside those namespaces is outside coldstep's hook scope; route them through the job container or rely on organizational network controls.

## GitHub Actions: threat model and mitigations

Coldstep is commonly used in **GitHub-hosted Ubuntu** jobs. This section summarizes **what the composite action can and cannot guarantee** for consumers hardening CI egress visibility or **defend** (blocking) mode.

### What a job adversary can do

Workflow steps run with the **same privileges** as the job (modulo `sudo` elevation for the agent per action design). A malicious or compromised step can attempt **egress**, **binary execution**, or **tampering** patterns similar to those discussed in public literature on **eBPF monitoring limits** (instrumentation gaps, overload/drops, cgroup scope). Coldstep’s **defend** (blocking) path is **IPv4-only** for cgroup **connect** / **sendmsg** hooks. **IPv6 is not supported** — see **README** → Requirements.

### Mitigations consumers should apply

| Mitigation | Detail |
| ---------- | ------ |
| **Pin the action** | Use **`coldstep-io/coldstep@<tag>`** (not **`@main`**) for reproducible behavior. |
| **Runner label** | Use **`ubuntu-latest`** (x64) as documented until additional labels are officially supported. |
| **Node alignment (optional)** | Coldstep’s composite does not run Node. If the same job uses **other** JavaScript actions, you may set **`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`** so those actions match hosted-runner Node defaults. |
| **Workflow permissions** | Grant **`contents: read`** (and other scopes) minimally; follow GitHub hardening guidance for your org. |
| **Interpret outputs** | Treat **`.coldstep-telemetry.json`** and JSONL as **best-effort telemetry** — design assumes **possible loss** under extreme event rates, consistent with industry guidance on eBPF-based monitoring. |

### Guarantees vs best-effort (defend and detect)

Coldstep’s contract has three layers:

1. **Defend (when programs are loaded and mode is blocking):** **IPv4** egress that hits the attached **cgroup** and/or **BPF LSM** hooks is **denied** unless it matches the **effective allowlist** (IPv4 literals / CIDRs in the LPM map, plus optional **DNS cache–backed** domain rules). This is **hook-scoped** and **IPv4-only**; it is not a promise that every kernel egress mechanism was evaluated.
2. **Detect:** Syscall and tracepoint visibility is **best-effort**. Counters may show **partial** visibility (e.g. unobserved syscall families, multi-iovec captures, ringbuf reserve failures). **Absence of JSONL lines does not prove absence of traffic.**
3. **Explicit non-coverage:** **IPv6** is unsupported. **io_uring** and similar paths can **bypass typical syscall tracepoints**; Coldstep may surface `io_uring_setup` as a **signal**, not as payload visibility. Organizational controls remain necessary for audit-grade posture (see **Residual risk** below).

**DNS domain allowlists (defend):** Resolution and BPF `dns_cache` updates are **best-effort**. High cardinality answers, shared IPs, and cache timing can make **allow-by-domain** subtle. Prefer **IPv4 literals or CIDRs** when you need crisp policy; treat domain rules as convenient but higher-ambiguity. The agent may **log a warning** when a single allowed domain resolves to more than **10** distinct IPv4 addresses (warn-only — does not change the effective allowlist). Future digest surfacing may add operator-visible notes without changing allow/deny unless explicitly documented.

### Defend hooks (cgroup and LSM)

| Layer | BPF object (repo) | Role |
| ----- | ----------------- | ---- |
| **cgroup** | `bpf/trace_defend.bpf.c` | **`cgroup/connect4`**, **`cgroup/sendmsg4`** — primary IPv4 egress defend for TCP and UDP on the job cgroup. |
| **LSM** | `bpf/trace_lsm_defend.bpf.c` | **`lsm/socket_connect`**, **`lsm/socket_sendmsg`** (`SEC(...)` names; supplemental BPF LSM defend where available). |

Both are **IPv4 only**. The agent reports BPF load/attach status in **`.coldstep-telemetry.json`** and in logs. If a program fails to attach, treat **defend** as **degraded** and inspect those rows and stderr—do not assume silent fallback implies the same defense story on every kernel.

### Residual risk (honest scope)

No userland agent can promise **complete** observation of every kernel path on every kernel revision. Consumers needing **audit-grade non-repudiation** must combine Coldstep with **organizational controls** (locked-down workflows, secrets policies, optional additional LSM / host controls outside this project).

### Optional third-party threat intel (OTX)

When a workflow supplies a non-empty **`OTX_API_KEY`** repository secret to the detect-report enrichment step, the runner performs **HTTPS requests** to AlienVault Open Threat Exchange (`otx.alienvault.com`) for indicator lookups. When the secret is **absent or empty**, **no such requests** occur. Enrichment is designed not to fail the job on API errors (see **`scripts/coldstep_detect_report/README.md`**).

### Code scanning (CodeQL)

The tracked workflow **`.github/workflows/codeql.yml`** runs CodeQL for **Go**, **JavaScript/TypeScript**, **C/C++**, and **GitHub Actions** only — **not Python**, because this repository does not ship Python sources. If **Code scanning “Default setup”** is also enabled in **Settings → Code security**, either **disable Default setup** in favor of that workflow, or **edit Default setup** and **remove the Python language** so analyses stay aligned and redundant jobs do not run.

### eBPF safety audit (P1-3, 2026-05-19)

A systematic audit of every BPF C translation unit and the Go-side attach
sequence ran on 2026-05-19 against the seven audit categories below. Inline
`AUDIT(5x)` comments on each verified call site make the review visible at
the source; this section is the audit-level summary.

| Category | Sites audited | Issues found | Fix |
| -------- | :-----------: | :----------: | --- |
| **5a — Map lookup null checks** | 24 (`bpf_map_lookup_elem`) | 0 | All sites already pair the lookup with a `!ptr` early return or guard the deref behind `if (ptr)`/`&&`. |
| **5b — Ringbuf reserve/discard pairing** | 11 (`bpf_ringbuf_reserve`) | 0 | Every reservation has a paired `bpf_ringbuf_submit` on success and `bpf_ringbuf_discard` on the probe-read-failure path. The `!ev` early returns hold no slot, so no discard is needed there. |
| **5c — Pointer arithmetic bounds** | 4 | 0 | `iov_base + sizeof(coldstep_iovec)` (two iov[1] peeks) is bounded by the kernel-side check inside `bpf_probe_read_user`; `msgvec_ptr + i*64` uses a `#pragma unroll` induction variable in [1, 7]; `__data_loc` offset is verifier-guarded `< 4096`. |
| **5d — Loop bounds** | 1 (`for` loop) | 0 | The only loop is the `#pragma unroll`'d sendmmsg extras walk with `SENDMMSG_EXTRA_MAX = 7`. |
| **5e — BTF CO-RE field stability** | 5 (`BPF_CORE_READ`) | 0 | All accessed fields (`task_struct.pid`, `task_struct.group_leader`, `signal_struct.pids[PIDTYPE_SID]`, `pid.numbers[0].nr`, `task_struct.nsproxy.pid_ns_for_children.ns.inum`) have been stable on kernels 5.15–6.x. |
| **5f — Helper return value checks** | 26 (`bpf_probe_read_*`) | 0 (1 hardening) | Probe-read returns are either explicitly checked OR the destination is zero-initialized so a failure fails closed. Hardening: `lsm_socket_connect` was relying on kernel 5.5+ probe-failure zeroing for `family`/`sk`/`protocol`/`daddr`/`dport`; the variables are now explicitly initialized to match the sibling `lsm_socket_sendmsg` pattern (defense in depth, no behavior change on supported kernels). |
| **5g — Cgroup attach cleanup** | 1 (`agent_linux.go` defend block) | 0 | LSM and cgroup attaches register `defer X.Close()` immediately after each successful attach, and an explicit `lnk1.Close()` runs if `lnk2` attach fails. `defendObjs.Close()` is registered once at the top of the block so the collection is always released on the partial-attach error returns. |
| **5h — Allowlist TOCTOU note** | 2 (cgroup + LSM loaders) | n/a | Added explicit `slog.Info("allowlist loaded into BPF map", …)` at startup with the entry counts; both loaders carry an `AUDIT(5h)` comment noting that the allowlist is a startup snapshot — runtime DNS rotation is not reflected until the next agent restart. |

The audit categories follow the in-repo security plan. Sites that look suspicious but are verified safe carry an inline note explaining why (e.g. unchecked `bpf_probe_read_kernel_str` paired with a `__builtin_memset` of the destination). The superseded standalone defend translation units (`bpf/trace_defend.bpf.c`, `bpf/trace_lsm_defend.bpf.c`) were not annotated because no Go package generates from them; they share their active logic with `bpf/defend_policy.inc` which is annotated.

### Further reading

Maintain optional extended design material under repo-root **`design/`** (e.g. **`egress-truthfulness-spec.md`**, **`egress-truthfulness-implementation-plan.md`**) or **`docs/`** in your clone; those trees are **gitignored** and **not** published from Git. The consumer-facing summary is the **GitHub Actions** sections above and **README** → Requirements.
