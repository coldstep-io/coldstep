# redteam — eBPF red-team probe sandbox

A small, runnable sandbox of "attack" probes used to validate that coldstep
actually captures the sensitive activity it claims to. Each case intentionally
triggers a class of suspicious behavior (process exec, DNS/UDP egress, BPF
introspection, TLS egress, filesystem permission changes) and the
[`coldstep-redteam-ebpf`](../.github/workflows/coldstep-redteam-ebpf.yml)
workflow asserts the events show up in `.coldstep-events.jsonl` with high
integrity (the anti-blindness gate, `coldstep assert-integrity`).

## Cases

| Case | Signal | Probe |
| :--- | :----- | :---- |
| [`exec-canary`](./exec-canary) | arbitrary process exec | `ls`, `bash -c` (comm=bash integrity canary) |
| [`udp-dns-canary`](./udp-dns-canary) | DNS / UDP egress | `dig @8.8.8.8` |
| [`bpf-audit-probe`](./bpf-audit-probe) | BPF map/prog enumeration | `bpftool map/prog show` |
| [`network-egress-tls`](./network-egress-tls) | outbound TLS data egress | `curl` + `openssl s_client` to an allowlisted host |
| [`fs-event-probe`](./fs-event-probe) | filesystem permission change | `chmod` (fchmodat) on a temp file |

Each case directory has a `probe.sh` (self-contained, runnable) and a
`README.md` describing the attack signal and the expected coldstep behavior.

## Running

Run the whole suite (this is what the workflow calls):

```bash
bash redteam/run-all.sh                 # uses default TLS host theclouddj.com
bash redteam/run-all.sh example.com     # forward a different allowlisted SNI
```

Or run a single case:

```bash
bash redteam/exec-canary/probe.sh
```

The probes are best-effort by design — a missing tool or a blocked egress
attempt degrades gracefully, because the *attempt* is the telemetry signal.

## Context

The probes generate telemetry; the assertions live in two places:

- **Workflow** — the `audit-validation` job in
  [`coldstep-redteam-ebpf.yml`](../.github/workflows/coldstep-redteam-ebpf.yml)
  starts coldstep (detect, enhanced profile), runs `redteam/run-all.sh`, stops
  coldstep, and runs `coldstep assert-integrity` as the anti-blindness gate.
- **Go integration tests** — the `redteam-integration` job runs the
  `TestRedTeam_*` suite under `internal/agent`, which asserts coldstep surfaces
  the security-review attack paths as JSONL events / deny behavior.

> These probes are deliberately benign (they touch only public hosts, the local
> temp dir, and read-only BPF introspection). They exist to test the monitor,
> not to cause harm.
