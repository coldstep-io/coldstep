# BPF audit probe

**Attack signal:** an attacker enumerating or tampering with loaded BPF
maps/programs (e.g. to find and detach the monitor).

**Probe:** `sudo bpftool map show` / `prog show` to introspect kernel BPF state.

**Expected coldstep behavior:** the privileged BPF introspection syscalls are
surfaced by the bpf-audit hook (`bpf_syscall_audit` telemetry). The probe
resolves a concrete `bpftool` binary so the recorded `comm` is `bpftool`, which
the integrity canaries match on. All calls are best-effort — a missing or
wrapper `bpftool` degrades gracefully.

**Requires:** `bpftool` (Debian/Ubuntu: `linux-tools-*`) and `sudo`.

Run it standalone:

```bash
bash redteam/bpf-audit-probe/probe.sh
```
