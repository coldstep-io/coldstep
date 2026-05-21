## Summary

Implements **H15**: a new `lsm/io_uring_cmd` BPF program that denies non-allowlisted IPv4 egress on `IORING_OP_URING_CMD` requests in **defend** mode. This closes a narrow but real gap — the URING_CMD path can reach the network stack via socket-backed `struct file *` without flowing through `security_socket_sendmsg()` (which the existing `lsm/socket_sendmsg` hook already covers for `IORING_OP_SEND` / `IORING_OP_SENDMSG`).

Defense-in-depth only — the cgroup `connect4` / `sendmsg4` hooks remain the always-on primary IPv4 defense path. Older kernels (pre-5.19, no `security_uring_cmd`) and kernels without `CONFIG_BPF_LSM` are gracefully detected and skip the hook silently.

## What changed

### BPF
- **`bpf/trace_lsm_defend_iouring.inc`** (new) — `SEC("lsm/io_uring_cmd")` program. Reads `ioucmd->file`, treats `file->private_data` as `struct socket *`, verifies via `sk->__sk_common.skc_family == AF_INET`, then runs the same LPM allowlist + DNS-cache + ignored-CIDR policy used by `lsm_socket_sendmsg`. Returns `-EPERM` on deny and emits a sample on the existing `lsm_deny_events` ringbuf. Every `bpf_probe_read_kernel` return is checked (audit 5f); `daddr == 0` falls through to allow so non-AF_INET URING_CMDs (NVMe pass-through etc.) are unaffected.
- **`bpf/trace_defend_all.bpf.c`** — `#include` the new section after `trace_lsm_defend_lsm.inc` so it reuses the `lsm_*` maps + policy helpers from that include.

### Go
- **`internal/bpf/defend/loader.go`**:
  - Added `HaveIOUringLSM()` — probes kernel BTF for `security_uring_cmd` (Linux 5.19+). Returns false on any BTF failure so callers degrade safely.
  - Updated `LoadDefendObjectsForKernel` signature to `(obj, wantLSM, wantIOUringLSM bool)`. New `wantLSM=true, wantIOUringLSM=false` path strips only the io_uring program (LSM-only maps stay so `socket_connect` / `socket_sendmsg` still load).
- **`internal/agent/agent_linux.go`**:
  - Probes `defend.HaveIOUringLSM()` before loading.
  - Attempts `link.AttachLSM` for `LsmIoUringCmd` after the existing two LSM attaches succeed. Failure here only degrades the io_uring path — the cgroup + socket-LSM defense story is unchanged.
  - Appends a `BPFStatus` row named `lsm/io_uring_cmd` **only** when attach was attempted, so pre-5.19 kernels are not reported as having a degraded hook they cannot host.

### Tests
- **`internal/bpf/defend/loader_test.go`** (new) — three pure-spec tests asserting the io_uring program is present, can be stripped together with the other LSM programs, and can be stripped on its own (pre-5.19 path).
- **`internal/agent/defend_iouring_source_test.go`** (new) — Linux-only structural test reading the BPF source files. Verifies the include is wired, includes are in the right order (cgroup → lsm → iouring), the hook uses the `lsm_*` policy helpers, and there are no unchecked `bpf_probe_read_kernel` calls.

### Docs
- **`SECURITY.md`** — updated the "guarantees vs best-effort" io_uring paragraph to describe the new defend coverage and graceful-degradation behavior, and added the `lsm/io_uring_cmd` row to the defend hooks table. Repo file references updated to the post-Phase-2.3 combined source layout (`trace_defend_all.bpf.c` + `*.inc`).

## Constraints honored

- **IPv4-only**, matching the rest of defend mode. No IPv6 promises added anywhere.
- **No `enforce` references** introduced.
- **No generated BPF artifacts** committed (`bpf/vmlinux.h`, `*_bpfel.go` remain gitignored).
- **Bounded reads only** — every `bpf_probe_read_kernel` is checked; no probe-loops; constant-size struct field reads.
- **Cross-platform builds preserved** — all new Go code is `//go:build linux`-tagged. The Windows stub path is untouched.
- **API additive at the boundary** — `LoadDefendObjectsForKernel` signature changed but only has one caller in the agent.

## Validation

- `bash scripts/check-gofmt.sh` — pass.
- `bash scripts/check-encoding.sh` — pass.
- `go test $(go list ./... | grep -v internal/bpf/) -count=1` — pass on Windows (BPF stub packages require Linux + clang + libbpf to generate `*_bpfel.go`; verified by CI's `coldstep-ci-runner.yml` `unit` / `unit-arm64` / `integration` / `defend-mode` jobs).
- BPF compile + verifier load on `ubuntu-latest` + `ubuntu-22.04` (x86 + arm64) is validated by CI.

## Follow-ups (out of scope)

- Integration test that actually fires an `IORING_OP_URING_CMD` against a socket to observe a deny on a kernel with `CONFIG_BPF_LSM=y` and `bpf` in `lsm=`. The current red-team fixtures don't include an io_uring driver; tracked separately.
- BG-05 `io_uring` completions research backlog item remains open — H15 is a defense-in-depth narrow patch, not the full coverage answer for async I/O.
