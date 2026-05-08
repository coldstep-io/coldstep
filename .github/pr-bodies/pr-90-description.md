## Summary

This branch bundles **BPF hot-path work** on `trace_connect`-related observability, **defend-mode JSONL clarity** (`hook_family` / `match_kind` on deny lines), **operator-facing honesty** updates (digest triage copy, `SECURITY.md` / `README`), a **warn-only** DNS allowlist cardinality log, **shared BPF helpers** (`coldstep_pure.h`) with **host-side C tests**, and **tooling** (agent Linux verify scripts, deep-debug and BPF C test runners, encoding-scan / MCP / review-gate scripts, code-review MCP Docker image).

## BPF (detect path)

- Reduce redundant `bpf_probe_read_user` on `struct msghdr` for sendmsg-style paths.
- Reuse connect tuple / pid-tgid plumbing where safe for connected egress and TLS/UDP paths.
- Style cleanup in `trace_udp_obs.inc`; related include and syscall-obs header tweaks.

## Defend / agent

- Deny JSONL events gain optional **`hook_family`** (`lsm` | `cgroup`) and **`match_kind`** (`dns_cache` | `unknown` from userspace cache lookup).
- `readDenyRing` is wired to enforcement backend and shared DNS cache.

## Policy / reporting / telemetry

- Warn (slog) when a single allowed domain resolves to more than **10** distinct IPv4s; compile outcome unchanged.
- Digest: triage row for partial visibility / io_uring signal; KPI footnotes aligned with `SECURITY.md`.
- `telemetry.Summary` and `DenyEvent` godoc tightened.

## Docs / repo hygiene

- `SECURITY.md`: guarantees vs best-effort, cgroup vs LSM table, DNS note; `README` links.
- `.gitignore`: `design/` for local specs; ignore bpf2go **`.o.tmp`** under `internal/bpf/`.

## Tooling and CI helpers

- `scripts/agent-linux-verify.*`, `agent_linux_verify.py`, `run-bpf-c-unit-tests.sh`, `docker-deep-debug.sh`, updates to `build-agent-linux.sh` / `docker-linux-test.sh`.
- Encoding check expansion, repo review gate, MCP surface emitter, code-review MCP Docker image and smoke scripts (see commit list for detail).

## Verification

- Linux: `go test ./...` (authoritative); Docker `golang` image used locally for agent/report/policy/telemetry packages.
- `scripts/check-encoding.sh` for tracked text.

## Risk / notes

- JSONL deny schema is **additive** (`omitempty` fields).
- DNS cardinality warning is **log-only**; does not change allowlists.
- Large surface area; prefer review by area (BPF vs agent vs scripts).
