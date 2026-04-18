# Runner IPv6 Telemetry + Enforcement (Plan B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add **IPv6** support for **egress enforcement** and matching **telemetry** on GitHub-hosted Linux runners: allowlisted destinations in **IPv6** form, **`cgroup/connect6`** and **`cgroup/sendmsg6`** programs mirroring IPv4, and (phase 1) **syscall-level IPv6 connect observation** where feasible without breaking CO-RE.

**Architecture:** **Userspace** extends `internal/policy` / `internal/agent` compile pipeline to populate **`allowed_ipv6`** `HASH` maps (16-byte keys). **BPF** adds `trace_enforce.bpf.c` sections `SEC("cgroup/connect6")` and `SEC("cgroup/sendmsg6")` with parity checks to IPv4 paths. **Deny events**: extend ringbuf struct with **IPv6 destination** (`daddr[16]`) **or** add parallel `deny_events_v6` map — pick **one** struct layout in Task 1 design note to avoid duplicate consumers.

**Tech Stack:** cilium `ebpf` `AttachCgroupInet6Connect`, `AttachCgroupInet6Sendmsg`, Go `net.IP`, domain resolution for AAAA records in enforce compile path.

---

## File Structure / Responsibility Map

- Modify: `bpf/trace_enforce.bpf.c` — IPv6 cgroup programs + `allowed_ipv6` HASH map + deny payload variant.
- Modify: `internal/bpf/traceenforce/*` — regenerated specs.
- Modify: `internal/agent/agent_linux.go` — `loadEnforceMaps` IPv6 keys, `readDenyRing` decode wider event if struct grows.
- Modify: `internal/config` — document `allowed-domains` resolving to AAAA when `COLDSTEP_ENFORCE_IPV6=1` or feature gate (exact env name chosen in Task 1).
- Modify: `internal/policy` — compilation of IPv6 literal allowlist strings.
- Test: `internal/agent/agent_linux_test.go` — enforce compile tests for IPv6 literals.

---

### Task 1: Data layout decision + BPF skeleton

**Files:**
- Modify: `bpf/trace_enforce.bpf.c`

- [ ] **Step 1: Choose deny event layout**

Either:

- **Option 1 (single struct):** `struct deny_event { ... __u8 daddr[16]; __u8 family; }` with `family = AF_INET / AF_INET6`, **breaking** JSONL consumers — requires coordinated **`telemetry`** + digest updates.

- **Option 2 (dual ringbufs):** `deny_events` IPv4 unchanged; add `deny_events_v6` — userspace merges streams.

Document chosen option in commit message; **recommend Option 2** for backward compatibility on first iteration.

- [ ] **Step 2: Add `allowed_ipv6` HASH + connect6 program**

Mirror `allowed_ipv4` stanza with `__type(key, struct in6_addr)` or raw `unsigned char[16]` key.

Implement `SEC("cgroup/connect6")` analogous to `enforce_connect4`, reading destination from `struct bpf_sock_addr *ctx` IPv6 fields (`ctx->user_ip6` per kernel BPF API).

- [ ] **Step 3: Build**

Run: `bash scripts/build-agent-linux.sh` from repo root.  
Expected: verifier success on `ubuntu-latest` kernel headers used by CI container.

---

### Task 2: Userspace map fill + tests

**Files:**
- Modify: `internal/agent/agent_linux.go` — functions building IPv6 allowlist sets.
- Modify: `internal/agent/agent_linux_test.go`

- [ ] **Step 1: Unit test IPv6 compile**

Add `TestRun_EnforceAllowlistIPv6Literal` asserting enforce map receives `2001:db8::1` when resolver yields no AAAA but literal allowed-ips includes IPv6 (mirror existing IPv4 literal test pattern around `compileEnforceAllowlist`).

- [ ] **Step 2: Wire loader**

Update `loadEnforceMaps` to call `objs.AllowedIpv6.Update` for each resolved key.

- [ ] **Step 3: Verification**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./internal/agent -count=1 -run Enforce`  
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add bpf/trace_enforce.bpf.c internal/bpf/traceenforce internal/agent/*.go
git commit -m "feat(enforce): IPv6 cgroup connect/sendmsg allowlist"
```

---

## Self-Review

- Plan B is intentionally large; split execution into **BPF skeleton commit** + **Go loader commit** if reviews require.
- Placeholder scan: syscall IPv6 **observe** path listed as optional follow-up PR if cgroup path lands first.
