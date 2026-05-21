## Summary

Implements **H14 — IPv6 block Phase 2** from the v0.4.0 hardening roadmap. The defend-mode BPF / userspace plumbing for blocking non-allowlisted IPv6 egress already landed in P2-1 (PR #164): `bpf/trace_defend_cgroup.inc` carries `cgroup/connect6` + `cgroup/sendmsg6` hooks that consult an AAAA-populated `allowed_ipv6` LPM trie and return EPERM on miss, `bpf/defend_lpm_v6_key.h` declares the trie key, `internal/policy/allowlist.go` resolves AAAA records in parallel, and `internal/agent/agent_linux_policy_maps.go` populates the trie. This PR closes the three remaining H14 gaps relative to that baseline:

- the public coverage telemetry now carries a meaningful **`ipv6` enforcement label** ("enforce" / "off") instead of the v0.2.9 stub `bool: false`,
- a Go-side unit test pins the **loopback / link-local bypass classification** that the BPF program relies on,
- **README** and **SECURITY.md** drop the "IPv6 is unsupported in defend" wording that was true at v0.2.9 and now reflect the H14 enforcement story.

## What changed

- **`internal/telemetry/event.go`** — `CoverageReport.IPv6` changes type from `bool` to `string` with three named values (`telemetry.CoverageIPv6Off`, `…ObserveOnly`, `…Enforce`). The "observe-only" tier is reserved for the standalone detect-mode IPv6 observer (H7, separately tracked in PR #199) and is not emitted by the current agent. The field stays in the same JSON position (`"ipv6": …`) with no `omitempty` so consumers can rely on the key always being present.

- **`internal/agent/agent_linux_digest.go`** — `buildCoverageReport` grows an `ipv6Enforced bool` parameter. When true it sets `CoverageReport.IPv6 = "enforce"`; otherwise `"off"`. No change to the other coverage cells (IPv4 TCP/UDP, TLS SNI, io_uring) — the agent's "Coverage scope" digest table already reads its IPv6 row from the digest-side renderer (`ipv6CoverageCell` in `internal/report/digest.go`), which is unchanged.

- **`internal/agent/agent_linux.go`** — the single `buildCoverageReport` caller computes `ipv6Enforced := cfg.Mode == config.ModeDefend && hasDefend`. An empty `allowed_ipv6` trie is still reported as `"enforce"` because the cgroup6 hook denies every non-loopback IPv6 destination in that posture (the existing digest renderer already labels it `✓ gated (defend block-all — empty allowed_ipv6)`). When the hooks are not loaded (detect mode, or kernel rejected the program), `hasDefend` is false and the label degrades to `"off"`.

- **`internal/agent/coverage_report_linux_test.go`** — `TestBuildCoverageReport` grows a sixth row pinning the defend-mode `"enforce"` outcome, plus an `ipv6Enforced` column on every existing row so detect-mode and probe-degraded paths regress against the `"off"` value. The IPv4 / TLS / io_uring assertions are unchanged.

- **`internal/telemetry/event_test.go`** — `TestCoverageReportJSON` now exercises `"ipv6":"enforce"` and a sibling `TestCoverageReportIPv6OffSerialization` locks the default `"off"` shape.

- **`internal/policy/ipv6_bypass.go` (new)** — `IPv6BypassesDefend(net.IP) bool` is the userspace mirror of the BPF helpers `cg_ipv6_is_loopback` and `cg_ipv6_is_link_local` in `bpf/trace_defend_cgroup.inc`. The function is documentation + a regression anchor: production code does not consult it (the BPF program is authoritative), but a Go test asserts the exact classification (`::1` and `fe80::/10` bypass; everything else — including `fec0::1`, `fe00::1`, `2001:db8::1`, `fc00::1`, `ff02::1`, `::` — does not). Drift here is a defend-bypass risk in either direction.

- **`internal/policy/ipv6_bypass_test.go` (new)** — table-test for `IPv6BypassesDefend` covering loopback, the fe80::/10 lower and upper bounds, the adjacent fec0::/10 and fe00::/10 ranges that must NOT bypass, unique-local fc00::/7, multicast ff00::/8, global 2000::/3, the unspecified `::`, and IPv4 inputs (which the IPv6 hook never sees but the helper defensively rejects).

- **`README.md`** — "At a glance" defend row now reads "Block IPv4 and IPv6 egress not on the allowlist (cgroup `connect4`/`sendmsg4` + `connect6`/`sendmsg6`; QUIC payloads remain uninspected)". The Requirements row for IP versions describes the H14 enforcement scope, the `::1` / `fe80::/10` always-bypass rule, and the explicit detect-mode IPv6 gap.

- **`SECURITY.md`** — the Coverage Boundaries table splits the old `IPv6 (all)` row into `IPv6 TCP (connect6)` and `IPv6 UDP (sendmsg6)`, both `✗` in detect / `✓` in defend with the H14 attribution. The "Why IPv4-only" paragraph is replaced by a "Defend-mode IPv6 enforcement (H14, v0.4.0)" paragraph spelling out the LPM-trie path, the always-bypass classes, and the still-open detect-mode gap. The "Operational implications", "What a job adversary can do", "Guarantees vs best-effort", and "Defend hooks" sections are updated in lockstep so no stale "IPv6 is unsupported" claim survives.

## Why no BPF or policy-compile changes

The BPF cgroup6 hooks (`defend_cgroup_connect6`, `defend_cgroup_sendmsg6`) already do the LPM lookup against `allowed_ipv6` and emit deny events on miss (P2-1, merged at `f243dcf`). `IPv6Set` already lives on `CompileResult` and is populated from parallel AAAA lookups bounded by `coldstepDomainLookupConcurrencyLimit = 32`; `populateAllowedIPv6Map` in `agent_linux_policy_maps.go` programs the trie. Reworking any of those would be churn, not progress — the H14 spec items that named those changes were satisfied by P2-1 ahead of v0.4.0.

What was left was the public-surface alignment: telemetry shape, docs, and a pinned regression for the loopback/link-local classifier. That is the scope of this PR.

## Constraints honored

- No new BPF programs, maps, or wire-format changes — `lpm_v6_key`, `allowed_ipv6`, and the cgroup6 hooks are unchanged.
- No schema bump — `telemetry.SchemaVersion` is unchanged. The `CoverageReport.IPv6` type change is a JSON value-shape adjustment (`bool` → `string`) within the same key; downstream consumers that parsed the v0.2.9 stub as `bool false` need to update to a string-typed reader, but the field has never carried a meaningful value before v0.4.0.
- No new `enforce` mode references — defend/detect remain the only public mode names.

## Validation

- `bash scripts/check-gofmt.sh` — clean on the modified files.
- `bash scripts/check-encoding.sh` — pass.
- `go vet ./...` on the non-BPF subset (BPF-stub packages require `go generate` on Linux) — pass.
- `go test ./internal/policy/... ./internal/telemetry/... -count=1` — pass.
- BPF compile + verifier load, defend integration, and the cross-architecture matrix are validated by `coldstep-ci-runner.yml` (`unit`, `unit-arm64`, `integration`, `detect-mode`, `defend-mode`).

## Follow-ups (out of scope)

- **H7 detect-mode IPv6 observation** (PR #199, branch `feat/h7-ipv6-detect-warn`) ships a standalone `internal/bpf/traceipv6` package that attaches cgroup/connect6+sendmsg6 in detect mode as observe-only. When that lands, `buildCoverageReport` should grow a second signal so the label can flip to `telemetry.CoverageIPv6ObserveOnly` in detect-mode runs where the observer attached. The constant is already defined.
- **Cgroup6 attach BPFStatus rows.** The current code logs at `slog.Info` when `cgroup/connect6` / `sendmsg6` fail to attach but does not append `BPFStatus` rows, so a degraded IPv6 path is not visible in the digest's BPF section. Tracking separately.
