# Coldstep Simplification Plan

> **Status:** Phases 2.2 and 2.4 complete. Phase 2.3 planned.
>
> This file lives at the repo root and is tracked in git (unlike `/docs/`).

---

## Phase 2.2 — Unified policy loader ✓ done (PR #136, net -13 LOC)

### Current state

`internal/config/config.go` and `internal/agent/agent_linux_policy_maps.go` each contain a full allowlist-compile path that partially duplicates the other:

- `config.go` calls `policy.BuildPolicyEx(hosts, ips, ignored, ...)` once at load time to *validate* the allowlist strings, and again via `cfg.BuildPolicy()` when the agent needs a `*policy.Policy` at runtime.
- `agent_linux_policy_maps.go` contains **two nearly identical functions** (one for the cgroup defend path, one for the LSM defend path) that each call `policy.CompileDomainAllowlist(ctx, cfg.AllowedDomains, ...)`, merge literal IPs, and then populate BPF maps. The IPv4 key-building and `pol.MergeLiteralAllowedIPv4Keys` / `pol.MergeLiteralAllowedIPv4Into` sequences are copy-pasted between the two functions.

### Planned state

Introduce a single `policy.CompileAllowlist(ctx context.Context, cfg *config.Config) (policy.CompileResult, *policy.Policy, error)` entry point (or equivalent internal helper) that both the cgroup path and LSM path call. Neither caller would duplicate the resolve-and-merge sequence.

The `config.BuildPolicy()` method already exists as the right seam; the remaining duplication is the `CompileDomainAllowlist` + `MergeLiteral*` block that appears twice in `agent_linux_policy_maps.go`.

### Rationale

- A bug fix or threshold change in one copy is silently missed in the other.
- The two paths must stay in sync whenever the BPF map loading contract changes.
- Test coverage of the shared path is diluted across two call sites.

### Estimated impact

~35–50 LOC removed from `agent_linux_policy_maps.go`; zero change to observable behaviour or BPF maps.

### Risks

Low. The two existing code paths are structurally identical today; the consolidation is a refactor with no semantic change. The only risk is a subtle difference between the cgroup and LSM contexts (e.g. a different `maxAttempts` value) that must be verified before merging.

---

## Phase 2.3 — Shared BPF skeleton

### Current state

There are two separate `bpf2go`-generated packages:

| Package | Source BPF file | Go struct |
|---|---|---|
| `internal/bpf/tracedefend` | `bpf/trace_defend.bpf.c` | `TracedefendObjects` |
| `internal/bpf/tracelsmdefend` | `bpf/trace_lsm_defend.bpf.c` | `TracelsmdefendObjects` |

Both BPF programs include `bpf/defend_policy.inc`, which defines the shared policy-map schema (`allowed_ipv4`, `allowed_domains`, `ignored_ipv4_nets`). The generated Go struct surface covers the same logical maps twice, under different type names.

### Planned state

Consolidate into a single `bpf2go` call (or a single source BPF file with conditional compilation for the cgroup vs. LSM attach path) that produces one `ColdstepDefendObjects` Go struct exposing both the cgroup programs and the LSM programs. The `internal/bpf/tracedefend` and `internal/bpf/tracelsmdefend` packages would be replaced by a single `internal/bpf/defend` package.

### Rationale

- `bpf2go` generates ~600 LOC per architecture pair (bpfel + bpfeb) × 2 packages = ~1 200 LOC of generated code covering the same maps.
- Any change to `defend_policy.inc` requires regenerating both packages and verifying both load correctly.
- The agent's `loadCgroupDefendMaps` / `loadLSMDefendMaps` functions must cast through two different generated types even though the underlying BPF maps are structurally identical.

### Estimated impact

~600 LOC removed from generated files; the two `gen.go` / `run_bpf2go.go` files collapse into one; the agent's map-loading calls use a single struct type. Requires `clang` / `libbpf-dev` for regeneration (already required for any BPF change).

### Risks

Medium. BPF skeleton consolidation requires careful testing under both attach paths (cgroup and LSM hook). The generated `.o` objects embed platform-specific BPF bytecode; any structural change must be validated on a Linux host with BPF support before merge. The pure-Go packages (`internal/policy`, `internal/config`, `cmd/`) are unaffected.

---

## Phase 2.4 — This document

### Current state

No single document described the planned simplifications or their rationale. Simplification intent was spread across ad-hoc PR descriptions and the `plans/` directory.

### Planned state

This file (`SIMPLIFICATION_PLAN.md`) at the repo root serves as the living reference. Each phase section is updated in-place as work completes (status line, estimated vs. actual LOC impact).

### Rationale

- Phases 2.2 and 2.3 are non-trivial refactors; having a written contract prevents drift between the implementation and the original intent.
- The `plans/` directory is not the right home for ongoing engineering decisions that need to be cited from PRs — repo-root docs are easier to link.
- `/docs/` is gitignored and therefore cannot serve this purpose.

### Estimated impact

+1 file, ~0 runtime LOC change.

### Risks

None.

---

## Completion checklist

- [x] 2.4 — SIMPLIFICATION_PLAN.md written and tracked
- [x] 2.2 — Unified policy loader implemented and merged (PR #136, net -13 LOC)
- [ ] 2.3 — Shared BPF skeleton implemented and merged
