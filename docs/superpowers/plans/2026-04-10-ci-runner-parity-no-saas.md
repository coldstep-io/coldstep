# CI runner egress parity (no SaaS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship **self-contained** GitHub Action + agent behaviors that match a **strong CI egress-guard** shape (detect vs block, allowlists, ignored networks, job summary, optional PR comment + Slack, log level, fail-on-error, feature flags, debug binary path)—**explicitly excluding** any `client-id` / `secret` / `url` SaaS auth, remote rule feeds, or proprietary hardening rule packs (clean-room: **original code**; public competitor READMEs/`action.yml` may be used only as **behavioral** reference, not source to copy).

**Architecture:** Extend **`internal/policy`** and **`internal/config`** for ignored CIDRs and optional allowlist IP CIDRs; extend **`bpf/trace_enforce.bpf.c`** + **`internal/bpf/traceenforce`** with an **LPM trie** (or equivalent) so **enforce** skips denies for ignored destinations while keeping the existing **hash allowlist** for positive permits; extend **`@actions/core`**-only **`src/post.ts`** / **`src/main.ts`** for PR comments (**add `@actions/github`**) and optional Slack `incoming-webhook` POST; wire new inputs through **`action.yml`** and **`AGENTS.md`** when behavior is user-visible.

**Tech stack:** Go 1.24+ (CI), `bpf2go` + CO-RE, `@actions/core`, `@actions/github`, `ncc`, TypeScript 5.x, Node 24.

**Repository state (2026-04-12):** Substantive items (ignored CIDRs + default RFC1918 merge with **`no-default-ignored-nets`** / **`NIGHTSTALKER_NO_DEFAULT_IGNORED_NETS`**, **≤128** merged nets, enforce **LPM** bypass, PR/Slack post hooks, **`feature-gates`** / **`release-path`**, nightstalker-demo **`guard-enforce-ignored`**) are **shipped on `main`**. Checklist boxes below are an **archival** step breakdown—use **`git log`**, **`README.md`**, and **`action.yml`** for ground truth.

---

## File map (create / modify)

| Path | Responsibility |
|------|------------------|
| `action.yml` | Inputs: `ignored-ip-nets`, `no-default-ignored-nets`, `report-pr-summary`, `slack-webhook-endpoint`, `feature-gates`, `release-path` (+ existing `github-token`, `smoke-test-egress`, etc.). |
| `src/main.ts` | Read inputs; pass env to agent child; optional `release-path` bin selection. |
| `src/post.ts` | After SIGTERM + optional job summary: PR comment + Slack when enabled. |
| `package.json` / `package-lock.json` | Add `@actions/github` (and types if needed). |
| `internal/policy/policy.go` | Parse ignored nets; optional CIDR allow-IPs; `Classify` order: ignored → allowed IP/host → not_listed. |
| `internal/policy/policy_test.go` | Table tests for ignored vs allowlist edge cases. |
| `internal/config/config.go` | Env: `NIGHTSTALKER_IGNORED_IP_NETS`, gates, etc. |
| `internal/config/config_test.go` | Invalid CIDR / enforce without allowlist unchanged. |
| `internal/agent/agent_linux.go` | Load ignored LPM map; pass ignores into policy; digest rows for `ClassIgnored` if surfaced. |
| `bpf/trace_enforce.bpf.c` | LPM map `ignored_ipv4_lpm`; early return in connect/sendmsg hooks when dst matches ignored prefix. |
| `internal/bpf/traceenforce/gen.go` + regenerate | Map definitions for LPM. |
| `internal/report/digest.go` (or policy rollup site) | Display class `ignored` consistently in KPI/policy text if needed. |
| `.github/workflows/nightstalker-demo.yml` | One job line proving ignored net does not produce deny under enforce (narrow fixture). |
| `AGENTS.md` | Only if a **durable** convention is added (e.g. default ignored RFC1918); keep short. |

**Out of scope for this plan (separate plan recommended):** `file-integrity`, `memory-protection`, `hardening` engine content, `apply-fs-events`, `report-process-tree` (requires **new BPF fields** such as parent PID from `sched_process_exec`—not present in `bpf/trace_exec.bpf.c` today).

---

### Task 1: Policy — parse `ignored-ip-nets` (IPv4 CIDR)

**Files:**

- Create: `internal/policy/ignore.go`
- Modify: `internal/policy/policy.go`
- Test: `internal/policy/policy_test.go`

- [x] **Step 1: Write failing tests**

Append to `internal/policy/policy_test.go`:

```go
func TestParseIgnoredIPNets_Valid(t *testing.T) {
	nets, err := ParseIgnoredIPNets("10.0.0.0/8, 192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 2 {
		t.Fatalf("got %d nets", len(nets))
	}
	got := map[string]bool{}
	for _, n := range nets {
		got[n.String()] = true
	}
	if !got["10.0.0.0/8"] || !got["192.168.1.0/24"] {
		t.Fatalf("missing CIDR: %#v", got)
	}
}

func TestParseIgnoredIPNets_RejectsIPv6(t *testing.T) {
	_, err := ParseIgnoredIPNets("2001:db8::/32")
	if err == nil {
		t.Fatal("expected error")
	}
}
```

TDD stub: add `internal/policy/ignore.go` with a stub returning `fmt.Errorf("not implemented")` so **Step 2** fails clearly; replace stub in **Step 3** with the real implementation using return type `[]*net.IPNet`.

- [x] **Step 2: Run tests — expect FAIL**

```bash
cd c:/dumper_5000
go test ./internal/policy -run TestParseIgnoredIPNets -count=1
```

Expected: compile error or `not implemented`.

- [x] **Step 3: Implement `ParseIgnoredIPNets`**

`internal/policy/ignore.go`:

```go
package policy

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

// ParseIgnoredIPNets parses comma/ASCII-whitespace-separated IPv4 CIDRs (v1: IPv4 only).
func ParseIgnoredIPNets(raw string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, tok := range splitFields(raw) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		_, n, err := net.ParseCIDR(tok)
		if err != nil {
			return nil, fmt.Errorf("invalid ignored-ip-net %q: %w", tok, err)
		}
		if ones, bits := n.Mask.Size(); bits != 32 || ones < 0 {
			return nil, fmt.Errorf("ignored-ip-net must be IPv4 CIDR: %q", tok)
		}
		out = append(out, n)
	}
	return out, nil
}
```

Reuse `splitFields` from `policy.go` (same package) — **either** export `splitFields` **or** duplicate the tiny `FieldsFunc` helper in `ignore.go` to avoid export churn (duplicate is acceptable for YAGNI).

- [x] **Step 4: Fix tests to assert real behavior**

Use `mustParseCIDR` helper in test file; assert `10.10.1.2` ∈ `10.0.0.0/8`.

- [x] **Step 5: Run tests — expect PASS**

```bash
go test ./internal/policy -count=1
```

- [x] **Step 6: Commit**

```bash
git add internal/policy/ignore.go internal/policy/policy_test.go
git commit -m "policy: parse ignored IPv4 CIDR nets"
```

---

### Task 2: Policy — `Classify` honors ignored nets (detect semantics)

**Files:**

- Modify: `internal/policy/policy.go`
- Modify: `internal/policy/policy_test.go`

- [x] **Step 1: Add `ClassIgnored` and extend `Policy`**

In `policy.go`, add:

```go
const (
	ClassIgnored Class = "ignored"
)
```

Extend `Policy` struct with `ignored []*net.IPNet` (unexported). Add constructor:

```go
// BuildPolicy parses hosts, IPs, and optional ignored CIDRs (IPv4 only for ignored).
func BuildPolicy(allowedHosts, allowedIPs, ignoredIPNets string) (*Policy, error) {
	ign, err := ParseIgnoredIPNets(ignoredIPNets)
	if err != nil {
		return nil, err
	}
	p, err := Parse(allowedHosts, allowedIPs)
	if err != nil {
		return nil, err
	}
	p.ignored = ign
	return p, nil
}
```

Keep existing `Parse` for backward compatibility; implement `BuildPolicy` calling `Parse` then attaching `ignored`.

In `Classify`, **first** check:

```go
if ip4 := ip.To4(); ip4 != nil && len(p.ignored) > 0 {
	for _, n := range p.ignored {
		if n.Contains(ip4) {
			return ClassIgnored
		}
	}
}
```

Then existing IP exact / FQDN logic.

Update `Class.Display()` for `ClassIgnored` → e.g. `ignored`.

- [x] **Step 2: Table test**

```go
func TestClassify_IgnoredBeforeNotListed(t *testing.T) {
	p, err := BuildPolicy("", "", "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Classify("", net.ParseIP("10.1.2.3")); got != ClassIgnored {
		t.Fatalf("got %s", got)
	}
}
```

- [x] **Step 3: Run**

```bash
go test ./internal/policy -count=1
```

- [x] **Step 4: Commit**

```bash
git add internal/policy/policy.go internal/policy/policy_test.go
git commit -m "policy: classify RFC1918-style ignores before allowlist"
```

---

### Task 3: Config + call sites — wire `NIGHTSTALKER_IGNORED_IP_NETS`

**Files:**

- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `internal/policy/policy_test.go` (only if integration tests import Parse)
- Grep + modify all `policy.Parse(` call sites to use `BuildPolicy` when ignored string available, or pass `""` to preserve behavior.

Use ripgrep from repo root:

```bash
rg "policy\.Parse\(" -n
```

Replace with `policy.BuildPolicy(hosts, ips, ignored)` where `ignored` comes from env.

Add to `Config`:

```go
IgnoredIPNets string
```

In `LoadFromEnv`:

```go
ignored := strings.TrimSpace(os.Getenv("NIGHTSTALKER_IGNORED_IP_NETS"))
if _, err := policy.ParseIgnoredIPNets(ignored); err != nil {
	return Config{}, err
}
```

(Or validate only inside `Policy()` — pick one path; **avoid double-parse** by storing raw string and validating in `Policy()`.)

Change `Config.Policy()`:

```go
func (c Config) Policy() (*policy.Policy, error) {
	return policy.BuildPolicy(c.AllowedHosts, c.AllowedIPs, c.IgnoredIPNets)
}
```

- [x] **Step 1: Unit test invalid ignored rejects config**

```go
func TestLoadFromEnv_InvalidIgnoredCIDR(t *testing.T) {
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("NIGHTSTALKER_IGNORED_IP_NETS", "not-a-cidr")
	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error")
	}
}
```

- [x] **Step 2: `gofmt`, `go test ./...`**

On Linux CI or `bash scripts/docker-ubuntu-test.sh` per `AGENTS.md`.

- [x] **Step 3: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go internal/policy/policy.go
# include every file changed by rg "policy\.Parse\(" → BuildPolicy migration
git commit -m "config: NIGHTSTALKER_IGNORED_IP_NETS for policy classify"
```

---

### Task 4: Action + main — pass `ignored-ip-nets` into sudo env

**Files:**

- Modify: `action.yml`
- Modify: `src/main.ts`
- Run: `npm run typecheck && npm run build`

`action.yml` (inputs section):

```yaml
  ignored-ip-nets:
    description: >-
      Comma- or whitespace-separated IPv4 CIDRs to treat as non-actionable for policy display
      and (when implemented) enforce bypass. Example: 10.0.0.0/8,172.16.0.0/12
    required: false
    default: ''
```

`src/main.ts` after reading other inputs:

```typescript
const ignoredIpNets = core.getInput('ignored-ip-nets') || '';
```

Add to `childEnv`:

```typescript
NIGHTSTALKER_IGNORED_IP_NETS: ignoredIpNets,
```

- [x] **Step 1: Typecheck + build**

```bash
npm ci
npm run typecheck
npm run build
```

- [x] **Step 2: Commit**

```bash
git add action.yml src/main.ts dist/
git commit -m "action: ignored-ip-nets input wired to agent env"
```

---

### Task 5: BPF enforce — skip deny when dst ∈ ignored LPM trie

**Files:**

- Modify: `bpf/trace_enforce.bpf.c`
- Modify: `internal/bpf/traceenforce/gen.go` (if map section names need export)
- Modify: `internal/agent/agent_linux.go` (`loadEnforceMaps` or adjacent)
- Test: extend integration / nightstalker-demo (real cgroup attach is hard in unit tests)

**Design:** Add `BPF_MAP_TYPE_LPM_TRIE` map `ignored_ipv4_lpm` with `struct { __u32 prefixlen; __u32 addr; }` key (IPv4 in `addr` as **big-endian** u32 per libbpf LPM examples) and `__u8` value `1`. Populate from Go with each ignored CIDR. In BPF, before `dst_is_allowlisted`, if `bpf_lpm_trie_lookup_elem(&ignored_ipv4_lpm, &key)` hits, **return 0** (allow) from the cgroup hook without deny.

**Go loader:** After `LoadTraceenforceObjects`, fill LPM from `cfg` parsed nets (duplicate parse from `Policy()` or store `[]*net.IPNet` on config — prefer reading from `policy.ParseIgnoredIPNets(cfg.IgnoredIPNets)` once in agent startup).

- [x] **Step 1: Document spike in `docs/superpowers/specs/` (optional one-pager)**

File: `docs/superpowers/specs/2026-04-10-enforce-ignored-lpm-notes.md` — key layout, max prefix entries (e.g. 64), what happens when empty map.

- [x] **Step 2: Implement BPF + regenerate**

```bash
bash scripts/build-agent-linux.sh
```

- [x] **Step 3: nightstalker-demo enforce line**

Add a step that sets `ignored-ip-nets: 10.0.0.0/8` and triggers traffic to `10.0.0.1` (or similar) that would otherwise deny—assert no `deny` JSONL row (or assert deny count 0). **Exact YAML** must follow existing nightstalker-demo patterns (`curl -4`, hosts pin rules from `AGENTS.md`).

- [x] **Step 4: Commit**

```bash
git add bpf/trace_enforce.bpf.c internal/bpf/traceenforce internal/agent/agent_linux.go .github/workflows/nightstalker-demo.yml
git commit -m "enforce: bypass denies for ignored IPv4 CIDR trie"
```

---

### Task 6: Default implicit ignores (CI baseline)

**Files:**

- Modify: `internal/policy/ignore.go` or `BuildPolicy`
- Test: `internal/policy/policy_test.go`

**Baseline:** implicitly ignore `10.0.0.0/8` and `172.16.0.0/12` (Docker-style internal traffic). **Merge** user `ignored-ip-nets` with defaults unless `NIGHTSTALKER_NO_DEFAULT_IGNORED_NETS=true` (document in `action.yml` description only if you add the escape hatch—YAGNI: always merge defaults for v1).

Implementation sketch in `BuildPolicy`:

```go
defaults, _ := ParseIgnoredIPNets("10.0.0.0/8 172.16.0.0/12")
// append user nets; dedupe by string() of CIDR in a map
```

- [x] **Step 1: Test** — empty user input still ignores `10.2.3.4`.

- [x] **Step 2: Commit**

```bash
git commit -m "policy: default Docker-style ignored RFC1918 nets"
```

---

### Task 7: `report-pr-summary` — PR comment with digest excerpt

**Files:**

- Modify: `action.yml`
- Modify: `package.json`
- Modify: `src/post.ts`
- Modify: `src/main.ts` (if inputs must be echoed to post via state file — **`core.getInput` in post only reads composite inputs if GitHub passes them**; for composite actions, post step receives same inputs—verify; if not, write `inputs.json` to `GITHUB_ACTION_PATH` in main).

**Preferred pattern:** In `post.ts`, `core.getInput('report-pr-summary')` works for composite actions on GitHub when inputs are declared on the step.

Add dependency:

```bash
npm install @actions/github@^6
```

`src/post.ts` core logic (illustrative — use real types):

```typescript
import * as github from '@actions/github';

async function maybePostPRSummary(body: string): Promise<void> {
  const flag = core.getInput('report-pr-summary');
  if (!['true', '1', 'yes', 'on'].includes(flag.toLowerCase())) {
    return;
  }
  const token = core.getInput('github-token') || process.env.GITHUB_TOKEN;
  if (!token) {
    core.warning('report-pr-summary: missing github-token');
    return;
  }
  const ctx = github.context;
  if (!ctx.payload.pull_request) {
    core.info('report-pr-summary: not a pull_request event; skipping');
    return;
  }
  const octokit = github.getOctokit(token);
  const pr = ctx.payload.pull_request.number;
  const snippet = body.length > 60000 ? body.slice(0, 60000) + '\n\n_(truncated)_\n' : body;
  await octokit.rest.issues.createComment({
    owner: ctx.repo.owner,
    repo: ctx.repo.repo,
    issue_number: pr,
    body: '## Nightstalker digest\n\n' + snippet,
  });
}
```

Call after reading digest file from workspace (same path helpers as `flushDetectLogToJobSummary`).

- [x] **Step 1: Unit-style manual test**

Run `act` or a fork PR—if unavailable, **mock** is acceptable **only** in a small `src/post-pr.test.ts` if you add `vitest`—**YAGNI:** skip TS test harness; rely on **typecheck** + **nightstalker-demo on PR** optional follow-up.

- [x] **Step 2: `npm run build`, commit `dist/`**

```bash
git add package.json package-lock.json src/post.ts action.yml dist/
git commit -m "action: optional PR comment with digest excerpt"
```

---

### Task 8: `slack-webhook-endpoint` — post step webhook

**Files:**

- Modify: `action.yml`
- Modify: `src/post.ts`

Use `fetch` (Node 18+) with JSON body `{"text": "..."}` for [Slack incoming webhooks](https://api.slack.com/messaging/webhooks). Redact secrets from digest body (grep for `Authorization` / `Bearer` defensively—optional minimal strip).

```typescript
async function maybeSlack(webhook: string, text: string): Promise<void> {
  if (!webhook) return;
  const r = await fetch(webhook, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text }),
  });
  if (!r.ok) {
    core.warning(`slack webhook failed: ${r.status}`);
  }
}
```

- [x] **Step 1: Commit**

```bash
git add src/post.ts action.yml dist/
git commit -m "action: optional Slack webhook notification"
```

---

### Task 9: `feature-gates` — pass-through env for agent experiments

**Files:**

- Modify: `action.yml`
- Modify: `src/main.ts`
- Modify: `internal/config/config.go` (parse `NIGHTSTALKER_FEATURE_GATES` key=value comma list into `map[string]string` if needed)

Minimal: pass raw string env `NIGHTSTALKER_FEATURE_GATES` unchanged; agent reads when first feature gate is implemented.

```typescript
const featureGates = core.getInput('feature-gates') || '';
// childEnv:
NIGHTSTALKER_FEATURE_GATES: featureGates,
```

- [x] **Step 1: Commit**

```bash
git commit -m "action: feature-gates passthrough env"
```

---

### Task 10: `release-path` — optional prebuilt `ci-runtime-guard` binary

**Files:**

- Modify: `action.yml`
- Modify: `src/main.ts`

If `release-path` non-empty and file executable exists at that path, **skip** `execFileSync('bash', [script, actionPath])` and copy or use that binary into `actionPath/bin/ci-runtime-guard`.

```typescript
const releasePath = core.getInput('release-path').trim();
if (releasePath) {
  const src = path.isAbsolute(releasePath) ? releasePath : path.join(baseDir, releasePath);
  if (!fs.existsSync(src)) {
    core.setFailed(`release-path not found: ${src}`);
    return;
  }
  fs.copyFileSync(src, binPath);
  fs.chmodSync(binPath, 0o755);
} else {
  execFileSync('bash', [script, actionPath], { stdio: 'inherit' });
}
```

- [x] **Step 1: Commit**

```bash
git commit -m "action: release-path debug override for agent binary"
```

---

## Self-review (plan vs “no SaaS” scope)

1. **Spec coverage:** SaaS/auth/url/secret **explicitly excluded**. Runner parity items mapped: ignored nets (+defaults), enforce bypass, PR summary, Slack, feature gates, release path. **Not covered here:** file integrity, memory protection, hardening tiers, FS events, process tree (needs BPF schema work)—listed under “Out of scope”.
2. **Placeholder scan:** No `TBD` tasks; BPF LPM requires kernel verifier validation on `ubuntu-latest` (called out).
3. **Type consistency:** `BuildPolicy` / `ParseIgnoredIPNets` naming used consistently; TS uses same input names as `action.yml`.

---

**Plan complete and saved to `docs/superpowers/plans/2026-04-10-ci-runner-parity-no-saas.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints for review.

**Which approach?**
