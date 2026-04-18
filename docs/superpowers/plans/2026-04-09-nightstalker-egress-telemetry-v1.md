# Nightstalker egress telemetry & allow lists (v1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add GitHub Action inputs and agent behavior for `allowed-hosts`, `allowed-ips`, operational `fail-on-error`, `log-level`, and `report-job-summary`; enrich Markdown + JSONL + summary JSON telemetry with per-TCP egress classification; keep **detect-only** and **no fail-on egress violation** in v1 (phase 2).

**Repository state (2026-04-11):** This v1 umbrella shipped on **`main`** (policy + config + telemetry + action + nightstalker-demo). The checklist below is **historical**; follow **`2026-04-10-network-egress-phase1.md`** and **`AGENTS.md`** for current egress work.

**Architecture:** Parse allow lists in Go (`internal/policy`), extend `config.LoadFromEnv` with `NIGHTSTALKER_*` variables set by the composite `main` step. The agent classifies each TCP row (`monitor` / `allowed` / `not listed` / `unknown`), appends a **Policy** column to the detect table, mirrors each TCP event to **JSONL**, and writes a **telemetry summary JSON** on shutdown. `main.ts` optionally waits for a **ready** JSON file before finishing; `post.ts` enforces `fail-on-error` and honors `report-job-summary`. Clean-room: original implementation without copying third-party guard code.

**Tech Stack:** Go 1.24+, `log/slog`, existing cilium/ebpf agent; Node 24 action (`@actions/core`), ncc `dist/` bundle.

---

## File map

| File | Responsibility |
|------|----------------|
| `internal/policy/policy.go` | Parse allow hosts/IPs; `Classify(fqdn, ip)` → `Class` |
| `internal/policy/policy_test.go` | Table-driven tests for hosts, wildcards, IPs |
| `internal/config/config.go` | New env fields; default paths under `GITHUB_WORKSPACE` |
| `internal/config/config_test.go` | Tests for new env wiring |
| `internal/telemetry/telemetry.go` | JSONL append + summary JSON write |
| `internal/telemetry/telemetry_test.go` | Golden / round-trip tests |
| `internal/report/detect.go` | Preamble + `FormatDetect*` with Policy column |
| `internal/report/detect_test.go` | Update assertions |
| `internal/agent/agent_linux.go` | slog, stats, policy, JSONL, ready file, summary on exit |
| `action.yml` | Inputs: `allowed-hosts`, `allowed-ips`, `fail-on-error`, `log-level`, `report-job-summary` |
| `src/main.ts` | `getInput` → env; optional wait for ready file |
| `src/post.ts` | `fail-on-error` + `report-job-summary`; read ready file |
| `README.md`, `AGENTS.md` | Document inputs and artifacts |
| `.github/workflows/nightstalker-demo.yml` | Optional grep for `Policy` / JSONL (keep existing egress checks) |

---

## Sprint 1 — Policy engine (TDD)

### Task 1: `internal/policy` package

**Files:**
- Create: `internal/policy/policy.go`
- Create: `internal/policy/policy_test.go`

- [x] **Step 1: Add `policy.go`**

```go
package policy

import (
	"net"
	"strings"
	"unicode"
)

// Class describes egress vs allow lists (v1: never fails the job).
type Class string

const (
	ClassMonitor   Class = "monitor"    // no allow lists configured
	ClassAllowed   Class = "allowed"
	ClassNotListed Class = "not_listed"
	ClassUnknown   Class = "unknown" // lists on, but only IP observed (no fqdn match path)
)

// Policy is immutable after Parse.
type Policy struct {
	enabled      bool
	exactHosts   map[string]struct{}
	wildSuffixes []string // "*.example.com" -> "example.com"
	ips          map[string]struct{}
}

// Parse builds a policy from raw action/env strings (comma or ASCII whitespace).
func Parse(allowedHosts, allowedIPs string) (*Policy, error) {
	p := &Policy{
		exactHosts: make(map[string]struct{}),
		ips:        make(map[string]struct{}),
	}
	for _, h := range splitFields(allowedHosts) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			suf := strings.TrimPrefix(h, "*.")
			if suf == "" || strings.Contains(suf, "*") {
				continue
			}
			p.wildSuffixes = append(p.wildSuffixes, suf)
		} else {
			p.exactHosts[h] = struct{}{}
		}
	}
	for _, raw := range splitFields(allowedIPs) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, &net.ParseError{Type: "ip", Text: raw}
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, &net.ParseError{Type: "ipv4", Text: raw}
		}
		p.ips[string(ip4)] = struct{}{}
	}
	p.enabled = len(p.exactHosts) > 0 || len(p.wildSuffixes) > 0 || len(p.ips) > 0
	return p, nil
}

func splitFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}

func hostMatchesWildcard(fqdn, suffix string) bool {
	if !strings.HasSuffix(fqdn, "."+suffix) {
		return false
	}
	prefix := strings.TrimSuffix(fqdn, "."+suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

// Classify evaluates observed egress. ip must be IPv4; fqdn lowercased externally.
func (p *Policy) Classify(fqdn string, ip net.IP) Class {
	if p == nil || !p.enabled {
		return ClassMonitor
	}
	ip4 := ip.To4()
	if ip4 != nil {
		if _, ok := p.ips[string(ip4)]; ok {
			return ClassAllowed
		}
	}
	fqdn = strings.ToLower(strings.TrimSpace(fqdn))
	if fqdn != "" {
		if _, ok := p.exactHosts[fqdn]; ok {
			return ClassAllowed
		}
		for _, suf := range p.wildSuffixes {
			if fqdn == suf || hostMatchesWildcard(fqdn, suf) {
				return ClassAllowed
			}
		}
		return ClassNotListed
	}
	return ClassUnknown
}

// Display renders a short Markdown table cell.
func (c Class) Display() string {
	switch c {
	case ClassMonitor:
		return "monitor"
	case ClassAllowed:
		return "allowed"
	case ClassNotListed:
		return "not listed"
	case ClassUnknown:
		return "unknown"
	default:
		return string(c)
	}
}
```

- [x] **Step 2: Add tests** (`policy_test.go`) covering: empty → monitor; exact host; `*.example.com` matches `a.example.com` not `a.b.example.com`; IP allow; not listed with fqdn; unknown with empty fqdn; invalid IP error.

- [x] **Step 3: Run**

```bash
go test ./internal/policy/... -v -count=1
```

Expected: PASS

- [x] **Step 4: Commit** `feat(policy): parse allow lists and classify egress`

---

## Sprint 2 — Config & telemetry helpers

### Task 2: Extend `config.LoadFromEnv`

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

Add fields: `AllowedHosts`, `AllowedIPs`, `LogLevel`, `EventsLogPath`, `TelemetrySummaryPath`, `AgentStatusPath`. Defaults when unset: under `GITHUB_WORKSPACE` — `.nightstalker-events.jsonl`, `.nightstalker-telemetry.json`, `.nightstalker-ready.json`. Validate policy via `policy.Parse` on non-empty host/IP strings; return error on invalid IPv4 literal.

- [x] **Step: Tests** set `NIGHTSTALKER_ALLOWED_IPS=999` → expect error; valid paths defaulting when workspace set.

- [x] **Run:** `go test ./internal/config/... -count=1`

### Task 3: `internal/telemetry`

**Files:**
- Create: `internal/telemetry/telemetry.go`
- Create: `internal/telemetry/telemetry_test.go`

Implement `AppendJSONL(path, record)` and `WriteSummary(path, summary)` with structs tagged `json:"..."`. Summary includes `version`, `exec_events`, `tcp_events`, `policy_counts` map.

- [x] **Run:** `go test ./internal/telemetry/... -count=1`

---

## Sprint 3 — Report table + agent wiring

### Task 4: Detect Markdown column

**Files:**
- Modify: `internal/report/detect.go`
- Modify: `internal/report/detect_test.go`

Add **Policy** column to preamble and `FormatDetectExecRow` (cell `—`), `FormatDetectTCPRow(..., policyDisplay string)`.

- [x] **Run:** `go test ./internal/report/... -count=1`

### Task 5: Agent

**Files:**
- Modify: `internal/agent/agent_linux.go`

- Initialize `slog` from `cfg.LogLevel` (default `info`).
- Build `*policy.Policy` from config (nil if parse skipped when both strings empty).
- Mutex-protected counters per class + exec/tcp totals.
- After exec BPF attached and `execRd` created, write `AgentStatusPath` JSON `{"ok":true,"pid":<optional>}`.
- In `readConnectRing`: `cl := pol.Classify(fqdn, ip)`; `AppendJSONL` tcp event; `FormatDetectTCPRow` with `cl.Display()`.
- On `Run` return (all goroutines done), `WriteSummary` to `TelemetrySummaryPath`.
- Use same mutex as detect append for JSONL or a dedicated `telemetryMu`.

- [x] **Run:** `go test ./internal/agent/... -count=1 -tags=!integration`
- [x] **Linux root (optional):** `go test ./internal/agent/... -tags=integration -count=1 -timeout=120s`

---

## Sprint 4 — Composite Action (Node)

### Task 6: `action.yml` + TypeScript

**Files:**
- Modify: `action.yml`
- Modify: `src/main.ts`
- Modify: `src/post.ts`

Inputs (defaults match brainstorm): `allowed-hosts`, `allowed-ips`, `fail-on-error` default `false`, `log-level` default `info`, `report-job-summary` default `true`.

`main.ts`: map to `NIGHTSTALKER_ALLOWED_HOSTS`, etc.; set `NIGHTSTALKER_AGENT_STATUS` to `join(workspace,'.nightstalker-ready.json')`; if `fail-on-error` true, after `spawn` poll up to 60s for ready JSON with `ok===true`, else `core.setFailed`.

`post.ts`: if `fail-on-error` and (missing ready or `ok!==true`) → `setFailed`; if `report-job-summary` false → skip appending detect body to `GITHUB_STEP_SUMMARY` (still SIGTERM agent, unlink/cleanup as today).

- [x] **Build:** `npm ci && npm run typecheck && npm run build`
- [x] **Commit** `dist/` if repo tracks it

---

## Sprint 5 — Docs & nightstalker-demo

### Task 7: README + AGENTS

Document new inputs, artifact filenames, operational `fail-on-error` vs future policy-fail; UTF-8 reminder for YAML.

### Task 8: nightstalker-demo

Keep capped egress; optionally `allowed-hosts` including `google.com`, `github.com`, `microsoft.com` and `grep` for `allowed` in Policy column (or JSONL) — **without** breaking minimal-connect smoke assumptions.

---

## Self-review (spec coverage)

| Requirement | Task |
|-------------|------|
| allowed-hosts / allowed-ips | Sprint 1–2 |
| operational fail-on-error | Sprint 4 (main wait + post check) |
| log-level + logs | Sprint 3 (slog) |
| report-job-summary | Sprint 4 post |
| Markdown + JSONL + summary JSON | Sprint 2–3 |
| No SaaS / no vendored third-party guard code | By design |
| No fail-on egress violation v1 | Omitted on purpose; note in README/AGENTS phase 2 |

---

**Plan complete and saved to `docs/superpowers/plans/2026-04-09-nightstalker-egress-telemetry-v1.md`. Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — run tasks in this session with checkpoints  

*This session continues with inline implementation and `go test` / `npm run` verification.*
