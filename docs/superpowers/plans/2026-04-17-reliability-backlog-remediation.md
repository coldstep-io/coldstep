# Reliability backlog remediation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close remaining test and CI gaps from `knowledge/reports/2026-04-17-reliability-code-review-findings.md` (Tracks B partials, C-SR-05 hygiene, CI race coverage) without changing production behavior unless a test proves a bug.

**Architecture:** Add focused unit tests for pure Go helpers (`preferRunError`, `loadIgnoredLPMMap` edge cases), extend Python unittest coverage for deterministic diff output, and add a GitHub Actions step running `go test -race` on agent packages. Optional BPF fault-injection stays out of scope unless a later task proves need for refactor hooks.

**Tech Stack:** Go 1.24.x, Python 3.12 unittest, GitHub Actions `ubuntu-latest`, Docker for local verification per `AGENTS.md`.

**Note:** Root `docs/` may be gitignored on this clone; copy the plan into a tracked path if your team publishes plans.

---

## File map

| Path | Role |
|------|------|
| `internal/agent/agent_linux.go` | Contains `preferRunError`, `loadIgnoredLPMMap`, `newEnforceDenyError`, `readDenyRing` (reference only). |
| `internal/agent/prefer_run_error_test.go` | **Create** — table tests for error precedence (`//go:build linux`). |
| `internal/agent/load_ignored_lpm_test.go` | **Create** — `loadIgnoredLPMMap` policy/error contract tests (`//go:build linux`). |
| `scripts/test_ci_coldstep_jsonl_traffic_diff.py` | **Modify** — golden ordering test for `multiset_diff`. |
| `.github/workflows/coldstep-ci-runner.yml` | **Modify** — add `-race` step after unit tests on `integration` or `unit` job (see Task 3). |

---

### Task 1: `preferRunError` precedence (B-SR-02 unit slice)

**Files:**
- Create: `internal/agent/prefer_run_error_test.go`
- Reference: `internal/agent/agent_linux.go` (`preferRunError` ~L1643–1654, `newEnforceDenyError` ~L222–230)

- [ ] **Step 1: Add failing tests**

Create `internal/agent/prefer_run_error_test.go`:

```go
//go:build linux

package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func TestPreferRunError_Precedence(t *testing.T) {
	cancelErr := context.Canceled
	plain := errors.New("plain operational")
	denyTCP := newEnforceDenyError(telemetry.DenyEvent{Protocol: "tcp", Dst: "1.2.3.4", Dport: 443})
	denyUDP := newEnforceDenyError(telemetry.DenyEvent{Protocol: "udp", Dst: "8.8.8.8", Dport: 53})

	tests := []struct {
		name    string
		current error
		cand    error
		want    error
	}{
		{"nil current takes candidate", nil, plain, plain},
		{"suppress canceled candidate", plain, cancelErr, plain},
		{"enforce deny replaces plain", plain, denyTCP, denyTCP},
		{"keep plain when current is deny", denyTCP, plain, denyTCP},
		{"deny replaces deny (first wins)", denyTCP, denyUDP, denyTCP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := preferRunError(tt.current, tt.cand)
			if got != tt.want && !sameErrorIdentity(got, tt.want) {
				t.Fatalf("preferRunError(%v, %v) = %v want %v", tt.current, tt.cand, got, tt.want)
			}
		})
	}
}

func sameErrorIdentity(a, b error) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Error() == b.Error()
}
```

If `preferRunError` prefers the **second** deny when both are enforce-deny, adjust **`want`** to match actual `preferRunError` semantics (read `agent_linux.go` — current code keeps `current` when both are deny). The table above matches: `deny replaces deny (first wins)` expects `denyTCP`.

- [ ] **Step 2: Run test on Linux**

Run (Docker per project policy):

```bash
docker run --rm -v "${PWD}:/src" -w /src golang:1.24-bookworm go test ./internal/agent -run TestPreferRunError_Precedence -count=1 -v
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/agent/prefer_run_error_test.go
git commit -m "test(agent): cover preferRunError precedence for enforce deny vs cancel"
```

---

### Task 2: `loadIgnoredLPMMap` error contracts (B-SR-04)

**Files:**
- Create: `internal/agent/load_ignored_lpm_test.go`
- Reference: `internal/agent/agent_linux.go` (`loadIgnoredLPMMap` ~L1381–1418)

**Important:** Function order is `len(nets)==0` → `m==nil` → `len(nets)>Max`. With **nil map** and **Max+1 nets**, the **nil-map error wins**, not `exceeds max`. Testing the **exceeds max** branch requires a **non-nil** `*ebpf.Map` (integration/BPF context).

- [ ] **Step 1: Write unit tests (no map)**

Create `internal/agent/load_ignored_lpm_test.go`:

```go
//go:build linux

package agent

import (
	"net"
	"strings"
	"testing"
)

func TestLoadIgnoredLPMMap_NilMapWithNetsReturnsWrappedError(t *testing.T) {
	_, n, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	err = loadIgnoredLPMMap(nil, []*net.IPNet{n})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "ignored_ipv4_lpm map is nil") {
		t.Fatalf("wrong message: %v", err)
	}
}

func TestLoadIgnoredLPMMap_EmptyNetsNoError(t *testing.T) {
	if err := loadIgnoredLPMMap(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := loadIgnoredLPMMap(nil, []*net.IPNet{}); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2 (optional): Integration — max-CIDR branch**

Only if you need full **B-SR-04** coverage: in `agent_integration_test.go`, after BPF objects load, obtain `IgnoredIpv4Lpm` from `traceenforce`, build `MaxIgnoredIPv4Nets+1` distinct `/32` nets under `10.0.0.0/8`, call `loadIgnoredLPMMap(map, nets)`, assert error contains `exceeds max`. Root + CI only.

- [ ] **Step 3: Docker test**

```bash
docker run --rm -v "${PWD}:/src" -w /src golang:1.24-bookworm go test ./internal/agent -run TestLoadIgnoredLPMMap -count=1 -v
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/agent/load_ignored_lpm_test.go
git commit -m "test(agent): loadIgnoredLPMMap nil-map and empty-net contracts (B-SR-04)"
```

---

### Task 3: Race detector CI step (B-SR-02)

**Files:**
- Modify: `.github/workflows/coldstep-ci-runner.yml` (job `unit` after `Unit tests`)

- [ ] **Step 1: Insert step**

After `- name: Unit tests` / `run: go test ./...`, add:

```yaml
      - name: Race detector (Go agent)
        run: go test -race -count=1 ./internal/agent/... -timeout 15m
```

Use **integration** job instead if unit job must stay under time budget — prefer **`unit`** job to catch races without sudo.

- [ ] **Step 2: Validate YAML**

Open PR or run `actionlint` if installed locally.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/coldstep-ci-runner.yml
git commit -m "ci: run go test -race on internal/agent (B-SR-02)"
```

Expected CI: `race` leg passes on `ubuntu-latest` (pure Go + ebpf should link).

---

### Task 4: Multiset diff golden stability (C-SR-05)

**Files:**
- Modify: `scripts/test_ci_coldstep_jsonl_traffic_diff.py`

- [ ] **Step 1: Add test**

Append to `DiffScriptTests`:

```python
    def test_multiset_diff_ordering_deterministic(self):
        # prev={a:1,b:2} curr={b:3,c:1} => new c, gone a, chg b (2->3)
        prev = collections.Counter({"b": 2, "a": 1})
        curr = collections.Counter({"b": 3, "c": 1})
        new, gone, chg = MOD.multiset_diff(prev, curr)
        self.assertEqual([(1, "c")], new)
        self.assertEqual([(1, "a")], gone)
        self.assertEqual([(2, 3, "b")], chg)
```

Add `import collections` at top if missing (file may already import it — if so, omit duplicate import).

- [ ] **Step 2: Run**

```bash
docker run --rm -v "${PWD}:/src" -w /src python:3.12-slim python3 -m unittest scripts/test_ci_coldstep_jsonl_traffic_diff.py -v
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add scripts/test_ci_coldstep_jsonl_traffic_diff.py
git commit -m "test(diff): multiset_diff deterministic ordering regression"
```

---

### Task 5 (optional / defer): BPF optional map fault injection (B-SR-03)

**Scope:** Prove TLS/FS `Update` failures stay warn-only and surface in digest capabilities — requires loaded `traceconnect`/`tracefs` objects or refactor to inject `mapUpdateFn`. **Defer** until product demands stronger guarantees.

**Minimal defer note:** No code in this plan; track as future issue referencing `#finding-b-sr-03`.

---

## Self-review

**1. Spec coverage**

| Report ID | Addressed by task |
|-----------|-------------------|
| B-SR-02 precedence | Task 1 + Task 3 |
| B-SR-04 ignored-LPM diagnostics | Task 2 (partial — nil map path) |
| C-SR-05 multiset determinism | Task 4 |
| B-SR-03 | Task 5 defer |

**Gap:** Max-CIDR branch of `loadIgnoredLPMMap` needs real map — optional integration follow-up.

**2. Placeholder scan:** No TBD/FIXME in executable steps.

**3. Type consistency:** `preferRunError` / `telemetry.DenyEvent` fields match existing types.

---

## Execution handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-17-reliability-backlog-remediation.md`.**

**Execution options:**

1. **Subagent-driven (recommended)** — Dispatch `Task` subagent_type `generalPurpose` or `subagent-driven-development` per task; review after Tasks 1–2 before CI YAML.

2. **Inline execution** — Run Tasks 1 → 4 sequentially in one session with Docker verification between commits.

**Which approach do you want?**
