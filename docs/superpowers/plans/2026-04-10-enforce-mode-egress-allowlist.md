# Enforce-Mode Egress Allowlist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `mode=enforce` that blocks non-allowlisted TCP/UDP egress in-kernel, fails fast on first deny, and reports denied actions in JSONL and Job Summary.

**Repository state (2026-04-11):** Enforce mode, deny JSONL, digest enforcement section, bounded deny-ring draining, and nightstalker-demo **`guard-enforce`** paths are **on `main`**.

**Architecture:** Keep detect-mode pipeline intact and add an enforce policy path with verdict-capable BPF hooks plus userspace allowlist compilation (domains -> IP set). In enforce mode, hook attach/policy load failures are hard failures. Deny events are emitted and surfaced before process exit.

**Tech Stack:** Go (`internal/config`, `internal/policy`, `internal/agent`, `internal/report`, `internal/telemetry`), eBPF C (`bpf/*`), bpf2go (`internal/bpf/*`), GitHub Actions (`.github/workflows/nightstalker-demo.yml`).

---

## File map

| File | Responsibility |
|------|----------------|
| `action.yml` | Add/describe `mode` and allowlist inputs |
| `README.md` | Document enforce semantics, fail-fast, deny reporting |
| `internal/config/config.go` | Parse/validate mode + allowlist inputs |
| `internal/policy/*` | Domain allowlist normalization, compile, and lookup helpers |
| `bpf/trace_connect.bpf.c` (or new enforce BPF C file) | Verdict path for TCP/UDP allow/deny |
| `internal/bpf/traceconnect/gen.go` (or new bpf package) | bpf2go generation target |
| `internal/agent/agent_linux.go` | Load enforce maps/hooks, fail-fast deny handling, emit deny events |
| `internal/telemetry/event.go` | Add deny event JSON type (additive) |
| `internal/report/digest.go` | Add enforcement section and denied action summary |
| `.github/workflows/nightstalker-demo.yml` | Add enforce scenario with real traffic + deny assertions |

---

### Task 1: Config and input contract (TDD)

**Files:**
- Modify: `action.yml`
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go` (create if missing)

- [x] **Step 1: Write failing tests for mode + allowlist parsing**

Add tests for:
- default mode = `detect`
- invalid mode rejected
- `enforce` without allowlist rejected
- allowlist normalization (trim, lowercase, dedupe)

- [x] **Step 2: Run targeted config tests to verify failure**

Run: `go test ./internal/config -count=1`  
Expected: FAIL before implementation.

- [x] **Step 3: Implement mode/input parsing and validation**

Add config fields:
- `Mode string` (`detect|enforce`)
- `AllowedDomains []string`

Validation rules:
- mode must be detect or enforce
- in enforce mode, allowlist must be non-empty

- [x] **Step 4: Update action input schema docs**

In `action.yml`, add `mode` and `allowed-domains` with defaults and descriptions matching behavior.

- [x] **Step 5: Re-run config tests**

Run: `go test ./internal/config -count=1`  
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add action.yml internal/config/config.go internal/config/*_test.go
git commit -m "feat(config): add detect/enforce mode and allowlist inputs"
```

---

### Task 2: Policy compiler for allowlist domains

**Files:**
- Modify/Create: `internal/policy/allowlist.go`
- Test: `internal/policy/allowlist_test.go`

- [x] **Step 1: Write failing tests for allowlist compile behavior**

Cover:
- canonical domain normalization
- duplicate removal
- unresolved domain handling contract for enforce mode
- IP membership lookup helper behavior

- [x] **Step 2: Run policy tests and verify failure**

Run: `go test ./internal/policy -count=1`  
Expected: FAIL before implementation.

- [x] **Step 3: Implement allowlist compiler**

Add helper(s):
- parse/normalize domains
- resolve to IPv4 set with bounded retries
- return compile result (ip set + unresolved domains)

- [x] **Step 4: Re-run policy tests**

Run: `go test ./internal/policy -count=1`  
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/policy/allowlist.go internal/policy/allowlist_test.go
git commit -m "feat(policy): compile domain allowlist to ip set"
```

---

### Task 3: Telemetry and report schema extensions for deny events

**Files:**
- Modify: `internal/telemetry/event.go`
- Modify/Test: `internal/telemetry/event_test.go`
- Modify: `internal/report/digest.go`
- Modify/Test: `internal/report/digest_test.go`

- [x] **Step 1: Write failing tests for deny event JSON and report section**

Add tests for:
- deny event JSON marshal shape
- report includes enforcement mode and denied summary

- [x] **Step 2: Run telemetry/report tests to verify failure**

Run:

```bash
go test ./internal/telemetry ./internal/report -count=1
```

Expected: FAIL before implementation.

- [x] **Step 3: Implement additive deny event type and digest inputs**

Add new event struct:
- `DenyEvent` with protocol, dst, dport, reason, mode, pid/tid/comm, ts/seq

Add digest inputs for enforcement section:
- mode
- allowlist size
- deny count
- first deny details

- [x] **Step 4: Re-run telemetry/report tests**

Run:

```bash
go test ./internal/telemetry ./internal/report -count=1
```

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/telemetry/event.go internal/telemetry/event_test.go internal/report/digest.go internal/report/digest_test.go
git commit -m "feat(telemetry): add deny events and enforcement report section"
```

---

### Task 4: eBPF enforcement hook path for TCP/UDP denies

**Files:**
- Modify/Create: `bpf/trace_connect.bpf.c` or separate enforce C file
- Modify: `internal/bpf/traceconnect/gen.go` (or new gen target)
- Verify: generated loaders via `go generate`

- [x] **Step 1: Write/adjust decode tests first if wire structs change**

Update `internal/agent/decode_network_linux_test.go` for any new deny sample layout.

- [x] **Step 2: Implement BPF allow/deny verdict logic**

Requirements:
- check destination IP against allowlist map
- allow if listed
- deny if not listed
- emit deny record metadata for userspace reporting

- [x] **Step 3: Regenerate BPF loaders**

Run:

```bash
go generate ./internal/bpf/traceconnect/...
```

Expected: PASS without clang warnings/errors.

- [x] **Step 4: Run decode tests**

Run: `go test ./internal/agent -run Decode -count=1`  
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add bpf/trace_connect.bpf.c internal/bpf/traceconnect/gen.go internal/agent/decode_network_linux_test.go
git commit -m "feat(bpf): add tcp/udp enforcement verdict path with deny metadata"
```

---

### Task 5: Agent enforce-mode runtime and fail-fast behavior

**Files:**
- Modify: `internal/agent/agent_linux.go`
- Modify/Test: `internal/agent/*_test.go`
- Modify/Test: `internal/agent/agent_integration_test.go` (Linux/root integration)

- [x] **Step 1: Write failing tests for enforce fail-fast behavior**

Add tests for:
- enforce mode start failure when allowlist invalid/empty
- deny event emission + immediate non-zero exit
- detect mode unchanged

- [x] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/agent -count=1
```

Expected: FAIL before implementation.

- [x] **Step 3: Implement enforce runtime path**

In `Run()`:
- compile/load allowlist map in enforce mode
- require enforcement hook attach success
- on first deny: write deny JSONL + update report state + return error immediately

Keep detect path behavior unchanged.

- [x] **Step 4: Re-run agent tests**

Run:

```bash
go test ./internal/agent -count=1
```

Expected: PASS on Linux-compatible environment.

- [x] **Step 5: Add/Run integration test for real block behavior**

Run:

```bash
sudo go test -tags=integration ./internal/agent/... -count=1 -run Enforce
```

Expected: PASS on ubuntu-latest/root.

- [x] **Step 6: Commit**

```bash
git add internal/agent/agent_linux.go internal/agent/*_test.go internal/agent/agent_integration_test.go
git commit -m "feat(agent): enforce allowlist with fail-fast deny handling"
```

---

### Task 6: nightstalker-demo enforce scenario with real traffic and deny assertions

**Files:**
- Modify: `.github/workflows/nightstalker-demo.yml`

- [x] **Step 1: Add enforce-mode workflow path**

Add a scenario with:
- real TCP/UDP attempts to allowlisted destination(s) -> expected success
- real TCP/UDP attempts to non-allowlisted destination(s) -> expected deny/fail-fast

- [x] **Step 2: Add assertions for deny evidence**

Assert:
- action exits non-zero in enforce scenario
- JSONL contains deny event(s)
- deny event contains expected protocol + dst + reason
- summary includes enforcement section and deny details

- [x] **Step 3: Keep detect scenario intact**

Ensure existing detect nightstalker-demo checks remain and still run independently.

- [x] **Step 4: Run encoding guard**

Run: `python scripts/assert_utf8_text.py`  
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add .github/workflows/nightstalker-demo.yml
git commit -m "ci(nightstalker-demo): add enforce-mode real traffic and deny assertions"
```

---

### Task 7: Final verification + docs alignment

**Files:**
- Modify: `README.md`
- Verify all touched packages

- [x] **Step 1: Update README enforce-mode section**

Document:
- mode behavior
- allowlist input usage
- fail-fast deny semantics
- HTTPS/status limitations

- [x] **Step 2: Run package tests**

Run:

```bash
go test ./internal/config ./internal/policy ./internal/telemetry ./internal/report ./internal/agent -count=1
```

Expected: PASS in Linux environment.

- [x] **Step 3: Run CI-like Linux script**

Run: `bash scripts/docker-ubuntu-test.sh`  
Expected: PASS for generate/format/vet/staticcheck/test/build.

- [x] **Step 4: Run integration gate where available**

Run: `NIGHTSTALKER_INTEGRATION=1 bash scripts/docker-ubuntu-test.sh`  
Expected: PASS on privileged Linux with tracing support.

- [x] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: document enforce mode allowlist and deny reporting"
```

---

## Self-review

**1. Spec coverage**
- Mode semantics and strict enforce behavior: Tasks 1, 5
- Allowlist compiler: Task 2
- Deny reporting JSONL/summary: Task 3
- BPF enforcement hook path: Task 4
- Real-world nightstalker-demo enforce validation: Task 6
- Docs + end-to-end validation: Task 7

**2. Placeholder scan**
- No TODO/TBD placeholders; each task has explicit files, commands, and expected outcomes.

**3. Type consistency**
- Additive event/report fields; existing detect telemetry preserved.
- Plan keeps schema compatibility by adding deny events rather than mutating existing types.
