# Full Review Issue Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the high/medium review findings by hardening DNS decompression safety, fixing HTTP IPv6 host parsing, making workflow tool dependencies explicit, and adding regression tests for each path.

**Architecture:** Keep existing runtime behavior and interfaces, but add strict parser guardrails and deterministic dependency setup. Implement each fix with a test-first approach in the nearest existing test file to avoid unnecessary refactors. Validate in Docker for reproducibility.

**Tech Stack:** Go (`testing`), Python/CI shell in GitHub Actions workflows, Dockerized verification.

---

## File Structure / Responsibility Map

- **DNS parser safety**
  - Modify: `internal/agent/dns_wire.go`
    - Add cycle-safe DNS name decompression logic with shared recursion budget/visited pointer tracking.
  - Modify: `internal/agent/dns_wire_test.go`
    - Add malformed packet regression tests (pointer loop, deep pointer chain).

- **HTTP Host parser correctness**
  - Modify: `internal/telemetry/parsehttp.go`
    - Correct Host extraction for bracketed IPv6 literals and optional ports.
  - Modify: `internal/telemetry/parsehttp_test.go`
    - Add IPv6 host parsing tests and malformed bracket edge-case tests.

- **Workflow tool dependency reliability**
  - Modify: `.github/workflows/coldstep-demo.yml`
  - Modify: `.github/workflows/coldstep-demo-enforce.yml`
  - Modify: `.github/workflows/coldstep-demo-detect.yml` (if needed for consistency/preflight)
  - Modify: `.github/workflows/coldstep-ci-runner.yml`
    - Ensure `dig`/`nc` are explicitly installed where used.
    - Add preflight command checks before usage.

- **Review/report closure**
  - Modify: `knowledge/reports/2026-04-17-reliability-code-review-findings.md`
    - Add verification notes for newly addressed review findings.

---

### Task 1: Harden DNS Name Decompression Against Pointer Loops

**Files:**
- Modify: `internal/agent/dns_wire.go`
- Test: `internal/agent/dns_wire_test.go`

- [ ] **Step 1: Write failing DNS pointer-loop test**

```go
func TestReadDNSName_PointerLoopReturnsFalse(t *testing.T) {
	// Header + name at offset 12 pointing to itself (0xC00C)
	packet := make([]byte, 16)
	packet[12] = 0xC0
	packet[13] = 0x0C

	_, _, ok := readDNSName(packet, 12)
	if ok {
		t.Fatal("expected pointer loop to fail safely")
	}
}
```

- [ ] **Step 2: Write failing deep-pointer-chain budget test**

```go
func TestReadDNSName_DeepPointerChainFailsBudget(t *testing.T) {
	packet := make([]byte, 128)
	// Build chain: 12 -> 14 -> 16 -> ...
	for off := 12; off < 100; off += 2 {
		packet[off] = 0xC0
		packet[off+1] = byte(off + 2)
	}
	// terminate far away with root label
	packet[102] = 0

	_, _, ok := readDNSName(packet, 12)
	if ok {
		t.Fatal("expected deep pointer chain to fail budget")
	}
}
```

- [ ] **Step 3: Run DNS tests to confirm failure**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./internal/agent -run "TestReadDNSName_(PointerLoopReturnsFalse|DeepPointerChainFailsBudget)" -v`  
Expected: FAIL (current implementation does not enforce global pointer loop/budget safety).

- [ ] **Step 4: Implement minimal safe decompression helper**

```go
func readDNSName(packet []byte, offset int) (string, int, bool) {
	visited := make(map[int]struct{}, 8)
	return readDNSNameSafe(packet, offset, visited, 0)
}

func readDNSNameSafe(packet []byte, offset int, visited map[int]struct{}, depth int) (string, int, bool) {
	const maxDepth = 32
	if depth > maxDepth {
		return "", 0, false
	}

	var labels []string
	for {
		if offset >= len(packet) {
			return "", 0, false
		}
		b := int(packet[offset])
		offset++
		if b == 0 {
			return joinDNSLabels(labels), offset, true
		}
		if b&0xC0 == 0xC0 {
			if offset >= len(packet) {
				return "", 0, false
			}
			ptr := (b&0x3F)<<8 | int(packet[offset])
			offset++
			if _, seen := visited[ptr]; seen {
				return "", 0, false
			}
			visited[ptr] = struct{}{}
			suffix, _, ok := readDNSNameSafe(packet, ptr, visited, depth+1)
			if !ok {
				return "", 0, false
			}
			if len(labels) == 0 {
				return suffix, offset, true
			}
			return joinDNSLabels(labels) + "." + suffix, offset, true
		}
		if b > 63 || offset+b > len(packet) {
			return "", 0, false
		}
		labels = append(labels, string(packet[offset:offset+b]))
		offset += b
	}
}
```

- [ ] **Step 5: Run targeted DNS tests**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./internal/agent -run "TestReadDNSName_(PointerLoopReturnsFalse|DeepPointerChainFailsBudget)" -v`  
Expected: PASS.

- [ ] **Step 6: Run full agent tests**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./internal/agent`  
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/agent/dns_wire.go internal/agent/dns_wire_test.go
git commit -m "fix(agent): prevent DNS compression pointer recursion loops"
```

---

### Task 2: Fix HTTP Host Parsing for Bracketed IPv6 Literals

**Files:**
- Modify: `internal/telemetry/parsehttp.go`
- Test: `internal/telemetry/parsehttp_test.go`

- [ ] **Step 1: Add failing tests for IPv6 Host header parsing**

```go
func TestParseHTTPRequestPrefix_IPv6HostWithPort(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n")
	_, host, _, ok := ParseHTTPRequestPrefix(raw)
	if !ok {
		t.Fatal("expected parse success")
	}
	if host != "2001:db8::1" {
		t.Fatalf("host=%q want %q", host, "2001:db8::1")
	}
}

func TestParseHTTPRequestPrefix_IPv6HostNoPort(t *testing.T) {
	raw := []byte("GET /health HTTP/1.1\r\nHost: [2001:db8::2]\r\n\r\n")
	_, host, _, ok := ParseHTTPRequestPrefix(raw)
	if !ok {
		t.Fatal("expected parse success")
	}
	if host != "2001:db8::2" {
		t.Fatalf("host=%q want %q", host, "2001:db8::2")
	}
}
```

- [ ] **Step 2: Run telemetry parser tests to confirm failure**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./internal/telemetry -run "TestParseHTTPRequestPrefix_IPv6Host" -v`  
Expected: FAIL (current parser trims at first `:`).

- [ ] **Step 3: Implement bracket-aware host normalization**

```go
func normalizeHostHeader(val string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return "?"
	}
	if strings.HasPrefix(val, "[") {
		end := strings.IndexByte(val, ']')
		if end > 1 {
			return val[1:end]
		}
		return "?"
	}
	if i := strings.IndexByte(val, ':'); i >= 0 {
		return val[:i]
	}
	return val
}
```

And replace existing host trim logic in `ParseHTTPRequestPrefix`:

```go
if name == "host" && val != "" {
	host = normalizeHostHeader(val)
	break
}
```

- [ ] **Step 4: Run telemetry tests**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./internal/telemetry`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/telemetry/parsehttp.go internal/telemetry/parsehttp_test.go
git commit -m "fix(telemetry): parse bracketed IPv6 Host headers correctly"
```

---

### Task 3: Make Workflow Tool Dependencies Explicit (`dig`, `nc`)

**Files:**
- Modify: `.github/workflows/coldstep-demo.yml`
- Modify: `.github/workflows/coldstep-demo-enforce.yml`
- Modify: `.github/workflows/coldstep-ci-runner.yml`

- [ ] **Step 1: Add explicit installs where commands are used**

Use consistent install block in relevant jobs:

```yaml
- name: Install runtime probes
  run: |
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nmap dnsutils netcat-openbsd curl
```

- [ ] **Step 2: Add preflight checks before first use**

```yaml
- name: Assert required tools are present
  run: |
    command -v dig
    command -v nc
    command -v nmap
```

- [ ] **Step 3: Validate workflow YAML syntax quickly**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace python:3.12-slim python - <<'PY'\nimport yaml,glob\nfor p in glob.glob('.github/workflows/*.yml'):\n    yaml.safe_load(open(p,encoding='utf-8'))\nprint('ok')\nPY`  
Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/coldstep-demo.yml .github/workflows/coldstep-demo-enforce.yml .github/workflows/coldstep-ci-runner.yml
git commit -m "fix(ci): install and preflight dig/nc dependencies explicitly"
```

---

### Task 4: Add Production-Path Deny-Ring Robustness Regression

**Files:**
- Modify: `internal/agent/agent_linux_test.go`

- [ ] **Step 1: Add malformed deny raw sample test around production helper path**

```go
func TestAppendDenyFromRaw_InvalidPayload(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Mode: config.ModeEnforce}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newEnforcementState()

	_, err := appendDenyFromRaw(cfg, []byte{0x01}, &seq, &jsonlMu, state)
	if err == nil {
		t.Fatal("expected decode error")
	}
}
```

- [ ] **Step 2: Add JSONL write failure test for deny append**

```go
func TestAppendDenyFromRaw_JSONLWriteFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Mode: config.ModeEnforce, EventsLogPath: blocked}
	var seq telemetry.SeqGen
	var jsonlMu sync.Mutex
	state := newEnforcementState()

	raw := make([]byte, denyEventWireSize)
	binary.LittleEndian.PutUint32(raw[0:4], 1)
	binary.LittleEndian.PutUint32(raw[4:8], 1)
	raw[24] = denyProtoTCP
	raw[25] = denyReasonDstNotAllowlisted
	copy(raw[28:32], net.ParseIP("1.1.1.1").To4())
	binary.BigEndian.PutUint16(raw[32:34], 443)

	_, err := appendDenyFromRaw(cfg, raw, &seq, &jsonlMu, state)
	if err == nil {
		t.Fatal("expected append deny jsonl error")
	}
}
```

- [ ] **Step 3: Run targeted and full agent tests**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./internal/agent -run "TestAppendDenyFromRaw_(InvalidPayload|JSONLWriteFailure)" -v`  
Expected: PASS.  

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./internal/agent`  
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/agent/agent_linux_test.go
git commit -m "test(agent): add deny ring malformed payload and jsonl failure coverage"
```

---

### Task 5: Verify End-to-End and Update Reliability Report

**Files:**
- Modify: `knowledge/reports/2026-04-17-reliability-code-review-findings.md`

- [ ] **Step 1: Run full Go suite in Docker**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./...`  
Expected: PASS.

- [ ] **Step 2: Run script tests in Docker**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace python:3.12-slim python -m unittest scripts/test_ci_coldstep_jsonl_traffic_diff.py`  
Expected: PASS.

- [ ] **Step 3: Update report verification evidence block**

Append/update evidence section with exact commands and outcomes:

```markdown
### 2026-04-17 follow-up verification

- `go test ./...` (Docker `golang:1.24-bookworm`) — PASS
- `python -m unittest scripts/test_ci_coldstep_jsonl_traffic_diff.py` (Docker `python:3.12-slim`) — PASS
- Added regression coverage:
  - DNS compression pointer loop safety
  - HTTP bracketed IPv6 Host parsing
  - deny append malformed payload/write failure
  - workflow tool dependency preflight (`dig`/`nc`)
```

- [ ] **Step 4: Commit**

```bash
git add knowledge/reports/2026-04-17-reliability-code-review-findings.md
git commit -m "docs(reliability): record follow-up verification and regression coverage"
```

---

## Self-Review Checklist

- **Spec coverage:** All reported issues are covered:
  - DNS recursion safety (Task 1)
  - IPv6 Host parsing (Task 2)
  - workflow `dig`/`nc` dependency drift (Task 3)
  - missing deny-path robustness tests (Task 4)
  - verification/report closure (Task 5)
- **Placeholder scan:** No `TODO/TBD/implement later` placeholders remain.
- **Type consistency:** Function/test names and paths match existing conventions and referenced files.

Plan complete and saved to `docs/superpowers/plans/2026-04-17-full-review-issue-remediation.md`. Two execution options:

1. Subagent-Driven (recommended) - I dispatch a fresh subagent per task, review between tasks, fast iteration
2. Inline Execution - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
