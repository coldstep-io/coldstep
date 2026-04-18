# UDP/HTTP Capture + Empty-State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure UDP/HTTP capture is reliable for real nightstalker-demo traffic and make digest sections explicitly explain why rows are empty.

**Repository state (2026-04-11):** UDP/HTTP BPF + decode paths, digest reason rows, and nightstalker-demo assertions are **on `main`**. This plan is **complete** from a product standpoint.

**Architecture:** Keep the existing `raw_tp/sys_enter` egress path, but harden the BPF capture logic and add userspace digest-state metadata for UDP/HTTP section rendering. Preserve detect-only behavior and JSONL schema while improving confidence through unit tests and nightstalker-demo assertions aligned with real traffic paths.

**Tech Stack:** eBPF C (`trace_connect.bpf.c`), Go (`internal/agent`, `internal/report`, `internal/telemetry`), GitHub Actions nightstalker-demo workflow.

---

## File map

| File | Responsibility |
|------|----------------|
| `bpf/trace_connect.bpf.c` | Improve UDP/HTTP syscall capture behavior and filtering robustness |
| `internal/agent/agent_linux.go` | Track UDP/HTTP reader status and pass section-state metadata to digest |
| `internal/report/digest.go` | Render explicit UDP/HTTP empty-state reason rows |
| `internal/report/digest_test.go` | Validate empty-state reason rendering and precedence |
| `internal/agent/decode_network_linux_test.go` | Keep struct decode parity checks for BPF samples |
| `.github/workflows/nightstalker-demo.yml` | Keep positive-path UDP/HTTP assertions and prevent ambiguous empty-state regressions |

---

### Task 1: BPF capture hardening for UDP/HTTP

**Files:**
- Modify: `bpf/trace_connect.bpf.c`
- Test: `internal/agent/decode_network_linux_test.go`

- [x] **Step 1: Write failing decode-shape test for any wire-layout change (if needed)**

If `struct udp_send_event` or `struct http_sniff_event` layout is touched, update/add a wire-size test first.

```go
func TestDecodeHTTPSniffEvent_tooShort(t *testing.T) {
	_, _, _, _, _, _, ok := decodeHTTPSniffEvent(make([]byte, 100))
	if ok {
		t.Fatal("expected false")
	}
}
```

- [x] **Step 2: Run targeted decode test to verify baseline**

Run: `go test ./internal/agent -run TestDecodeHTTP -count=1`  
Expected: PASS (or FAIL only if layout changed and tests need update first).

- [x] **Step 3: Implement minimal BPF hardening in `trace_connect.bpf.c`**

Apply focused updates:

```c
/* keep existing sendto path */
if (id == (long)NIGHTSTALKER_NR_SENDTO) {
    /* existing pointer reads ... */
    if (!addr_ul)
        return 0; /* explicit known limitation retained for phase-1 */
    if (read_ipv4_sockaddr(addr_ul, &sin_port, &sin_addr))
        return 0;

    /* unchanged UDP ring submit */

    if (sin_port == bpf_htons(80) && len >= 4 &&
        http_prefix_looks_like_request((void *)buf_ptr, len)) {
        /* unchanged HTTP ring submit */
    }
}
```

Notes for this step:
- Keep verifier-friendly style (`bpf_probe_read_user`, bounded caps, fixed-size ring structs).
- Do not add TLS parsing or IPv6 here.
- If broadening beyond `sendto` is attempted, do it in a separate commit with dedicated tests.

- [x] **Step 4: Regenerate BPF loaders**

Run: `go generate ./internal/bpf/traceconnect/...`  
Expected: no clang/verifier build errors.

- [x] **Step 5: Run decode tests**

Run: `go test ./internal/agent -run TestDecode -count=1`  
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add bpf/trace_connect.bpf.c internal/agent/decode_network_linux_test.go
git commit -m "feat(bpf): harden udp/http capture path for nightstalker-demo traffic"
```

---

### Task 2: Add UDP/HTTP section-state metadata in agent runtime

**Files:**
- Modify: `internal/agent/agent_linux.go`
- Test: `internal/agent/*_test.go` (new targeted unit tests if needed)

- [x] **Step 1: Write failing test for digest input state mapping**

Add a unit test that validates state precedence (degraded hook > reader errors > no events).

```go
func TestDigestSectionReasonPrecedence(t *testing.T) {
	// Build minimal input/state and assert selected reason key.
	// Expect degraded to win over reader-error/no-events.
}
```

- [x] **Step 2: Run test and confirm failure**

Run: `go test ./internal/agent -run TestDigestSectionReasonPrecedence -count=1`  
Expected: FAIL (test not implemented by current code path).

- [x] **Step 3: Implement runtime state tracking in `agent_linux.go`**

Add minimal fields and wiring:

```go
type sectionState struct {
	HookOK          bool
	ReaderErrors    int
	ObservedEventN  int
}
```

Track:
- UDP ring read/decode warnings -> increment UDP reader error counter.
- HTTP ring read/decode warnings -> increment HTTP reader error counter.
- Observed event counts from existing stats counters.
- Hook attach status from current BPF status.

Pass these into `report.DigestInput`.

- [x] **Step 4: Run focused agent tests**

Run: `go test ./internal/agent -count=1`  
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/agent/agent_linux.go internal/agent/*_test.go
git commit -m "feat(agent): track udp/http section state for digest explanations"
```

---

### Task 3: Digest empty-state reason rows for UDP/HTTP

**Files:**
- Modify: `internal/report/digest.go`
- Modify/Test: `internal/report/digest_test.go`

- [x] **Step 1: Write failing digest tests first**

Add test matrix:

```go
func TestBuildDetectMarkdown_UDPEmptyReason_NoEvents(t *testing.T) {}
func TestBuildDetectMarkdown_UDPEmptyReason_Degraded(t *testing.T) {}
func TestBuildDetectMarkdown_UDPEmptyReason_ReaderErrors(t *testing.T) {}
func TestBuildDetectMarkdown_HTTPEmptyReason_NoEvents(t *testing.T) {}
func TestBuildDetectMarkdown_HTTPEmptyReason_Degraded(t *testing.T) {}
func TestBuildDetectMarkdown_HTTPEmptyReason_ReaderErrors(t *testing.T) {}
```

Each test should assert a stable substring in markdown.

- [x] **Step 2: Run report tests and verify failure**

Run: `go test ./internal/report -run EmptyReason -count=1`  
Expected: FAIL before implementation.

- [x] **Step 3: Implement reason-row rendering in `digest.go`**

Add additive fields in `DigestInput` and use precedence:

```go
// precedence: degraded hook > reader errors > no events
func udpSectionReason(in DigestInput) string { /* ... */ }
func httpSectionReason(in DigestInput) string { /* ... */ }
```

When `len(in.UDPRows) == 0`, render one table row with reason text; same for HTTP.

- [x] **Step 4: Run report tests**

Run: `go test ./internal/report -count=1`  
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/report/digest.go internal/report/digest_test.go
git commit -m "feat(report): add explicit udp/http empty-state reason rows"
```

---

### Task 4: nightstalker-demo workflow regression hardening

**Files:**
- Modify: `.github/workflows/nightstalker-demo.yml`

- [x] **Step 1: Add assertion that empty UDP/HTTP tables are never ambiguous**

Keep existing positive checks, and add grep checks for explicit empty-state reason marker(s) if no UDP/HTTP rows exist.

```bash
# pseudo-shape in workflow step:
if ! grep -q '"type":"udp"' "$j"; then
  grep -q 'UDP reason:' "$f" || { echo "expected explicit UDP empty-state reason"; exit 1; }
fi
if ! grep -q '"type":"http"' "$j"; then
  grep -q 'HTTP reason:' "$f" || { echo "expected explicit HTTP empty-state reason"; exit 1; }
fi
```

- [x] **Step 2: Validate workflow YAML and shell syntax**

Run: `python scripts/assert_utf8_text.py`  
Expected: PASS.

- [x] **Step 3: Commit**

```bash
git add .github/workflows/nightstalker-demo.yml
git commit -m "ci(nightstalker-demo): enforce explicit udp/http empty-state explanations"
```

---

### Task 5: Full verification in CI-like Linux environment

**Files:**
- Verify only: repo root scripts/tests

- [x] **Step 1: Run CI-like Docker script**

Run: `bash scripts/docker-ubuntu-test.sh`  
Expected: `go generate`, `gofmt`, `vet`, `staticcheck`, `go test`, build all pass.

- [x] **Step 2: Run integration gate (if environment supports privileged tracing)**

Run: `NIGHTSTALKER_INTEGRATION=1 bash scripts/docker-ubuntu-test.sh`  
Expected: integration tests pass on Linux/privileged environment; if Docker Desktop tracefs blocks, rely on GitHub integration runner evidence.

- [x] **Step 3: Push and confirm nightstalker-demo green**

Run:

```bash
git push origin <branch>
gh run list --workflow nightstalker-demo.yml --limit 1
gh run watch
```

Expected: nightstalker-demo job passes with UDP/HTTP assertions and digest checks.

- [x] **Step 4: Final commit hygiene check**

Run: `git status --short`  
Expected: clean working tree.

---

## Self-review

**1. Spec coverage**
- Empty-state UX: Task 3
- Capture confidence / diagnostics: Tasks 1–2
- nightstalker-demo validation: Task 4
- End-to-end verification: Task 5

**2. Placeholder scan**
- No TODO/TBD placeholders; each task has concrete files, commands, and expected outcomes.

**3. Type consistency**
- Uses existing `DigestInput`, UDP/HTTP row types, and agent ring-read flow; new fields are additive and internal.
