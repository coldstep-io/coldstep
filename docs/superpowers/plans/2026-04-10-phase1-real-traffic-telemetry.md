# Phase 1 Real-Traffic Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve UDP/TCP/HTTP detect reporting to better match the desired operator output while enforcing real traffic generation and validation in nightstalker-demo.

**Repository state (2026-04-11):** The digest empty-state / KPI / nightstalker-demo real-traffic checks described here are **implemented on `main`**. Use **`README.md`**, **`AGENTS.md`**, and **`git log`** for ground truth.

**Architecture:** Keep the current detect-only eBPF + userspace pipeline, add section-state metadata for UDP/HTTP empty-state reasons, and tighten nightstalker-demo traffic generation/assertions so CI validates real world signals (not header-only output). Preserve JSONL compatibility and explicit HTTPS limits.

**Tech Stack:** Go (`internal/agent`, `internal/report`, `internal/telemetry`), eBPF C (`bpf/trace_connect.bpf.c`), GitHub Actions workflow checks (`.github/workflows/nightstalker-demo.yml`).

---

## File map

| File | Responsibility |
|------|----------------|
| `internal/report/digest.go` | Render explicit UDP/HTTP empty-state reason rows and optional URL summary/status marker text |
| `internal/report/digest_test.go` | Unit tests for reason precedence and table output invariants |
| `internal/agent/agent_linux.go` | Collect and pass UDP/HTTP section-state metadata (hook health, reader/decode errors, event counts) |
| `internal/agent/decode_network_linux_test.go` | Preserve decode structure checks for UDP/HTTP ringbuf records |
| `.github/workflows/nightstalker-demo.yml` | Ensure real TCP/UDP/HTTP traffic generation and shape-aware assertions |
| `README.md` (optional) | Document what HTTP/HTTPS fields are available in detect mode |

---

### Task 1: Add digest empty-state reason rows (TDD)

**Files:**
- Modify: `internal/report/digest.go`
- Modify/Test: `internal/report/digest_test.go`

- [x] **Step 1: Write failing tests for UDP/HTTP empty-state reasons**

Add test cases for precedence:

```go
func TestBuildDetectMarkdown_UDPEmptyReason_Degraded(t *testing.T) {}
func TestBuildDetectMarkdown_UDPEmptyReason_ReaderErrors(t *testing.T) {}
func TestBuildDetectMarkdown_UDPEmptyReason_NoEvents(t *testing.T) {}
func TestBuildDetectMarkdown_HTTPEmptyReason_Degraded(t *testing.T) {}
func TestBuildDetectMarkdown_HTTPEmptyReason_ReaderErrors(t *testing.T) {}
func TestBuildDetectMarkdown_HTTPEmptyReason_NoEvents(t *testing.T) {}
```

- [x] **Step 2: Run tests to verify failure**

Run: `go test ./internal/report -run EmptyReason -count=1`  
Expected: FAIL before implementation.

- [x] **Step 3: Implement minimal reason-row logic in `digest.go`**

Add additive `DigestInput` fields and precedence helpers:

```go
func udpEmptyReason(in DigestInput) string { /* degraded > reader errors > no events */ }
func httpEmptyReason(in DigestInput) string { /* degraded > reader errors > no events */ }
```

When `len(in.UDPRows)==0` or `len(in.HTTPRows)==0`, render one row with reason text instead of an ambiguous empty table body.

- [x] **Step 4: Run report tests**

Run: `go test ./internal/report -count=1`  
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/report/digest.go internal/report/digest_test.go
git commit -m "feat(report): add explicit udp/http empty-state reason rows"
```

---

### Task 2: Plumb runtime section-state metadata from agent

**Files:**
- Modify: `internal/agent/agent_linux.go`
- Modify/Test: `internal/agent/*_test.go`

- [x] **Step 1: Write failing test for section-state mapping**

Add a focused unit test that verifies digest input receives expected UDP/HTTP state flags/counters.

```go
func TestRun_BuildsDigestInputWithUDPHTTPSectionState(t *testing.T) {}
```

- [x] **Step 2: Run targeted test to verify failure**

Run: `go test ./internal/agent -run DigestInputWithUDPHTTPSectionState -count=1`  
Expected: FAIL before implementation.

- [x] **Step 3: Implement minimal state plumbing**

In `agent_linux.go`:

- track UDP/HTTP reader/decode errors separately,
- derive hook health from existing BPF status,
- pass these fields to `report.DigestInput`.

Keep current event JSONL writes unchanged.

- [x] **Step 4: Run agent tests**

Run: `go test ./internal/agent -count=1`  
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/agent/agent_linux.go internal/agent/*_test.go
git commit -m "feat(agent): pass udp/http section-state metadata into digest"
```

---

### Task 3: Harden nightstalker-demo real-traffic generation + assertions

**Files:**
- Modify: `.github/workflows/nightstalker-demo.yml`

- [x] **Step 1: Add explicit real-traffic generation checks**

Keep generation commands for:
- TCP (`/dev/tcp`, `nc`),
- UDP (resolver `dig/getent` + explicit UDP path where possible),
- HTTP (`curl --http1.1`, raw GET via `nc`).

Ensure commands run with bounded retries and are not replaced by synthetic stubs.

- [x] **Step 2: Add shape-aware assertions in verify step**

Check JSONL and digest for:

```bash
grep -q '"type":"tcp"' "$j"
grep -q '"type":"udp"' "$j"
grep -q '"type":"http"' "$j"
grep '"type":"udp"' "$j" | grep -q '"dport":53'
grep '"type":"http"' "$j" | grep -q '"dport":80'
grep -q '`GET`' "$f"
```

Also assert empty-state reason text appears when section row count is zero.

- [x] **Step 3: Validate workflow text encoding/syntax**

Run: `python scripts/assert_utf8_text.py`  
Expected: PASS.

- [x] **Step 4: Commit**

```bash
git add .github/workflows/nightstalker-demo.yml
git commit -m "ci(nightstalker-demo): enforce real tcp/udp/http traffic and evidence checks"
```

---

### Task 4: Optional operator-facing docs alignment

**Files:**
- Modify: `README.md` (if needed)

- [x] **Step 1: Add concise detect-mode field expectations**

Document:
- HTTP cleartext method/host/path are available,
- HTTPS response code is unavailable in phase 1 detect-only mode,
- UDP/TCP domain enrichment is best-effort.

- [x] **Step 2: Run docs lint/quick sanity**

Run: `python scripts/assert_utf8_text.py`  
Expected: PASS.

- [x] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: clarify phase1 real-traffic telemetry and https limits"
```

---

### Task 5: Verification gates before merge

**Files:**
- Verify only

- [x] **Step 1: Run package-level tests**

Run:

```bash
go test ./internal/report ./internal/agent ./internal/telemetry -count=1
```

Expected: PASS (Linux authoritative; Windows host limitations acknowledged).

- [x] **Step 2: Run CI-like container check**

Run: `bash scripts/docker-ubuntu-test.sh`  
Expected: `go generate`, `gofmt`, `vet`, `staticcheck`, `go test`, and build pass.

- [x] **Step 3: Run integration gate where supported**

Run: `NIGHTSTALKER_INTEGRATION=1 bash scripts/docker-ubuntu-test.sh`  
Expected: PASS on Linux environments with tracing support; if Docker Desktop tracing is unavailable, rely on GitHub integration evidence.

- [x] **Step 4: Verify nightstalker-demo run**

Run:

```bash
git push -u origin <feature-branch>
gh run list --workflow nightstalker-demo.yml --limit 1
gh run watch
```

Expected: nightstalker-demo green with real-traffic assertions.

---

## Self-review

**1. Spec coverage**
- Empty-state reasons: Tasks 1–2
- Real traffic generation/assertions: Task 3
- HTTPS detect-only expectation: Tasks 4 + existing footnotes
- CI evidence: Task 5

**2. Placeholder scan**
- No TBD/TODO placeholders; each step includes concrete actions and commands.

**3. Type consistency**
- Uses additive `DigestInput` metadata and existing UDP/HTTP event schema; no incompatible JSONL changes.
