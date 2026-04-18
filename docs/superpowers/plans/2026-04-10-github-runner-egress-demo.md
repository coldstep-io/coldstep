# GitHub runner egress demo (detect + enforce) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship bounded **deny-event draining** in enforce mode, update **nightstalker-demo** to prove **TCP / UDP / HTTP (cleartext)** in detect and enforce using **`curl`** and **`dig`**, and document **IPv4-only** and **HTTP vs HTTPS** semantics—per [2026-04-10-github-runner-egress-demo-design.md](../specs/2026-04-10-github-runner-egress-demo-design.md).

**Repository state (2026-04-11):** **`readDenyRing`** now drains up to **`enforceDenyDrainMaxEvents`** samples for **`enforceDenyDrainDuration`** after the first deny ( **`ringbuf.Reader.SetDeadline`** + **`os.ErrDeadlineExceeded`** ), appends each via **`appendDenyFromRaw`**, calls **`runCancel`** to stop sibling readers, then returns **`fmt.Errorf("enforce deny: …")`** using the **first** deny’s fields. **`Run`** merges **`errCh`** so an **`enforce deny:`** error wins over **`context.Canceled`** from other goroutines. **`.github/workflows/nightstalker-demo.yml`** already matches Tasks 4–5 (curl/dig, enforce greps). **`AGENTS.md`** already documents HTTP vs HTTPS / IPv4 enforce (Task 6).

**Architecture:** Keep BPF verdicts unchanged. Refactor the **deny ringbuf reader** in `internal/agent/agent_linux.go` so that after the first deny, userspace **reads additional deny records** until a **short deadline** or **max event count**, appending each to JSONL and updating `enforcementState`. Then return a single **`enforce deny`** error so `Run` still exits non-zero. Update **`.github/workflows/nightstalker-demo.yml`** probe order: **allowed** cleartext HTTP + HTTPS first, then **deny** TCP + UDP. Add **unit tests** for the new drain behavior and extend **grep** assertions.

**Tech Stack:** Go 1.24+, `github.com/cilium/ebpf` v0.21 (`ringbuf.Reader` with `SetDeadline`), GitHub Actions `ubuntu-latest`, bash, `curl`, `dig`.

**Historical note (2026-04-10):** Worktree **`feature/udp-http-capture-empty-state`** was a **separate branch**; do **not** commit `scripts/__pycache__/`.

---

## File map

| File | Role |
|------|------|
| `internal/agent/agent_linux.go` | `handleDenySample`, `readDenyRing`; implement drain loop and optional split of append vs final error |
| `internal/agent/agent_linux_test.go` | Tests for single-deny and multi-deny drain; `TestRun_EnforceDenyEventEmission` + `TestAppendDenyFromRaw_TwoSamples` |
| `.github/workflows/nightstalker-demo.yml` | Detect job: `curl`/`dig` probes + greps for tcp/udp/http; Enforce job: allowlist, probe order, assert `http` JSONL + tcp+udp denies |
| `AGENTS.md` | Short paragraph: cleartext HTTP vs HTTPS, IPv4-only enforcement |

---

### Task 1: Constants and helper for append-only deny handling

**Files:**
- Modify: `internal/agent/agent_linux.go` (near `handleDenySample` / `decodeDenyEvent`)

- [x] **Step 1: Add drain constants** (package-level or next to `readDenyRing`)

```go
const (
	enforceDenyDrainMaxEvents = 32
	enforceDenyDrainDuration   = 1200 * time.Millisecond
)
```

- [x] **Step 2: Add `appendDenyFromRaw`** that decodes `raw`, updates `state`, appends JSONL, returns **only** I/O / decode errors (never the synthetic `enforce deny` fatal)

```go
func appendDenyFromRaw(cfg config.Config, raw []byte, seq *telemetry.SeqGen, jsonlMu *sync.Mutex, state *enforcementState) error {
	tgid, tid, commb, protocolRaw, reasonRaw, daddr, dport, ok := decodeDenyEvent(raw)
	if !ok {
		return fmt.Errorf("decode deny event")
	}
	protocol := denyProtocolLabel(protocolRaw)
	reason := denyReasonLabel(reasonRaw)
	dst := net.IP(daddr[:]).String()
	comm := string(bytes.TrimRight(commb[:], "\x00"))
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	deny := telemetry.DenyEvent{
		Type: "deny", TS: ts, Seq: seq.Next(), PID: tgid, TGID: tgid, ThreadID: tid,
		Comm: comm, Protocol: protocol, Dst: dst, Dport: dport, Reason: reason, Mode: "enforce",
	}
	if state != nil {
		state.noteDeny(denyDigestRowFromEvent(deny))
	}
	if cfg.EventsLogPath != "" {
		jsonlMu.Lock()
		err := telemetry.AppendJSONL(cfg.EventsLogPath, deny)
		jsonlMu.Unlock()
		if err != nil {
			return fmt.Errorf("append deny jsonl: %w", err)
		}
	}
	return nil
}
```

- [x] **Step 3: Change `handleDenySample`** to call `appendDenyFromRaw` then return `fmt.Errorf("enforce deny: protocol=%s dst=%s dport=%d reason=%s", ...)` as today (keeps single-call sites working until Task 2)

- [x] **Step 4: Commit**

```bash
git add internal/agent/agent_linux.go
git commit -m "refactor(agent): extract appendDenyFromRaw for deny handling"
```

---

### Task 2: Implement `readDenyRing` bounded drain

**Files:**
- Modify: `internal/agent/agent_linux.go` — replace body of `readDenyRing`

- [x] **Step 1: Replace `readDenyRing`** with logic:

1. Loop forever on `ctx.Done()` vs `rd.Read()`.
2. On `ringbuf.ErrClosed` or `ctx.Err()`, return nil or ctx error.
3. On successful read: call `appendDenyFromRaw`; if append error, return it.
4. On first successful append in this invocation, set `drainUntil := time.Now().Add(enforceDenyDrainDuration)` and `n := 1`.
5. While `n < enforceDenyDrainMaxEvents` and `time.Now().Before(drainUntil)`, set `rd.SetDeadline(time.Now().Add(50 * time.Millisecond))`, `Read()` again; if timeout (check `errors.Is(err, os.ErrDeadlineExceeded)`), continue until outer wall clock passes `drainUntil`; on data, append and `n++`.
6. After drain window, return **`fmt.Errorf("enforce deny: ...")`** using **first** deny’s fields (store `firstProtocol`, `firstDst`, `firstDport`, `firstReason` from first successful append in this session).

Use `errors.Is` for deadline. Import `os` if needed for `os.ErrDeadlineExceeded`.

**Note:** If `SetDeadline` is unsupported on your `ringbuf.Reader`, use `select` + goroutine with a channel for `Read()`—but **cilium/ebpf v0.21** exposes `SetDeadline` on `*ringbuf.Reader`; verify with `go doc github.com/cilium/ebpf/ringbuf.Reader`.

- [x] **Step 2: Run unit tests (Linux or WSL with tags)**

Run: `go test ./internal/agent/... -tags=linux -count=1`  
Expected: pass or compile errors to fix.

- [x] **Step 3: Commit**

```bash
git add internal/agent/agent_linux.go
git commit -m "feat(agent): drain enforce deny ringbuf for bounded window"
```

---

### Task 3: Unit tests — multi-deny drain and existing test update

**Files:**
- Modify: `internal/agent/agent_linux_test.go`

- [x] **Step 1: Update `TestRun_EnforceDenyEventEmissionAndFailFast`**  
Rename to `TestRun_EnforceDenyEventEmission` or add a comment that "fail fast" now means "return error after drain"; assertion: still **one** synthetic deny in file, still expect `enforce deny` error from `handleDenySample` when testing `handleDenySample` alone.

- [x] **Step 2: Add `TestAppendDenyFromRaw_TwoSamples`**  
Two different raw payloads (TCP and UDP); call `appendDenyFromRaw` twice; assert JSONL contains **both** `"protocol":"tcp"` and `"protocol":"udp"` and `state.denyCount() == 2`.

- [x] **Step 3: Add `TestReadDenyRing_DrainsTwoRecords`** (optional if you can construct `ringbuf.Reader` from memory—**if too heavy**, skip ringbuf test and rely on integration; otherwise use a test-only helper that feeds raw samples)

**Pragmatic path:** Implement **two-append** test for `appendDenyFromRaw` only; add a **small unexported test helper** `drainDenyRecords(ctx, cfg, rd, ...)` test via **table-driven** mock **not** available—**minimum** is `appendDenyFromRaw` dual test + manual nightstalker-demo.

- [x] **Step 4: Run**

Run: `go test ./internal/agent/... -tags=linux -count=1 -run 'Enforce|AppendDeny' -v`  
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add internal/agent/agent_linux_test.go
git commit -m "test(agent): cover appendDenyFromRaw and enforce deny expectations"
```

---

### Task 4: nightstalker-demo — detect job (`curl` / `dig`, assert tcp / udp / http)

**Files:**
- Modify: `.github/workflows/nightstalker-demo.yml`

- [x] **Step 1: Open workflow** with UTF-8-safe editor (repo has UTF-8 guards).

- [x] **Step 2: In the detect egress simulation step**, ensure probes (bounded, **≤2 attempts per traffic class** per AGENTS.md):

```bash
set -euo pipefail
# HTTPS → TCP
for _ in 1 2; do curl -fsS --max-time 20 --connect-timeout 5 "https://google.com/" >/dev/null || true; done
# Cleartext HTTP → HTTP sniff path (port 80)
for _ in 1 2; do curl -fsS --max-time 20 --connect-timeout 5 "http://example.com/" >/dev/null || true; done
# UDP DNS
for _ in 1 2; do dig +time=1 +tries=1 @8.8.8.8 google.com A >/dev/null || true; done
```

Adjust hosts to match **existing** AGENTS egress domain list if required (`google.com`, `github.com`, `microsoft.com`).

- [x] **Step 3: Extend verification greps** so JSONL or digest mentions **http** traffic (e.g. grep `"type":"http"` **or** digest HTTP KPI non-empty—match actual `digest.go` output).

- [x] **Step 4: Commit**

```bash
git add .github/workflows/nightstalker-demo.yml
git commit -m "ci(nightstalker-demo): curl+dig detect probes and http assertions"
```

---

### Task 5: nightstalker-demo — enforce job (allowlist, order, tcp+udp+http denies)

**Files:**
- Modify: `.github/workflows/nightstalker-demo.yml`

- [x] **Step 1: Set** `allowed-domains: google.com` (or single domain that resolves IPv4 on CI).

- [x] **Step 2: Egress simulation block — strict order:**

```bash
set -euo pipefail
# Resolve (log for demo)
getent ahosts google.com || true
getent ahosts microsoft.com || true

# Allowed — cleartext HTTP first (http JSONL)
for _ in 1 2; do curl -fsS --max-time 20 --connect-timeout 5 "http://www.google.com/" >/dev/null || true; done
# Allowed — HTTPS
for _ in 1 2; do curl -fsS --max-time 20 --connect-timeout 5 "https://www.google.com/" >/dev/null || true; done
# Denied — TCP (microsoft not on allowlist)
for _ in 1 2; do curl -fsS --max-time 20 --connect-timeout 5 "https://www.microsoft.com/" >/dev/null || true; done
# Denied — UDP
for _ in 1 2; do timeout 20 bash -c 'printf "x" >/dev/udp/1.1.1.1/53' 2>/dev/null || true; done

sleep 2
```

- [x] **Step 3: Verification** — require:

```bash
grep '"type":"deny"' "$j" | grep -q '"protocol":"tcp"'
grep '"type":"deny"' "$j" | grep -q '"protocol":"udp"'
grep -q '"type":"http"' "$j" || grep -q '### HTTP' "$f"
```

Tune if digest uses different headings (read `internal/report/digest.go`).

- [x] **Step 4: Commit**

```bash
git add .github/workflows/nightstalker-demo.yml
git commit -m "ci(nightstalker-demo): enforce demo with google allow and microsoft deny"
```

---

### Task 6: AGENTS.md — operator semantics

**Files:**
- Modify: `AGENTS.md`

- [x] **Step 1: Add bullet** under network / egress section:

```markdown
- **HTTP vs HTTPS in telemetry:** Cleartext **`http://`** probes may produce **http** JSONL rows (BPF sniff); **`https://`** appears as **tcp** connect events only (no TLS HTTP bodies). **Enforce** allowlists are **IPv4** from resolved **A** records; IPv6 is not enforced in v1.
```

- [x] **Step 2: Commit**

```bash
git add AGENTS.md
git commit -m "docs(agents): clarify HTTP cleartext vs HTTPS and IPv4 enforce"
```

---

### Task 7: Verification (Linux)

**Files:**
- None

- [x] **Step 1: Docker Ubuntu script** (from repo root, Git Bash or Linux):

```bash
bash scripts/docker-ubuntu-test.sh
```

Expected: `gofmt`, `go vet`, `go test`, build succeed inside container.

- [x] **Step 2: Push branch / main**

```bash
git push origin main
```

---

## Self-review (plan vs spec)

| Spec requirement | Task |
|------------------|------|
| Bounded deny drain | Task 2 |
| TCP + UDP deny in one enforce run | Tasks 2 + 5 |
| HTTP visible (cleartext) detect + enforce | Tasks 4 + 5 |
| curl replaces nc where applicable | Tasks 4 + 5 |
| dig for UDP | Tasks 4 + 5 |
| IPv4 documented | Task 6 |
| No BPF verdict change | Task 2 only userspace |

**Placeholder scan:** None intentional.

---

## Execution handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-10-github-runner-egress-demo.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
