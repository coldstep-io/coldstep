# Egress digest integration + npm supply chain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Repository state (2026-04-11):** Tasks below are **complete** on `main` (`package.json` `overrides.undici`, rebuilt `dist/*`, KPI `<sub>` note in `internal/report/digest.go`, `TestRun_UDPSendtoLoggedJSONL` / `TestRun_HTTPSendtoPort80JSONL` in `agent_integration_test.go`). Checkboxes retained as `[x]` for traceability.

**Goal:** Prove the BPF→JSONL→digest path for IPv4 UDP (`sendto`) and cleartext HTTP (`sendto` to port 80) in root integration tests, document capture semantics in the detect markdown KPI, and land the npm `undici` advisory fix without upgrading to ESM-only `@actions/core` v3 (incompatible with `@vercel/ncc`).

**Architecture:** Leave `bpf/trace_connect.bpf.c` syscall selection unchanged for this plan; align automated tests with the same traffic shapes already validated in `.github/workflows/nightstalker-demo.yml` (`/dev/udp/.../53`, `nc` pipe with a raw `GET`). Users who see TCP but not UDP/HTTP are usually hitting **coverage limits**, not a broken markdown builder—`internal/report/digest.go` already renders empty-state rows via `udpEmptyReason` / `httpEmptyReason` (see `internal/report/digest_test.go`).

**Tech Stack:** Go (`internal/agent`, `internal/report`), npm (`package.json` overrides, `@vercel/ncc` bundles), GitHub Actions integration job (`-tags=integration`).

**Note:** `docs/superpowers/plans/2026-04-10-udp-http-capture-and-empty-state.md` partially duplicates digest work that is **already implemented** (empty-state tests and nightstalker-demo greps). Follow **this** plan instead; do not reintroduce pseudo-markers like `UDP reason:`—nightstalker-demo uses table-row patterns with `degraded hook`, `reader errors (N)`, or `no events`.

---

## File map

| File | Responsibility |
|------|----------------|
| `package.json` | `overrides` for `undici@^6.23.1` so `@actions/http-client` no longer resolves to vulnerable `undici@5.x` |
| `package-lock.json` | Locked tree after `npm install` |
| `dist/main/index.js` (+ `.map`) | Regenerated `ncc` bundle for the composite action main entry |
| `dist/post/index.js` (+ `.map`) | Regenerated `ncc` bundle for the post step |
| `internal/agent/agent_integration_test.go` | New `TestRun_*` cases: UDP via `/dev/udp`, HTTP via `nc` + raw request (skip if `nc` missing) |
| `internal/report/digest.go` | One HTML `<sub>` line immediately after the KPI table explaining `sendto` / `:80` / TLS |
| `internal/report/digest_test.go` | Extend `TestBuildDetectMarkdown_KPIAndSections` needle list (or add one focused test) for the new KPI note |

---

### Task 1: Land npm `undici` override and rebuilt action bundles

**Files:**

- Modify: `package.json`
- Modify: `package-lock.json`
- Modify: `dist/main/index.js`, `dist/main/index.js.map`, `dist/post/index.js`, `dist/post/index.js.map`

- [x] **Step 1: Ensure `package.json` contains the override**

```json
{
  "name": "nightstalker-action",
  "private": true,
  "scripts": {
    "typecheck": "tsc --noEmit",
    "build": "ncc build src/main.ts -o dist/main --source-map && ncc build src/post.ts -o dist/post --source-map"
  },
  "dependencies": {
    "@actions/core": "^1.11.1"
  },
  "overrides": {
    "undici": "^6.23.1"
  },
  "devDependencies": {
    "@types/node": "^24.0.0",
    "@vercel/ncc": "^0.38.3",
    "typescript": "^5.7.2"
  },
  "engines": {
    "node": ">=24"
  }
}
```

- [x] **Step 2: Refresh the lockfile and verify audit is clean**

Run:

```powershell
Set-Location c:\dumper_5000
npm install
npm audit
```

Expected: `found 0 vulnerabilities` (or equivalent success exit code).

- [x] **Step 3: Rebuild bundles**

Run:

```powershell
Set-Location c:\dumper_5000
npm run typecheck
npm run build
```

Expected: both `ncc` builds complete with exit code 0.

- [x] **Step 4: Commit**

```bash
git add package.json package-lock.json dist/main/index.js dist/main/index.js.map dist/post/index.js dist/post/index.js.map
git commit -m "fix(npm): override undici for advisory resolution; rebuild ncc bundles"
```

---

### Task 2: Document capture semantics under the KPI table

**Files:**

- Modify: `internal/report/digest.go` (function `BuildDetectMarkdown`, immediately after the KPI row block that ends with `| **http** | … |`)
- Modify: `internal/report/digest_test.go`

- [x] **Step 1: Write the failing substring assertion first**

In `TestBuildDetectMarkdown_KPIAndSections`, append to the `needle` slice:

```go
"<sub>UDP KPI counts IPv4 sendto egress.",
```

Full loop context (`internal/report/digest_test.go`):

```go
	for _, needle := range []string{
		"### KPI", "| **exec** | 1 |", "| **udp** | 3 |", "| **http** | 4 |",
		"UDP sendto", "HTTP/1 cleartext", "Canonical log (JSONL)", "connect(2)",
		"PID (TGID)", "| `99` |", "`sh`", "Executable (BPF-capped)", "`/bin/sh`",
		"UDP KPI counts IPv4 sendto egress.",
	} {
```

- [x] **Step 2: Run report tests and confirm failure**

Run:

```powershell
Set-Location c:\dumper_5000
go test ./internal/report -run TestBuildDetectMarkdown_KPIAndSections -count=1
```

Expected: FAIL with `missing "UDP KPI counts IPv4 sendto egress."`.

- [x] **Step 3: Insert the KPI scope note in `BuildDetectMarkdown`**

In `internal/report/digest.go`, after writing the four KPI rows and the blank line following them (currently `b.WriteString("\n")` right after the http KPI line), insert **before** the `PolicyCounts` block:

```go
	b.WriteString("<sub>UDP KPI counts IPv4 sendto egress. HTTP KPI counts cleartext HTTP/1 request bytes on sendto to destination port 80 only; https traffic appears as tcp connect events.</sub>\n\n")
```

Keep the existing `if len(in.PolicyCounts) > 0` logic unchanged below this line.

- [x] **Step 4: Run report tests**

Run:

```powershell
Set-Location c:\dumper_5000
go test ./internal/report -count=1
```

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/report/digest.go internal/report/digest_test.go
git commit -m "docs(report): clarify udp/http KPI capture semantics in detect digest"
```

---

### Task 3: Root integration test — UDP `sendto` produces JSONL

**Files:**

- Modify: `internal/agent/agent_integration_test.go`

- [x] **Step 1: Append the new test (full file section to add at end of file)**

```go
func TestRun_UDPSendtoLoggedJSONL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	dir := t.TempDir()
	detect := filepath.Join(dir, "detect.md")
	events := filepath.Join(dir, ".nightstalker-events.jsonl")
	if err := os.WriteFile(detect, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("NIGHTSTALKER_ALLOWED_HOSTS", "")
	t.Setenv("NIGHTSTALKER_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("NIGHTSTALKER_DETECT_LOG", detect)
	t.Setenv("NIGHTSTALKER_EVENTS_LOG", events)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(450 * time.Millisecond)

	// Same traffic class as nightstalker-demo: bash /dev/udp IPv4 sendto to :53
	cmd := exec.Command("bash", "-c", `timeout 6 bash -c 'printf "x" >/dev/udp/1.1.1.1/53' 2>/dev/null || true`)
	if err := cmd.Run(); err != nil {
		t.Logf("udp probe (non-fatal): %v", err)
	}

	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"type":"udp"`)) {
		t.Fatalf("expected at least one udp JSONL line, got:\n%s", b)
	}
	if !bytes.Contains(b, []byte(`"dport":53`)) {
		t.Fatalf("expected udp JSONL with dport 53, got:\n%s", b)
	}
}
```

- [x] **Step 2: Run the new test on Linux with integration tag**

Run (on Linux host or privileged Docker per `AGENTS.md`):

```bash
cd /path/to/nightstalker
sudo go test ./internal/agent -tags=integration -run TestRun_UDPSendtoLoggedJSONL -count=1 -v
```

Expected before implementation: build OK, FAIL with `expected at least one udp JSONL line` if test file not added yet; after adding test, PASS on `ubuntu-latest`-class environment.

- [x] **Step 3: Commit**

```bash
git add internal/agent/agent_integration_test.go
git commit -m "test(integration): assert udp sendto jsonl on linux bpf run"
```

---

### Task 4: Root integration test — cleartext HTTP via `nc` + raw `GET`

**Files:**

- Modify: `internal/agent/agent_integration_test.go`

- [x] **Step 1: Add the HTTP integration test**

```go
func TestRun_HTTPSendtoPort80JSONL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("nc not installed:", err)
	}
	dir := t.TempDir()
	detect := filepath.Join(dir, "detect.md")
	events := filepath.Join(dir, ".nightstalker-events.jsonl")
	if err := os.WriteFile(detect, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("NIGHTSTALKER_ALLOWED_HOSTS", "")
	t.Setenv("NIGHTSTALKER_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("NIGHTSTALKER_DETECT_LOG", detect)
	t.Setenv("NIGHTSTALKER_EVENTS_LOG", events)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(450 * time.Millisecond)

	// Cleartext HTTP/1 request bytes on sendto to :80 (matches bpf/trace_connect.bpf.c).
	// Use doubled backslashes so bash printf emits real CRLF after unescaping.
	payload := "GET / HTTP/1.1\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n"
	script := "printf '" + payload + "' | timeout 10 nc -w 6 example.com 80 >/dev/null 2>&1 || true"
	cmd := exec.Command("bash", "-c", script)
	if err := cmd.Run(); err != nil {
		t.Logf("http probe (non-fatal): %v", err)
	}

	cancel()
	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("Run: %v", err)
	}

	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"type":"http"`)) {
		t.Fatalf("expected at least one http JSONL line, got:\n%s", b)
	}
	if !bytes.Contains(b, []byte(`"dport":80`)) {
		t.Fatalf("expected http JSONL with dport 80, got:\n%s", b)
	}
}
```

- [x] **Step 2: Run the HTTP integration test**

Run:

```bash
sudo go test ./internal/agent -tags=integration -run TestRun_HTTPSendtoPort80JSONL -count=1 -v
```

Expected: PASS when outbound `example.com:80` is reachable from the runner (true on `ubuntu-latest` today). If corporate firewalls block port 80, document skip in commit message and consider swapping host to the same allowlisted FQDN strategy as nightstalker-demo in a follow-up—**do not** silently weaken the assertion in CI without an issue link.

- [x] **Step 3: Commit**

```bash
git add internal/agent/agent_integration_test.go
git commit -m "test(integration): assert cleartext http sendto:80 jsonl on linux bpf run"
```

---

### Task 5: Linux CI parity and UTF-8 gate

**Files:**

- Verify only (no new files unless CI YAML must reference new tests—integration job already runs `-tags=integration` on Linux)

- [x] **Step 1: Run UTF-8 text gate**

Run:

```powershell
Set-Location c:\dumper_5000
python scripts/assert_utf8_text.py
```

Expected: exit code 0.

- [x] **Step 2: Run Docker Ubuntu test script (authoritative for BPF + Go)**

Run (from Git Bash or Linux):

```bash
bash scripts/docker-ubuntu-test.sh
```

Expected: `gofmt`, `go vet`, `staticcheck`, `go test ./...` (unit) pass inside the container.

- [x] **Step 3: Optional privileged integration inside Docker**

Run:

```bash
NIGHTSTALKER_INTEGRATION=1 bash scripts/docker-ubuntu-test.sh
```

Expected: integration package tests pass when the container supports BPF + tracing; if `sched_process_exec` / tracefs limits fail on Docker Desktop per `AGENTS.md`, record that outcome in the PR description and rely on GitHub Actions integration job logs as evidence.

- [x] **Step 4: Final hygiene**

Run:

```bash
git status --short
```

Expected: clean tree after commits.

---

## Self-review

**1. Spec coverage (conversation + repo facts)**

| Requirement | Task |
|-------------|------|
| Dependabot / `undici` advisories without `@actions/core` v3 + `ncc` break | Task 1 |
| Explain why TCP can appear without UDP/HTTP in digest | Task 2 |
| Automated proof UDP path works end-to-end on Linux BPF | Task 3 |
| Automated proof HTTP sniff path works end-to-end | Task 4 |
| CI-quality verification | Task 5 |

**2. Placeholder scan**

- No `TBD` / `TODO` / open-ended “add validation” steps.
- Task 4 notes a real network dependency; escape sequences are explicit in code.

**3. Type consistency**

- Tests use existing `config.LoadFromEnv`, `Run`, env vars `NIGHTSTALKER_EVENTS_LOG` / `NIGHTSTALKER_DETECT_LOG` consistent with `TestRun_ExecJSONLIncludesExePath`.

**4. Gap vs older plan file**

- Do **not** re-implement digest empty-state tables (`2026-04-10-udp-http-capture-and-empty-state.md` Tasks 2–3)—already present in `digest.go` / `digest_test.go`.
- Do **not** add nightstalker-demo `grep` for fictional `UDP reason:` strings; existing workflow already validates empty-state row shapes.

---

**Plan complete and saved to `docs/superpowers/plans/2026-04-10-egress-digest-integration-and-npm-supply-chain.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration (**REQUIRED SUB-SKILL:** superpowers:subagent-driven-development).

**2. Inline Execution** — Execute tasks in this session using executing-plans with checkpoints (**REQUIRED SUB-SKILL:** superpowers:executing-plans).

**Which approach?**
