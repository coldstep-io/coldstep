# Coldstep CI reliability + eBPF hardening + second brain — implementation program

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drive GitHub Actions workflows to **green** where failures are product/CI defects; advance **eBPF observability/enforce** along a verifier-safe roadmap; maintain **honest threat-model** alignment with literature; and **mandatorily** capture research and decisions in the local **`knowledge/`** vault (“second brain”) before and after substantive changes.

**Architecture:** Treat work as **ordered streams** with a **brain gate**: (1) **inventory + vault search** → (2) **CI stabilization** (`coldstep-ci-runner.yml` jobs: `action_manifest`, `unit`, `unit-arm64`, `integration`, `action_bundle`, `detect-mode`, `prevent-mode`; plus `coldstep-ci-nightly.yml`) → (3) **BPF tranches** aligned to hook-class map (trace vs cgroup enforce) → (4) **telemetry/digest honesty** (loss signals already partially in `runStats` / `.coldstep-telemetry.json`) → (5) **vault synthesis reports** per milestone. **YAGNI:** do not expand IPv6 enforce or new syscall surfaces until prior tranche is green on PR CI + documented.

**Tech stack:** Go **1.25.x** (`go.mod` / `toolchain`), **cilium/ebpf**, BPF C under **`bpf/`**, GitHub Actions **`ubuntu-latest`** / matrix OS labels, **`gh` CLI** for run inventory, local **`knowledge/`** Obsidian pipeline (`records/` → `raw/` → `wiki/` → `reports/` → `Index.md`).

**Plan location note:** Default `docs/superpowers/plans/` is **gitignored** in this repository; this file lives under **`.github/design/`** as the tracked implementation plan.

---

## File / area map (what may change)

| Area | Paths | Responsibility |
| ---- | ----- | -------------- |
| CI orchestration | `.github/workflows/coldstep-ci.yml`, `coldstep-ci-runner.yml`, `coldstep-ci-nightly.yml`, demo workflows | Job graph, timeouts, matrix, permissions |
| CI scripts | `scripts/check-gofmt.sh`, `scripts/build-agent-linux.sh`, `scripts/check_workflow_action_pins.py`, `scripts/ci_coldstep_jsonl_traffic_diff.py`, `scripts/test_*.py` | Preconditions for jobs |
| Agent + BPF | `internal/agent/agent_linux.go`, `bpf/*.bpf.c`, `bpf/*.inc`, `internal/bpf/**` | Load, ringbuf readers, enforce programs |
| Telemetry JSON | `internal/telemetry/*.go`, `.coldstep-telemetry.json` consumer contract | Loss counters / stats export |
| Product docs | `README.md`, `SECURITY.md`, `.github/design/*-mitigations-design.md` | Consumer honesty |
| Second brain (local) | `knowledge/README.md`, `knowledge/wiki/*`, `knowledge/raw/*`, `knowledge/records/*`, `knowledge/reports/*`, `knowledge/Index.md` | Research persistence (not git) |

---

### Task 1: Second brain — mandatory preflight (before any CI/BPF edit)

**Files:**
- Read: `knowledge/README.md`
- Search: `knowledge/wiki/`, `knowledge/raw/`, `knowledge/records/` (grep or Obsidian)

- [ ] **Step 1: Open vault entrypoints**

Read `knowledge/README.md` and `knowledge/Index.md` (create minimal `Index.md` rows if a theme is missing).

- [ ] **Step 2: Search existing research** (PowerShell from repo root)

```powershell
Set-Location <REPO_ROOT>
Select-String -Path "knowledge\wiki\*.md","knowledge\raw\*.md","knowledge\records\*.md" -Pattern "enforce|ringbuf|govulncheck|workflow|detect-mode|prevent" -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 40
```

Expected: either hits with paths to reuse **or** empty result → you **must** add new `raw/` + `records/` when you pull URLs later (Task 2).

- [ ] **Step 3: Commit discipline (local only)**

Do **not** `git add` under `knowledge/`. Record in your session notes that vault updates are **local** per root `.gitignore`.

---

### Task 2: Second brain — CI failure inventory report (local)

**Files:**
- Create (local): `knowledge/reports/YYYY-MM-DD-ci-actions-inventory.md` (use today’s date in the filename)

- [ ] **Step 1: List recent failing runs**

```powershell
gh run list --repo coldstep-io/coldstep --limit 40 --json databaseId,conclusion,displayTitle,workflowName,headBranch,url
```

Filter mentally to `conclusion != "success"` (or export to JSON and filter with `jq` if available).

- [ ] **Step 2: Write the report with this exact section skeleton**

```markdown
# CI failure inventory

## Failed runs (last N)
| Run ID | Workflow | Branch | Conclusion | URL |
| --- | --- | --- | --- | --- |

## Job-level next step
For each failed run ID, run:
`gh run view <ID> --log-failed`
and paste **failing job name** + **first error line** into subsection per run.

## P0 order (fill)
1. action_manifest / pins / UTF-8
2. unit / unit-arm64 (gofmt, bpf codegen, staticcheck, tests)
3. integration (sudo BPF)
4. action_bundle (npm)
5. detect-mode / prevent-mode
6. nightly only if PR path green
```

- [ ] **Step 3: Link from `knowledge/Index.md`**

Add a wikilink row: `[[reports/YYYY-MM-DD-ci-actions-inventory]]`.

---

### Task 3: Fix stream — `action_manifest` job (pins, UTF-8, Python tests, shell markers)

**Files:**
- Modify (as needed): `scripts/check_workflow_action_pins.py`, `scripts/assert_utf8_text.py`, `scripts/test_check_workflow_action_pins.py`, `.github/workflows/*.yml`
- Run locally: same commands as workflow

- [ ] **Step 1: Reproduce locally**

```powershell
python3 scripts/assert_utf8_text.py
python3 scripts/check_workflow_action_pins.py
python3 -m unittest discover -s scripts -p "test_*.py" -v
bash scripts/test_workflow_diff_markers.sh
```

Expected: all exit **0**. If `bash` missing on Windows, run the same inside **`golang:1.25-bookworm`** or **`Dockerfile.deep-debug`** container where `bash` exists.

- [ ] **Step 2: Fix failures**

Apply minimal edits. Typical failures: **non-UTF-8 tracked text**, **`@main` pin** in workflow, unittest expectation drift.

- [ ] **Step 3: Vault note**

Append a short subsection to `knowledge/reports/YYYY-MM-DD-ci-actions-inventory.md`: **what broke** + **fix summary** + **files touched**.

- [ ] **Step 4: Commit (git tracked files only)**

```powershell
git add <paths>
git commit -S -m "ci: fix action_manifest failures (pins/utf8/scripts)"
```

---

### Task 4: Fix stream — `unit` / `unit-arm64` jobs (Go + BPF codegen)

**Files:**
- Run: `scripts/check-gofmt.sh`, `scripts/build-agent-linux.sh`, `go vet`, `staticcheck`, tests under `internal/...`

- [ ] **Step 1: Linux Docker reproduction** (matches CI)

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace golang:1.25-bookworm bash -lc '
set -euo pipefail
export GOTOOLCHAIN=auto
bash scripts/check-gofmt.sh
bash scripts/build-agent-linux.sh /workspace
go vet ./...
go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
export PATH="$(go env GOPATH)/bin:$PATH"
staticcheck ./...
go test ./... -count=1
go test -race -count=1 ./internal/agent/... -timeout 15m
'
```

Expected: all **0** exit. Replace `${PWD}` with repo root on Windows host path (`c:\GitHub\coldstep` → `/workspace`).

- [ ] **Step 2: Fix failures**

- `gofmt`: run `gofmt -w` on reported files.
- `build-agent-linux.sh`: fix BPF compile / bpf2go drift; regenerate checked-in Go only if repo expects it.
- `staticcheck`: address findings or narrow scope with documented `#nolint` only if justified.
- `go test -race`: fix data races (historical example: mutex around test maps in `internal/policy/allowlist_test.go`).

- [ ] **Step 3: Vault**

Add **`knowledge/raw/`** stub if you relied on an external doc (e.g. Go race detector manual) + **`records/`** snapshot per `knowledge/README.md`.

- [ ] **Step 4: Commit**

```powershell
git commit -S -m "fix(ci): unit job — gofmt/bpf/vet/staticcheck/tests"
```

---

### Task 5: Fix stream — `integration` job (sudo + BPF)

**Files:**
- `internal/agent/*_test.go` (integration tag), `scripts/build-agent-linux.sh`

- [ ] **Step 1: Reproduce in privileged Linux**

```powershell
docker run --rm --privileged -v "${PWD}:/workspace" -w /workspace golang:1.25-bookworm bash -lc '
set -euo pipefail
export GOTOOLCHAIN=auto
bash scripts/build-agent-linux.sh /workspace
sudo -E env "PATH=$PATH" go test -tags=integration ./internal/agent/... -count=1
'
```

Expected: **PASS**. If kernel lacks BPF inside container, rely on **GitHub-hosted** integration as source of truth and fix code paths that assume features.

- [ ] **Step 2: Fix + commit** with message `fix(ci): integration tests (sudo BPF)`.

- [ ] **Step 3: Vault report line** under inventory report.

---

### Task 6: Fix stream — `action_bundle` (Node 24)

**Files:**
- `package.json`, `package-lock.json`, `src/main.ts`, `src/post.ts`, `dist/main/index.js`, `dist/post/index.js`

- [ ] **Step 1: Reproduce**

```powershell
npm ci
npm run typecheck
npm run build
```

- [ ] **Step 2: Fix TypeScript** until typecheck clean; run build.

- [ ] **Step 3: Commit built artifacts** (repo policy: tracked `dist/` matches TS)

```powershell
git add src dist package-lock.json
git commit -S -m "fix(ci): action_bundle typecheck/build"
```

---

### Task 7: Fix stream — `detect-mode` job (composite + JSONL assertions)

**Files:**
- `.github/workflows/coldstep-ci-runner.yml` (job `detect-mode`), `action.yml`, `src/main.ts`, `internal/agent/agent_linux.go`, `scripts/ci_coldstep_jsonl_traffic_diff.py`

- [ ] **Step 1: Identify failure class**

From `gh run view --log-failed`: distinguish **composite/start**, **missing tools**, **JSONL grep miss**, **prev-run diff** (`COLDSTEP_DIFF_STRICT`).

- [ ] **Step 2: Targeted fix**

- JSONL missing `type:tls` / `fs_event`: adjust probes/gates in agent **or** relax job only if product allows (prefer fixing root cause).
- Diff baseline missing: ensure **`coldstep-events-baseline-ubuntu-latest`** artifact upload still runs (`if: always()` already present).

- [ ] **Step 3: Vault**

If behavior ties to literature (eBPF loss / partial hooks), link **`wiki/ebpf-monitoring-evasion`** and add **`records/`** for any new URL.

---

### Task 8: Fix stream — `prevent-mode` job (enforce + verifier time)

**Files:**
- `bpf/trace_enforce.bpf.c`, `internal/agent/agent_linux.go`, policy code `internal/policy/*`, workflow job `prevent-mode`

- [ ] **Step 1: Classify failure**

Verifier timeout vs deny JSONL assertion vs allowlist DNS empty.

- [ ] **Step 2: Fix minimal**

Keep **`timeout-minutes: 45`** headroom; fix policy compile errors and deny reason strings expected by grep steps (`dst_not_allowlisted`, TCP deny).

- [ ] **Step 3: Vault**

Update **`knowledge/wiki/coldstep-scope-ipv4-v1.md`** (or create) if enforce semantics change.

---

### Task 9: Nightly workflow — `coldstep-ci-nightly.yml`

**Files:**
- `.github/workflows/coldstep-ci-nightly.yml`, `go.mod`

- [ ] **Step 1: Manual dispatch**

Use GitHub UI: Actions → **coldstep-ci nightly** → Run workflow → enable govulncheck + shuffle; optionally full race.

- [ ] **Step 2: Fix `govulncheck`**

If Go stdlib vuln: bump **`toolchain`** / **`go` directive** in `go.mod` per scanner output (workspace already moved to **1.25.8** toolchain historically).

- [ ] **Step 3: Vault**

`knowledge/records/` snapshot for CVE/advisory URL + `reports/` one-paragraph summary.

---

### Task 10: BPF tranche **E** — ringbuf reserve visibility (regression tests + optional parity maps)

**Fact check:** `telemetry.Summary` **already** defines `udp_ringbuf_reserve_failures` and `dns_ringbuf_reserve_failures` (`internal/telemetry/telemetry.go` lines 43–44). BPF maps `udp_ringbuf_reserve_failures` / `dns_ringbuf_reserve_failures` exist (`bpf/trace_connect.bpf.c`, `bpf/trace_dns.bpf.c`), and `internal/agent/agent_linux.go` reads them into stats (~1482–1510, ~1765–1766, ~1982–2013).

**Goal:** Lock the contract with **tests**; only add **new** BPF maps if you need parity for **connect/http/tls** ringbuf reserve failures (same pattern as UDP/DNS).

**Files:**
- Modify: `internal/telemetry/telemetry_test.go` (linux-tagged), optionally `bpf/trace_tcp_obs.inc` / `bpf/trace_http_obs.inc` + generated Go if adding new failure counters

- [ ] **Step 1: Add regression test** — append to `internal/telemetry/telemetry_test.go` after existing `TestWriteSummary`:

```go
func TestWriteSummaryIncludesRingbufReserveFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "telemetry.json")
	s := Summary{
		Version: 2, SchemaVersion: SchemaVersion,
		ExecEvents: 1, TCPEvents: 1, UDPEvents: 1, HTTPEvents: 1,
		UDPRingbufReserveFailures:   7,
		DNSRingbufReserveFailures:   3,
		PolicyCounts:                map[string]int{"monitor": 1},
	}
	if err := WriteSummary(p, s); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"udp_ringbuf_reserve_failures": 7`)) {
		t.Fatalf("missing udp reserve count: %s", b)
	}
	if !bytes.Contains(b, []byte(`"dns_ringbuf_reserve_failures": 3`)) {
		t.Fatalf("missing dns reserve count: %s", b)
	}
}
```

Add `"bytes"` to imports in that file.

- [ ] **Step 2: Run (Linux / Docker)**

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace golang:1.25-bookworm bash -lc 'export GOTOOLCHAIN=auto; go test ./internal/telemetry/... -count=1'
```

Expected: **PASS**.

- [ ] **Step 3 (optional):** Add `connect_events` / `http_events` ringbuf reserve failure maps mirroring UDP — only if product requires symmetry; otherwise **skip** and record **deferred** in `knowledge/reports/`.

- [ ] **Step 4: Vault** — link Trail of Bits pitfall #5 in `knowledge/wiki/ebpf-debugging-testing-security-telemetry.md` or a new `knowledge/reports/YYYY-MM-DD-tranche-E-telemetry-tests.md`.

- [ ] **Step 5: Commit** `test(telemetry): cover ringbuf reserve fields in summary JSON`.

---

### Task 11: BPF tranche **A** — UDP path coverage audit (`sendmsg` / connected UDP)

**Goal:** Validate **`bpf/trace_udp_sendmsg.inc`** + `trace_connect.bpf.c` multiplex covers monitored UDP egress paths on **`ubuntu-latest`** kernel; add **agent-level test** or **integration probe** that exercises `sendmsg` vs `sendto` where feasible.

**Files:**
- Read: `bpf/trace_udp_sendmsg.inc`, `bpf/trace_connect.bpf.c`, `internal/agent/agent_linux.go` (UDP ring reader `readUDPRing`)

- [ ] **Step 1: Document current hooks** in local vault `knowledge/wiki/ebpf-coldstep-bpf-c.md` (paragraph + code pointers).

- [ ] **Step 2: Add integration scenario** under `internal/agent/*_test.go` (build tag `integration`) **or** extend CI detect steps only if test harness cannot — prefer Go integration test.

- [ ] **Step 3: Commit** `test(bpf): cover UDP sendmsg path`.

---

### Task 12: BPF tranche **D** — DNS / TLS visibility counters (lightweight)

**Goal:** Add **count metrics** (maps or userspace counters) for “DNS sniff sample count” / “TLS ClientHello count” exported similarly to Task 10 — **only if** BPF side already emits events; avoid new unstable kprobes.

**Files:**
- Possibly `bpf/trace_dns.bpf.c`, `internal/agent/agent_linux.go`, `internal/telemetry/*`

- [ ] **Step 1: Vault search** `knowledge/raw/docs-ebpf-io.md` for program limits.

- [ ] **Step 2: Implement smallest counter increment in userspace** (preferred) based on ringbuf records already parsed.

- [ ] **Step 3: Tests + commit** `feat(telemetry): dns/tls visibility counters`.

---

### Task 13: BPF tranche **B** — IPv6 cgroup enforce (**product gate**)

**Goal:** Only start if README/product explicitly expands scope; otherwise **skip** and record in `knowledge/reports/` **“deferred per v1 IPv4 scope.”**

**Files (if enabled):**
- `bpf/trace_enforce.bpf.c` (`SEC("cgroup/connect6")` / `sendmsg6`), `internal/policy/policy.go`, `README.md`, `SECURITY.md`

- [ ] **Step 1: Design approval checkpoint** — do **not** code until `SECURITY.md` + README updated with IPv6 semantics.

---

### Task 14: BPF tranche **C** — cgroup attach / job scoping validation

**Goal:** Document and test that enforce attaches to expected cgroup for GitHub Actions job (reuse `internal/cgroup/path_linux.go`).

**Files:**
- `internal/cgroup/path_linux.go`, tests, `knowledge/wiki/github-actions-networking.md` stub links.

---

### Task 15: Adversarial honesty — docs sync (no magic claims)

**Files:**
- `SECURITY.md`, `.github/design/2026-04-19-coldstep-gha-ebpf-mitigations-design.md`

- [ ] **Step 1: Diff check**

Ensure **no sentence** promises universal syscall coverage; align language with Doyensec / Trail of Bits / Gregg citations already in design doc.

- [ ] **Step 2: Vault**

`knowledge/raw/` stubs already exist for those URLs — add **`reports/`** if threat model changes.

---

### Task 16: Program closure — merge readiness

- [ ] **Step 1: Full Docker CI mirror** (aggregate)

Run Task 4 docker block + Task 3 scripts + Task 6 npm in sequence.

- [ ] **Step 2: Write `knowledge/reports/YYYY-MM-DD-program-milestone-complete.md`** summarizing merged tasks, CI run links, open backlog.

- [ ] **Step 3: Git**

Open PR to **`dev`** with signed commits; **do not push `main`** unless policy allows.

---

## Plan self-review (spec coverage)

| Requirement | Task coverage |
| ----------- | ------------- |
| Fix failing CI jobs | Tasks 2–9 |
| eBPF capability expansion | Tasks 10–14 |
| Hardening vs known attacks (honest + telemetry) | Tasks 10–12, 15 |
| Second brain usage | Tasks 1–2, every task “Vault” step |
| Bleeding edge / govulncheck | Task 9 |
| No placeholder tasks | No `TBD`; deferred IPv6 explicit in Task 13 |

**Placeholder scan:** None intentional — Task 13 explicitly gates IPv6.

---

## Execution handoff

**Plan complete and saved to** `.github/design/2026-04-20-coldstep-ci-ebpf-second-brain-program-implementation-plan.md`.

**Two execution options:**

1. **Subagent-driven (recommended)** — dispatch a fresh subagent per task (or per stream), review between tasks.
2. **Inline execution** — run tasks in this session using **executing-plans**, batching with checkpoints.

**Which approach?**
