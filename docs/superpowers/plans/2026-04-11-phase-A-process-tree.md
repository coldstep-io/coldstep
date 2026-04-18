# Phase A — Process tree (fork lineage + digest) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional **parent→child process lineage** for GitHub-hosted `ubuntu-latest` by attaching **`sched:sched_process_fork`**, emitting **`proc_fork`** JSONL rows, maintaining a **capped in-memory edge list**, and rendering a bounded **“Process tree (recent)”** section in `.nightstalker-detect.md`, gated by **`NIGHTSTALKER_FEATURE_GATES=proc_tree=1`** so default runs stay unchanged.

**Repository state (2026-04-11):** Phase A is **implemented** on `main` (config gates, telemetry, proctree, digest, agent wiring, integration test, nightstalker-demo `feature-gates: proc_tree=1`). The optional **git worktree** prerequisite below was **skipped** in favor of landing on `main`. **BPF attach:** use **`SEC("raw_tp/sched_process_fork")`** and **`link.AttachRawTracepoint`** (name `sched_process_fork`): GitHub **Azure** `ubuntu-latest` vmlinux BTF often **omits** `parent_comm` / `child_comm` on `trace_event_raw_sched_process_fork`, so a plain **`tp/sched/sched_process_fork`** program that reads those fields **fails CI clang**; raw tracepoint args are **`struct task_struct *` parent/child** and match **`TP_PROTO`** reliably.

**Architecture:** Introduce a small **CO-RE BPF** program (`bpf/trace_fork.bpf.c`) with its own **ringbuf** and **`internal/bpf/tracefork`** bpf2go package (same pattern as `traceexec` / `tracedns`). The Linux agent (`internal/agent/agent_linux.go`) **conditionally loads and attaches** fork tracing when the feature gate is on, decodes ringbuf samples into **`telemetry.ProcForkEvent`**, appends JSONL under the existing mutex + `telemetry.SeqGen`, and feeds a pure-Go **`internal/proctree`** reducer that turns **edges + exec identities** into **pre-rendered markdown lines** for `report.BuildDetectMarkdown`. **Detect-only** remains default; fork attach failure must **degrade** (BPF status row + continue) like DNS/syscall paths, never fail `Run` in detect mode.

**Tech Stack:** Go 1.24.x, `cilium/ebpf` (**`link.AttachRawTracepoint`** for fork, `ringbuf.Reader`), `bpf2go`, **clang** `-Wall -Werror`, repo **`bpf/vmlinux.h`** from **`scripts/build-agent-linux.sh`**, GitHub Actions **`ubuntu-latest`**, optional **`bash scripts/docker-ubuntu-test.sh`** for Linux parity on dev machines.

**Specification source:** [`docs/superpowers/specs/2026-04-11-extended-runtime-security-design.md`](../specs/2026-04-11-extended-runtime-security-design.md) §3.1–§3.3, §4 Phase A, §8 (one plan per phase).

---

## File map (create / modify / responsibility)

| Path | Responsibility |
|------|----------------|
| `internal/config/featuregates.go` | Parse `NIGHTSTALKER_FEATURE_GATES` (`k=v` comma-separated, case-insensitive keys, trim whitespace). Export `ParseFeatureGates(raw string) map[string]string` and `FeatureGateEnabled(m map[string]string, key string) bool` treating `1`, `true`, `yes`, `on` as enabled. |
| `internal/config/config.go` | Add `FeatureGates map[string]string` to `Config`; in `LoadFromEnv`, populate from `os.Getenv("NIGHTSTALKER_FEATURE_GATES")`. |
| `internal/config/config_test.go` | Table tests for gate parsing + `LoadFromEnv` sees gates. |
| `bpf/trace_fork.bpf.c` | BPF: **`SEC("raw_tp/sched_process_fork")`**, ringbuf `fork_events`; read **`pid`** and **`comm`** from **`struct task_struct *`** args (`ctx->args[0]` parent, `ctx->args[1]` child) via **CO-RE** / `bpf_probe_read_kernel_str` on `comm` (see **Repository state** above—avoid `tp/` + `trace_event_raw_sched_process_fork` comm fields on Azure BTF). |
| `internal/bpf/tracefork/gen.go` | `//go:generate bpf2go ... Tracefork ../../../bpf/trace_fork.bpf.c` mirroring `internal/bpf/traceexec/gen.go` cflags include paths. |
| `scripts/build-agent-linux.sh` | Add `go generate ./internal/bpf/tracefork/...` after other bpf2go lines. |
| `internal/telemetry/event.go` | Add `ProcForkEvent` JSONL type (`"proc_fork"`). Optionally extend `MetaEvent` with `Capabilities map[string]bool` (omit when empty). Keep **`SchemaVersion` at 2** unless you intentionally break consumers (umbrella allows capabilities without bump). |
| `internal/telemetry/event_test.go` | Round-trip / `EventType` coverage for `proc_fork` line. |
| `internal/telemetry/telemetry.go` | Extend `Summary` with `ProcForkEvents int` `json:"proc_fork_events,omitempty"` (or non-omitempty zero default). |
| `internal/proctree/summary.go` | Pure Go: `type Edge struct { ParentTGID, ChildTGID uint32; ParentComm, ChildComm string }`, `type ExecIdentity struct { Comm, Exe string }`, `func FormatForestLines(edges []Edge, exec map[uint32]ExecIdentity, maxLines int) []string` building **text trees** with `└─` / `├─`, **node cap** and **“+N more”** when truncated. |
| `internal/proctree/summary_test.go` | Table-driven tests: single edge, chain A→B→C, diamond (two parents impossible—duplicate child edges last-wins), empty exec map, truncation at `maxLines`. |
| `internal/report/digest.go` | Extend `DigestInput` with `ProcForkTotal int`, `ProcessTreeLines []string`, `TruncatedProcessTree bool`, `ProcForkDegraded bool`, `ProcForkReaderErrors int`. Extend `BuildDetectMarkdown` KPI table with `| **proc_fork** | … |` **only when** `ProcForkTotal > 0 || ProcForkDegraded || len(ProcessTreeLines) > 0` (avoid noisy zero row when feature off). Add `<details>` **Process tree (recent)** after Exec section, with empty-state row mirroring UDP pattern (`degraded hook` / `reader errors (k)` / `no events`). |
| `internal/report/digest_test.go` | Golden substrings for new KPI + section + truncation footnote `proc_fork` / `process tree`. |
| `internal/agent/agent_linux.go` | Wire fork BPF load/attach behind gate; `readForkRing`; bounded edge buffer; extend `runStats`, `buildDigestInput`, `rowBuffer` or parallel buffer; extend `bpfSt` slice ordering **documented** in `agent_linux_test.go`; `defer` close fork link/reader; extend shutdown `BuildMeta` capabilities map when enabled. |
| `internal/agent/agent_linux_test.go` | Update expected BPF status names/counts if `bpfSt` layout changes. |
| `internal/agent/agent_integration_test.go` | New `TestRun_ProcForkJSONLWhenFeatureGate` (root, `NIGHTSTALKER_FEATURE_GATES=proc_tree=1`, spawn child, assert JSONL contains `"type":"proc_fork"`). |
| `.github/workflows/nightstalker-demo.yml` | On `uses: ./` for `guard` job, set `with: feature-gates: proc_tree=1`. After egress / before stop, run a **deterministic** spawn: `bash -c '/bin/true'` (or `bash -lc true`). In verify step, `grep -q '"type":"proc_fork"'` on `.nightstalker-events.jsonl` and `grep -qi 'process tree'` on `.nightstalker-detect.md`. |

**Explicitly out of scope for this plan file:** Phase B–E (FS, integrity, memory LSM, hardening rules), **enforce** behavior changes, **Windows** agent paths, **IPv6** / non-`ubuntu-latest` runners, perfect **PID namespace** attribution (document “best-effort” in digest footnote only).

---

## Prerequisite: dedicated git worktree (recommended)

The umbrella spec and writing-plans skill recommend isolating large BPF work.

- [x] **Step 1: Create worktree** (optional — **skipped** on `main` for Phase A; keep commands below for future large BPF work.)

```bash
cd /path/to/nightstalker
git fetch origin
git worktree add ../nightstalker-phase-a-process-tree -b phase-a-process-tree origin/main
cd ../nightstalker-phase-a-process-tree
```

Expected: worktree exists on branch `phase-a-process-tree`.

---

### Task 1: Feature gate parser (pure Go, TDD)

**Files:**
- Create: `internal/config/featuregates.go`
- Test: `internal/config/config_test.go` (append tests; if you prefer isolation, create `internal/config/featuregates_test.go` instead)

- [x] **Step 1: Write failing tests** (append to `internal/config/config_test.go`)

```go
func TestParseFeatureGates(t *testing.T) {
	t.Parallel()
	m := ParseFeatureGates(" proc_tree=1 , FS_EVENTS=false ")
	if got := m["proc_tree"]; got != "1" {
		t.Fatalf("proc_tree: got %q", got)
	}
	if got := m["fs_events"]; got != "false" {
		t.Fatalf("fs_events: got %q", got)
	}
	if FeatureGateEnabled(m, "PROC_TREE") != true {
		t.Fatalf("PROC_TREE should enable")
	}
	if FeatureGateEnabled(m, "proc_tree") != true {
		t.Fatalf("proc_tree should enable")
	}
	if FeatureGateEnabled(m, "missing") {
		t.Fatalf("missing gate should be disabled")
	}
}

func TestParseFeatureGates_InvalidPairsIgnored(t *testing.T) {
	t.Parallel()
	m := ParseFeatureGates("nonsense,foo=bar=qux,,=nokey,noval=")
	// Parser skips segments without '=', keys empty after trim, and values empty after trim.
	if len(m) != 1 || m["foo"] != "bar=qux" {
		t.Fatalf("unexpected map: %#v", m)
	}
}
```

- [x] **Step 2: Run tests (expect compile failure)**

Run (Linux or Git Bash on Windows — repo unit tests are pure Go):

```bash
cd /path/to/repo
go test ./internal/config/... -count=1
```

Expected: **FAIL** build — `undefined: ParseFeatureGates`.

- [x] **Step 3: Implement parser**

Create `internal/config/featuregates.go`:

```go
package config

import "strings"

// ParseFeatureGates parses NIGHTSTALKER_FEATURE_GATES: comma-separated k=v pairs.
// Keys are lowercased; values preserve case (trimmed). Invalid segments are skipped.
func ParseFeatureGates(raw string) map[string]string {
	out := make(map[string]string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			continue
		}
		out[strings.ToLower(k)] = v
	}
	return out
}

// FeatureGateEnabled reports whether key is enabled (case-insensitive key).
// Truthy values: 1, true, yes, on (case-insensitive).
func FeatureGateEnabled(m map[string]string, key string) bool {
	if len(m) == 0 {
		return false
	}
	v, ok := m[strings.ToLower(strings.TrimSpace(key))]
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
```

- [x] **Step 4: Run tests (expect pass)**

```bash
go test ./internal/config/... -count=1
```

Expected: **PASS**.

- [x] **Step 5: Commit**

```bash
git add internal/config/featuregates.go internal/config/config_test.go
git commit -m "config: parse NIGHTSTALKER_FEATURE_GATES for proc_tree gate"
```

---

### Task 2: Wire `FeatureGates` into `Config` + `LoadFromEnv`

**Files:**
- Modify: `internal/config/config.go` (add field on `Config` struct near other env-backed fields)
- Modify: `internal/config/config.go` (`LoadFromEnv` return struct)
- Test: `internal/config/config_test.go`

- [x] **Step 1: Write failing test**

```go
func TestLoadFromEnv_FeatureGates(t *testing.T) {
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("NIGHTSTALKER_ALLOWED_HOSTS", "")
	t.Setenv("NIGHTSTALKER_ALLOWED_IPS", "")
	t.Setenv("NIGHTSTALKER_FEATURE_GATES", "proc_tree=1,other=0")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !FeatureGateEnabled(cfg.FeatureGates, "proc_tree") {
		t.Fatalf("expected proc_tree enabled")
	}
	if FeatureGateEnabled(cfg.FeatureGates, "other") {
		t.Fatalf("expected other disabled")
	}
}
```

- [x] **Step 2: Run test (expect fail)**

```bash
go test ./internal/config/... -run TestLoadFromEnv_FeatureGates -count=1
```

Expected: **FAIL** — unknown field `FeatureGates` or gate not populated.

- [x] **Step 3: Implement**

In `internal/config/config.go`:

```go
type Config struct {
	// ... existing fields ...
	FeatureGates map[string]string
}
```

In `LoadFromEnv()` before `return Config{...}`:

```go
gates := ParseFeatureGates(os.Getenv("NIGHTSTALKER_FEATURE_GATES"))
```

Add `FeatureGates: gates,` to the returned `Config{...}`.

- [x] **Step 4: Run test (expect pass)**

```bash
go test ./internal/config/... -run TestLoadFromEnv_FeatureGates -count=1
```

Expected: **PASS**.

- [x] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "config: load feature gates from env into Config"
```

---

### Task 3: Telemetry — `ProcForkEvent`, meta capabilities, summary counter

**Files:**
- Modify: `internal/telemetry/event.go`
- Modify: `internal/telemetry/telemetry.go`
- Modify: `internal/telemetry/meta_linux.go` (only if you add `Capabilities` to `MetaEvent` and need constructor help — optional)
- Test: `internal/telemetry/event_test.go`

- [x] **Step 1: Write failing test** (append `internal/telemetry/event_test.go`)

```go
func TestProcForkEventJSONLRoundTrip(t *testing.T) {
	t.Parallel()
	line := `{"type":"proc_fork","ts":"2026-04-11T00:00:00Z","seq":7,"parent_pid":1,"child_pid":42,"parent_comm":"bash","child_comm":"true","note":"best-effort tgid"}` + "\n"
	if got := EventType([]byte(line)); got != "proc_fork" {
		t.Fatalf("EventType=%q", got)
	}
}

func TestMetaCapabilitiesOmitEmpty(t *testing.T) {
	t.Parallel()
	raw := `{"type":"meta","schema_version":2,"ts":"t","agent_version":"v","kernel_release":"k","github":{},"bpf":[],"capabilities":{"proc_tree":true}}` + "\n"
	var m MetaEvent
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if !m.Capabilities["proc_tree"] {
		t.Fatalf("capabilities: %#v", m.Capabilities)
	}
}
```

Add to `MetaEvent` in `event.go`:

```go
Capabilities map[string]bool `json:"capabilities,omitempty"`
```

Add struct:

```go
// ProcForkEvent is one JSONL record for sched_process_fork (parent/child IDs are best-effort TGID on typical kernels).
type ProcForkEvent struct {
	Type        string `json:"type"` // "proc_fork"
	TS          string `json:"ts"`
	Seq         uint64 `json:"seq"`
	ParentPID   uint32 `json:"parent_pid"` // kernel-reported parent id (see note)
	ChildPID    uint32 `json:"child_pid"`  // kernel-reported child id
	ParentComm  string `json:"parent_comm"`
	ChildComm   string `json:"child_comm"`
	Note        string `json:"note,omitempty"`
}
```

Extend `Summary` in `telemetry.go`:

```go
ProcForkEvents int `json:"proc_fork_events,omitempty"`
```

- [x] **Step 2: Run tests (expect fail on MetaCapabilities if field missing)**

```bash
go test ./internal/telemetry/... -count=1
```

Expected: **FAIL** compile on `Capabilities` / `MetaEvent` until fields added.

- [x] **Step 3: Implement** the structs/fields above in `event.go` and `telemetry.go`.

- [x] **Step 4: Run tests (expect pass)**

```bash
go test ./internal/telemetry/... -count=1
```

Expected: **PASS**.

- [x] **Step 5: Commit**

```bash
git add internal/telemetry/event.go internal/telemetry/telemetry.go internal/telemetry/event_test.go
git commit -m "telemetry: proc_fork JSONL type and summary counter"
```

---

### Task 4: BPF — `sched_process_fork` → ringbuf

**Files:**
- Create: `bpf/trace_fork.bpf.c`
- Create: `internal/bpf/tracefork/gen.go`

**Implementation note (2026-04-11):** The **canonical source** is **`bpf/trace_fork.bpf.c`** on `main`: **`raw_tp/sched_process_fork`** + **`struct bpf_raw_tracepoint_args`** (`args[0]`/`args[1]` as `struct task_struct *`), **`BPF_CORE_READ(..., pid)`**, and **`bpf_probe_read_kernel_str`** on **`&parent->comm`** / **`&child->comm`**. Do **not** rely on **`trace_event_raw_sched_process_fork`** `parent_comm`/`child_comm` fields for CI: Azure BTF often omits them (clang error on `ubuntu-latest`).

- [x] **Step 1: Confirm tracepoint / task layout in BTF**

Run Linux build script once so `bpf/vmlinux.h` exists:

```bash
bash scripts/build-agent-linux.sh "$(pwd)"
grep -n "struct task_struct" bpf/vmlinux.h | head
```

Use this to validate **`task_struct`** fields used by the BPF program (`pid`, `comm`).

- [x] **Step 2: Add `bpf/trace_fork.bpf.c`**

See **`bpf/trace_fork.bpf.c`** in the repo (too long to duplicate here). Attach from Go with **`link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_fork", ...})`**.

- [x] **Step 3: Add `internal/bpf/tracefork/gen.go`**

```go
package tracefork

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -cc clang -no-strip -target bpfel,bpfeb -cflags "-O2 -g -Wall -Werror -I../../../bpf -I/usr/include/bpf" Tracefork ../../../bpf/trace_fork.bpf.c -- -I../../../bpf -I/usr/include/bpf
```

- [x] **Step 4: Run go generate (expect success on Linux with clang)**

```bash
bash scripts/build-agent-linux.sh "$(pwd)"
```

Expected: **exit 0**; `internal/bpf/tracefork/tracefork_bpfel.go` (and `bpfeb`) generated (gitignored objects may exist locally).

- [x] **Step 5: Commit C + gen stub**

```bash
git add bpf/trace_fork.bpf.c internal/bpf/tracefork/gen.go scripts/build-agent-linux.sh
git commit -m "bpf: add sched_process_fork tracepoint package (tracefork)"
```

---

### Task 5: Pure Go — `internal/proctree` forest formatter

**Files:**
- Create: `internal/proctree/summary.go`
- Create: `internal/proctree/summary_test.go`

- [x] **Step 1: Write failing tests** (`internal/proctree/summary_test.go`)

```go
package proctree

import "testing"

func TestFormatForestLines_SimpleChain(t *testing.T) {
	t.Parallel()
	edges := []Edge{
		{ParentTGID: 1, ChildTGID: 10, ParentComm: "bash", ChildComm: "sh"},
		{ParentTGID: 10, ChildTGID: 11, ParentComm: "sh", ChildComm: "true"},
	}
	exec := map[uint32]ExecIdentity{
		1:  {Comm: "bash", Exe: "/bin/bash"},
		10: {Comm: "sh", Exe: "/bin/sh"},
		11: {Comm: "true", Exe: "/usr/bin/true"},
	}
	lines := FormatForestLines(edges, exec, 20)
	if len(lines) < 2 {
		t.Fatalf("expected multiple lines: %#v", lines)
	}
	if lines[0] == "" {
		t.Fatalf("empty first line")
	}
}

func TestFormatForestLines_Truncates(t *testing.T) {
	t.Parallel()
	var edges []Edge
	for i := uint32(2); i <= 50; i++ {
		edges = append(edges, Edge{ParentTGID: 1, ChildTGID: i, ParentComm: "p", ChildComm: "c"})
	}
	lines := FormatForestLines(edges, map[uint32]ExecIdentity{}, 5)
	if len(lines) > 6 {
		t.Fatalf("expected truncation cap, got %d lines", len(lines))
	}
}
```

- [x] **Step 2: Run tests (expect fail)**

```bash
go test ./internal/proctree/... -count=1
```

Expected: **FAIL** — package not found.

- [x] **Step 3: Implement `internal/proctree/summary.go`**

Minimum viable algorithm (concrete reference implementation — replace with clearer code if you prefer, but keep exported names):

```go
package proctree

import (
	"fmt"
	"sort"
)

type Edge struct {
	ParentTGID uint32
	ChildTGID  uint32
	ParentComm string
	ChildComm  string
}

type ExecIdentity struct {
	Comm string
	Exe  string
}

// FormatForestLines renders up to maxLines human-readable tree lines.
// Edges later in the slice win for duplicate (parent,child) keys.
func FormatForestLines(edges []Edge, exec map[uint32]ExecIdentity, maxLines int) []string {
	if maxLines <= 0 {
		return nil
	}
	// Build adjacency list parent -> children (dedupe by child id).
	type pair struct{ p, c uint32 }
	seen := make(map[pair]struct{})
	var adj map[uint32][]uint32
	adj = make(map[uint32][]uint32)
	for _, e := range edges {
		p := e.ParentTGID
		c := e.ChildTGID
		if p == 0 || c == 0 {
			continue
		}
		pr := pair{p: p, c: c}
		if _, ok := seen[pr]; ok {
			continue
		}
		seen[pr] = struct{}{}
		adj[p] = append(adj[p], c)
	}
	for p := range adj {
		ch := adj[p]
		sort.Slice(ch, func(i, j int) bool { return ch[i] < ch[j] })
		adj[p] = ch
	}
	// Roots: nodes that appear as parent but never as child in this edge set.
	childSet := make(map[uint32]struct{})
	for _, e := range edges {
		if e.ChildTGID != 0 {
			childSet[e.ChildTGID] = struct{}{}
		}
	}
	var roots []uint32
	for p := range adj {
		if _, ok := childSet[p]; !ok {
			roots = append(roots, p)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })

	var out []string
	var dfs func(p uint32, depth int, prefix string)
	dfs = func(p uint32, depth int, prefix string) {
		if len(out) >= maxLines {
			return
		}
		id := exec[p]
		label := fmt.Sprintf("%s(%d)", id.Comm, p)
		if id.Comm == "" {
			label = fmt.Sprintf("?(%d)", p)
		}
		exe := ""
		if id.Exe != "" {
			exe = " " + id.Exe
		}
		out = append(out, prefix+label+exe)
		if len(out) >= maxLines {
			return
		}
		ch := adj[p]
		for i, c := range ch {
			if len(out) >= maxLines {
				return
			}
			branch := "├─ "
			if i == len(ch)-1 {
				branch = "└─ "
			}
			nextPrefix := prefix
			if depth > 0 {
				nextPrefix = prefix + "   "
			}
			// Ensure child identity exists minimally from edge comms.
			if _, ok := exec[c]; !ok {
				exec[c] = ExecIdentity{Comm: edgeChildComm(edges, p, c)}
			}
			dfs(c, depth+1, nextPrefix+branch)
		}
	}

	// Seed exec comms from edges if missing.
	for _, e := range edges {
		if _, ok := exec[e.ParentTGID]; !ok && e.ParentComm != "" {
			exec[e.ParentTGID] = ExecIdentity{Comm: e.ParentComm}
		}
		if _, ok := exec[e.ChildTGID]; !ok && e.ChildComm != "" {
			exec[e.ChildTGID] = ExecIdentity{Comm: e.ChildComm}
		}
	}

	for _, r := range roots {
		dfs(r, 0, "")
		if len(out) >= maxLines {
			break
		}
	}
	if len(out) == 0 && len(edges) > 0 {
		out = append(out, "(unable to derive roots from sampled edges)")
	}
	return out
}

func edgeChildComm(edges []Edge, p, c uint32) string {
	for i := len(edges) - 1; i >= 0; i-- {
		e := edges[i]
		if e.ParentTGID == p && e.ChildTGID == c {
			return e.ChildComm
		}
	}
	return ""
}
```

**Note:** The recursive `dfs` mutates the `exec` map when filling missing children — copy the map at call site in the agent if immutability matters; in tests pass a disposable map.

- [x] **Step 4: Run tests (expect pass)**

```bash
go test ./internal/proctree/... -count=1
```

Expected: **PASS** (adjust test assertions if you tweak rendering).

- [x] **Step 5: Commit**

```bash
git add internal/proctree/summary.go internal/proctree/summary_test.go
git commit -m "proctree: format fork edges into bounded markdown lines"
```

---

### Task 6: Digest — KPI + “Process tree (recent)” section

**Files:**
- Modify: `internal/report/digest.go`
- Modify: `internal/agent/agent_linux.go` (`buildDigestInput` and callers — in **Task 7** you wire data; this task can use zero values first)
- Test: `internal/report/digest_test.go`

- [x] **Step 1: Write failing test** (append `internal/report/digest_test.go`)

```go
func TestBuildDetectMarkdown_ProcessTreeSection(t *testing.T) {
	md := BuildDetectMarkdown(DigestInput{
		BPF:               []telemetry.BPFStatus{{Name: "sched_process_fork", OK: true}},
		ExecTotal:         0,
		ProcForkTotal:     2,
		ProcessTreeLines:  []string{"bash(1) /bin/bash", "└─ true(2) /usr/bin/true"},
		MaxRowsPerSection: 50,
	})
	if !strings.Contains(md, "| **proc_fork** | 2 |") {
		t.Fatalf("missing proc_fork KPI:\n%s", md)
	}
	if !strings.Contains(md, "Process tree (recent)") {
		t.Fatalf("missing section title:\n%s", md)
	}
	if !strings.Contains(md, "bash(1)") {
		t.Fatalf("missing tree line:\n%s", md)
	}
}
```

Extend `DigestInput` in `digest.go` with:

```go
ProcForkTotal         int
ProcessTreeLines      []string
TruncatedProcessTree  bool
ProcForkDegraded      bool
ProcForkReaderErrors  int
```

Implement in `BuildDetectMarkdown`:
- After exec KPI rows, if `ProcForkTotal > 0 || ProcForkDegraded || len(ProcessTreeLines) > 0`, append KPI row `proc_fork`.
- After `writeExec()` (see `digest.go` around the `writeExec := func()` / `writeExec()` call site), add `writeProcessTree()` mirroring `writeUDP` empty-reason style.

Helper for empty reason:

```go
func procTreeEmptyReason(in DigestInput) string {
	if in.ProcForkDegraded {
		return "degraded hook"
	}
	if in.ProcForkReaderErrors > 0 {
		return fmt.Sprintf("reader errors (%d)", in.ProcForkReaderErrors)
	}
	return "no events"
}
```

- [x] **Step 2: Run test (expect fail)**

```bash
go test ./internal/report/... -run TestBuildDetectMarkdown_ProcessTreeSection -count=1
```

Expected: **FAIL** (missing fields or strings).

- [x] **Step 3: Implement** struct fields + markdown writers + footnote key `proc_fork` in truncation list alongside exec/tcp/udp/http.

- [x] **Step 4: Run full package tests**

```bash
go test ./internal/report/... -count=1
```

Expected: **PASS**.

- [x] **Step 5: Commit**

```bash
git add internal/report/digest.go internal/report/digest_test.go
git commit -m "report: digest KPI and section for process tree"
```

---

### Task 7: Agent wiring — load fork BPF, read ring, JSONL, stats, digest input

**Files:**
- Modify: `internal/agent/agent_linux.go` (imports, `runStats`, `buildDigestInput`, `Run`, new helpers)
- Modify: `internal/agent/agent_linux_test.go` (BPF table expectations if present)
- Modify: `internal/telemetry/meta_linux.go` OR inline in `agent_linux.go` after `BuildMeta` — set `Capabilities["proc_tree"]=true` when gate enabled and fork BPF attached successfully

**Concrete wiring checklist:**

1. Import `github.com/shermanatoor/nightstalker/internal/bpf/tracefork` and `github.com/shermanatoor/nightstalker/internal/proctree`.
2. Extend `runStats` with `procForkN int` and `addProcFork()` method; include in `snapshotSummary` mapping to `telemetry.Summary.ProcForkEvents`.
3. Add `forkEdgeBuffer` struct (mutex, `max int`, `edges []proctree.Edge`) with `add(parent, child uint32, pcomm, ccomm string)` keeping last `max` edges via same `trimRing` pattern as `rowBuffer`.
4. In `Run`, after successful exec attach block (`internal/agent/agent_linux.go` where `execLnk` attaches), if `config.FeatureGateEnabled(cfg.FeatureGates, "proc_tree")`:
   - `LoadTraceforkObjects`, `link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_fork", Program: objs.HandleSchedProcessFork})`, `ringbuf.NewReader(objs.ForkEvents)`.
   - On **any** error: set `bpfSt` append or insert row `{Name: "sched_process_fork", OK: false, Detail: ...}`, **log Info**, continue (detect must run).
   - On success: append `telemetry.BPFStatus{Name: "sched_process_fork", OK: true}` — **grow `bpfSt` slice** from 3 to 4 elements; update **all** tests that assume length 3.
5. Add `readForkRing(ctx, cfg, rd, stats, edgesBuf, seq, jsonlMu)` modeled on `readExecRing` (`internal/agent/agent_linux.go` starting ~557). Decode binary:

```go
type forkEventWire struct {
	ParentPID  uint32
	ChildPID   uint32
	ParentComm [16]byte
	ChildComm  [16]byte
}
```

JSONL:

```go
evOut := telemetry.ProcForkEvent{
	Type: "proc_fork", TS: ts, Seq: n,
	ParentPID: ev.ParentPID, ChildPID: ev.ChildPID,
	ParentComm: commP, ChildComm: commC,
	Note:       "best-effort pid namespace; parent/child are kernel fork trace ids",
}
```

6. `buildDigestInput` (`internal/agent/agent_linux.go` search `func buildDigestInput`): pass `ProcForkTotal: stats.procForkN` (expose via new `runStats` accessor like `counts()`), build `ProcessTreeLines` via `proctree.FormatForestLines(edgesSnapshot, execIdentityMap, maxRows)` where `execIdentityMap` is built by scanning `rows.snapshot()` exec slice into `map[uint32]proctree.ExecIdentity{pid -> {Comm, Exe}}`.

7. Shutdown meta: when gate enabled,

```go
meta, err := telemetry.BuildMeta(agentVersionString(), bpfSt)
if cfg != nil { /* pseudo */ }
if FeatureGateEnabled(cfg.FeatureGates, "proc_tree") {
	if meta.Capabilities == nil {
		meta.Capabilities = map[string]bool{}
	}
	meta.Capabilities["proc_tree"] = true
}
```

Use `config.FeatureGateEnabled` from the `config` package (same function as Task 1 or unexported wrapper — **do not duplicate** string logic in agent).

8. `go func` wg: add fork reader goroutine; on `runCtx.Done()` close fork reader like exec.

- [x] **Step 1: Unit compile check (no integration)**

```bash
go build -o /dev/null ./cmd/ci-runtime-guard
```

Expected: **FAIL** until imports and types resolve.

- [x] **Step 2: Implement** per checklist (single focused commit is acceptable, or split Task 7a/7b if you prefer smaller commits).

- [x] **Step 3: Update `internal/agent/agent_linux_test.go`** expectations for `bpfSt` length and any snapshot structs referencing `telemetry.BPFStatus` length **3** → **4** when fork gate defaults off **keep length 3**; when testing gate on, expect fork row present. Prefer **conditional** assertions based on gate env in test.

- [x] **Step 4: Linux compile**

```bash
GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/ci-runtime-guard
```

Expected: **PASS** (on dev machine cross-compile is enough for compile; BPF objects are `linux` tagged).

- [x] **Step 5: Commit**

```bash
git add internal/agent/agent_linux.go internal/agent/agent_linux_test.go internal/telemetry/meta_linux.go
git commit -m "agent: optional sched_process_fork stream behind proc_tree gate"
```

---

### Task 8: Integration test — `proc_fork` JSONL when gate enabled

**Files:**
- Modify: `internal/agent/agent_integration_test.go`

- [x] **Step 1: Add test**

```go
func TestRun_ProcForkJSONLWhenFeatureGate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	dir := t.TempDir()
	summary := filepath.Join(dir, "summary.md")
	if err := os.WriteFile(summary, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, "events.jsonl")
	detect := filepath.Join(dir, "detect.md")

	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("NIGHTSTALKER_ALLOWED_HOSTS", "")
	t.Setenv("NIGHTSTALKER_ALLOWED_IPS", "")
	t.Setenv("CI_GUARD_MODE", "detect")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	t.Setenv("NIGHTSTALKER_EVENTS_LOG", events)
	t.Setenv("NIGHTSTALKER_DETECT_LOG", detect)
	t.Setenv("NIGHTSTALKER_FEATURE_GATES", "proc_tree=1")

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg) }()

	time.Sleep(400 * time.Millisecond)

	// Deterministic child process.
	if err := exec.Command("bash", "-c", "true").Run(); err != nil {
		t.Fatal(err)
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
	if !bytes.Contains(b, []byte(`"type":"proc_fork"`)) {
		t.Fatalf("expected proc_fork in jsonl:\n%s", string(b))
	}
}
```

- [x] **Step 2: Run integration test on Linux CI / Docker only**

```bash
bash scripts/docker-ubuntu-test.sh
```

Expected: with `NIGHTSTALKER_INTEGRATION=1` per repo docs, or local `sudo` on Linux runner, **PASS**. On Windows host without Docker: **skip** documenting that CI is authoritative.

- [x] **Step 3: Commit**

```bash
git add internal/agent/agent_integration_test.go
git commit -m "test(integration): assert proc_fork JSONL when feature gate on"
```

---

### Task 9: nightstalker-demo — enable gate + grep `proc_fork` + digest section

**Files:**
- Modify: `.github/workflows/nightstalker-demo.yml`

- [x] **Step 1: Edit `uses: ./` step under `guard` job**

Add:

```yaml
        with:
          feature-gates: proc_tree=1
```

(Indentation: two spaces under `uses`.)

- [x] **Step 2: After `Egress simulation` step commands**, append a spawn line:

```bash
          bash -c '/bin/true'
```

- [x] **Step 3: In `Verify nightstalker-demo egress in detect log`**, after exec path assertion, add:

```bash
          grep -q '"type":"proc_fork"' "$j" || { echo "expected proc_fork JSONL when proc_tree gate enabled"; exit 1; }
          grep -qi 'process tree' "$f" || { echo "expected process tree section in digest"; exit 1; }
```

- [x] **Step 4: Commit**

```bash
git add .github/workflows/nightstalker-demo.yml
git commit -m "ci(nightstalker-demo): assert proc_fork stream with proc_tree gate"
```

---

### Task 10: UTF-8 + formatting gates (repo policy)

- [x] **Step 1: Run UTF-8 assert**

```bash
python scripts/assert_utf8_text.py
```

Expected: **exit 0**.

- [x] **Step 2: gofmt + vet + unit tests (Linux-shaped)**

```bash
bash scripts/docker-ubuntu-test.sh
```

Expected: **exit 0** (or minimum: `gofmt -l` empty, `go test ./...` on Linux).

- [x] **Step 3: Commit** only if fixes were required.

```bash
git add -A
git commit -m "chore: gofmt and utf8 after process tree phase A"
```

---

## Self-review (plan quality)

**1. Spec coverage (umbrella Phase A + §3):**

| Spec item | Plan task |
|-----------|-----------|
| `sched_process_fork` hook | Task 4 (BPF), Task 7 (attach) |
| Merge with exec, caps/TTL | Task 5–7 (edge buffer + exec map + formatter caps) |
| JSONL `proc_fork` | Task 3, 7 |
| Digest “Process tree (recent)” | Task 6 |
| `feature-gates` (`proc_tree=1`) | Task 1–2, 7, 9 |
| Rate limits / explicit degraded | Task 6 empty reasons + `runStats` reader error counters (wire `readForkRing` warnings like exec) |
| meta capabilities / schema | Task 3 capabilities field (no forced schema bump) |
| nightstalker-demo exit criteria | Task 8–9 |
| **Not in this plan:** cgroup-scoped rollups, `proc_tree` periodic aggregate rows — add follow-up task file if product wants `proc_tree` summary JSONL type |

**2. Placeholder scan:** No `TBD` / `TODO` / generic “add tests” without code / “similar to Task N” — gaps called out explicitly in table above.

**3. Type consistency:** `ProcForkEvent` fields `parent_pid` / `child_pid` match JSONL test; `DigestInput` uses `ProcForkTotal` / `ProcessTreeLines` consistently; `telemetry.Summary` uses `ProcForkEvents` (agent must populate same name as json tag).

---

## Plan complete and saved to `docs/superpowers/plans/2026-04-11-phase-A-process-tree.md`. Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**

If **Subagent-Driven** is chosen: **REQUIRED SUB-SKILL:** superpowers:subagent-driven-development (fresh subagent per task + two-stage review).

If **Inline Execution** is chosen: **REQUIRED SUB-SKILL:** superpowers:executing-plans (batch execution with checkpoints for review).
