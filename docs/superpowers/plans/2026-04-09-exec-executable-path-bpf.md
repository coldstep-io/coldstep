# Exec executable path (sched_process_exec filename) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the `sched_process_exec` BPF program and Go agent so exec events carry a **bounded UTF-8 executable path** read from the tracepoint’s dynamic `filename` field (not only `bpf_get_current_comm`), surfaced in JSONL and the job-summary digest.

**Repository state (2026-04-12):** **`exe`** on exec JSONL, digest column, **`__data_loc_filename`** handling in **`bpf/trace_exec.bpf.c`**, integration + nightstalker-demo assertions are **shipped on `main`**. This plan is **complete**.

**Architecture:** Keep **`SEC("tp/sched/sched_process_exec")`**. Cast `ctx` to `struct trace_event_raw_sched_process_exec` from `bpf/vmlinux.h`, decode `__data_loc_filename` (Linux convention: **low 16 bits** = byte offset from start of `__data`, **high 16 bits** = length), then `bpf_probe_read_kernel_str` into a fixed `char[EXE_PATH_MAX]` in the ringbuf record. Userspace extends `binary.Read` layout, `telemetry.ExecEvent`, and digest rows. **No mocks of the kernel:** verification is **`go test -tags=integration ./internal/agent/...`** on a **real Linux + root + BPF** runner (existing pattern in `agent_integration_test.go`) plus **`go generate`** / **`docker-ubuntu-test.sh`** for compile gates.

**Tech stack:** C BPF (clang, `-Wall -Werror`), cilium/ebpf bpf2go, Go 1.24+, GitHub Actions `ubuntu-latest` / Docker `ubuntu:24.04` for generate + integration.

---

## File map

| File | Responsibility |
|------|------------------|
| `bpf/trace_exec.bpf.c` | Read `__data_loc_filename`, copy filename into ringbuf struct |
| `bpf/vmlinux.h` | Already defines `trace_event_raw_sched_process_exec` (no edit unless regenerating BTF dump) |
| `internal/bpf/traceexec/gen.go` | Unchanged directive; run `go generate` after C changes |
| `internal/agent/agent_linux.go` | `execEvent` struct, `readExecRing` decode, `ExecDigestRow` population |
| `internal/telemetry/event.go` | `ExecEvent` JSON field e.g. `Exe` / `filename` |
| `internal/report/digest.go` | Exec table column + `ExecDigestRow.Exe` + `sanitizeCell` |
| `internal/report/digest_test.go` | Digest contains exe column and sample row |
| `internal/telemetry/event_test.go` | JSON marshal includes new field |
| `internal/agent/agent_integration_test.go` | New test: real run, assert JSONL exec line has non-empty exe path |
| `.github/workflows/nightstalker-demo.yml` (optional hardening) | `grep` JSONL for `"exe":` or `"filename":` on non-empty value |

---

### Task 1: BPF — ringbuf layout + filename read

**Files:**
- Modify: `bpf/trace_exec.bpf.c`
- Test: `bash scripts/docker-ubuntu-test.sh` (or container with clang) — `go generate ./internal/bpf/traceexec/...` must succeed

- [x] **Step 1: Replace `struct exec_event` and handler body**

Use a fixed path buffer size **256** (`EXE_PATH_MAX`) to limit ringbuf pressure (kernel paths can be longer; truncation is acceptable and documented).

```c
#ifndef EXE_PATH_MAX
#define EXE_PATH_MAX 256
#endif

struct exec_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 exe_path[EXE_PATH_MAX];
};

SEC("tp/sched/sched_process_exec")
int handle_sched_process_exec(void *ctx)
{
	struct trace_event_raw_sched_process_exec *e;
	struct exec_event *ev;
	__u64 pt;
	__u32 loc;
	__u32 off, len;
	void *src;

	e = (struct trace_event_raw_sched_process_exec *)ctx;
	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	pt = bpf_get_current_pid_tgid();
	ev->tgid = (__u32)(pt >> 32);
	ev->tid = (__u32)pt;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	__builtin_memset(&ev->exe_path, 0, sizeof(ev->exe_path));

	loc = e->__data_loc_filename;
	off = loc & 0xFFFF;
	len = (loc >> 16) & 0xFFFF;
	if (len > 0 && off < 4096) {
		src = (void *)((__u64)e + sizeof(*e) + off);
		if (len >= EXE_PATH_MAX)
			len = EXE_PATH_MAX - 1;
		bpf_probe_read_kernel_str(ev->exe_path, len + 1, src);
	}

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
```

- [x] **Step 2: Regenerate loaders**

Run from repo root on Linux with clang + libbpf headers (same as CI):

```bash
go generate ./internal/bpf/traceexec/...
```

Expected: `internal/bpf/traceexec/traceexec_bpfel.go` (and `bpfeb` if generated) rebuild without clang errors.

- [x] **Step 3: Commit**

```bash
git add bpf/trace_exec.bpf.c internal/bpf/traceexec/
git commit -m "feat(bpf): capture sched_process_exec filename into ringbuf"
```

---

### Task 2: Go — decode ringbuf + JSONL + digest

**Files:**
- Modify: `internal/agent/agent_linux.go` (`execEvent`, `readExecRing`)
- Modify: `internal/telemetry/event.go` (`ExecEvent` — add `Exe string \`json:"exe"\``)
- Modify: `internal/report/digest.go` (`ExecDigestRow`, `writeExec` table header + row format)
- Modify: `internal/report/digest_test.go`, `internal/telemetry/event_test.go`

- [x] **Step 1: Extend `execEvent` and decode in `readExecRing`**

In `internal/agent/agent_linux.go`, align `execEvent` with C (little-endian, packed):

```go
type execEvent struct {
	TGID    uint32
	TID     uint32
	Comm    [16]byte
	ExePath [256]byte
}
```

After `binary.Read`, derive:

```go
exe := string(bytes.TrimRight(ev.ExePath[:], "\x00"))
```

Pass `exe` into `report.ExecDigestRow{..., Exe: exe}` and `telemetry.ExecEvent{..., Exe: exe}` (field name `Exe` in Go, JSON `exe`).

- [x] **Step 2: `ExecDigestRow` and markdown**

In `internal/report/digest.go`:

```go
type ExecDigestRow struct {
	TS       string
	PID      uint32
	ThreadID uint32
	Comm     string
	Exe      string // executable path (may be truncated in BPF)
}
```

Table header (example):

```go
b.WriteString("| Time (UTC) | PID (TGID) | TID | Comm | Executable (BPF-capped) |\n|:--|--:|--:|:-|:-|\n")
```

Row: use `sanitizeCell(r.Exe)` for the last column; apply `truncateUTF8ToMaxBytes` if you need a digest width cap (e.g. 120 bytes) before `sanitizeCell`.

- [x] **Step 3: Unit tests (no kernel mock — markdown/JSON only)**

`internal/telemetry/event_test.go` — extend or add:

```go
func TestExecEventJSON_IncludesExe(t *testing.T) {
	ev := ExecEvent{
		Type: "exec", TS: "2026-01-01T00:00:00Z", Seq: 1,
		PID: 1, TGID: 1, ThreadID: 2, Comm: "sh",
		Exe: "/bin/bash",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"exe":"/bin/bash"`)) {
		t.Fatalf("missing exe: %s", b)
	}
}
```

`internal/report/digest_test.go` — add `Exe` to sample `ExecRows` and assert substring e.g. `| `/bin/bash` |` or `Executable` in the markdown.

- [x] **Step 4: Run tests (Linux or Docker)**

```bash
docker run --rm -v "$PWD:/workspace" -w /workspace golang:1.24-bookworm bash -lc \
  'apt-get update -qq && apt-get install -y -qq libbpf-dev && go test ./internal/report/... ./internal/telemetry/... -count=1'
```

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/agent/agent_linux.go internal/telemetry/event.go internal/report/digest.go internal/report/digest_test.go internal/telemetry/event_test.go
git commit -m "feat(agent): surface exec exe path from BPF in JSONL and digest"
```

---

### Task 3: Integration test (real BPF, no mocks)

**Files:**
- Modify: `internal/agent/agent_integration_test.go`

- [x] **Step 1: Add `TestRun_ExecJSONLIncludesExePath`**

Build on `TestRun_DetectWritesSummary`: same env (`CI_GUARD_MODE=detect`, workspace temp dir), set **`NIGHTSTALKER_EVENTS_LOG`** to `filepath.Join(dir, "events.jsonl")` (verify exact env name in `internal/config/config.go` — use **`NIGHTSTALKER_EVENTS_LOG`** or whatever maps to `cfg.EventsLogPath`).

After `Run` returns, read `events.jsonl`, scan lines for `"type":"exec"` and assert the line contains **`"exe":`** with a non-empty value (e.g. `strings.Contains(line, `"exe":"/`)` or small `json.Unmarshal` into a struct with `Exe string`).

Trigger at least one exec: the existing `noop.sh` path is enough; the exe path should end with `sh` or similar.

Skeleton:

```go
func TestRun_ExecJSONLIncludesExePath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF load")
	}
	dir := t.TempDir()
	detect := filepath.Join(dir, "detect.md")
	events := filepath.Join(dir, "events.jsonl")
	// touch detect, set env GITHUB_WORKSPACE, NIGHTSTALKER_EVENTS_LOG=events,
	// GITHUB_STEP_SUMMARY, CI_GUARD_MODE=detect, clear allow lists
	// cfg := config.LoadFromEnv()
	// ctx, cancel := context.WithTimeout(..., 6*time.Second)
	// go Run(ctx, cfg); sleep; run noop.sh; cancel; <-errCh
	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"type":"exec"`)) {
			continue
		}
		if bytes.Contains(line, []byte(`"exe":"")) {
			continue
		}
		if bytes.Contains(line, []byte(`"exe":"`)) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no exec JSONL with non-empty exe:\n%s", b)
	}
}
```

- [x] **Step 2: Run integration tests only on Linux CI**

Local (privileged Docker):

```bash
NIGHTSTALKER_INTEGRATION=1 bash scripts/docker-ubuntu-test.sh
```

Or:

```bash
sudo go test -tags=integration ./internal/agent/... -count=1 -run TestRun_ExecJSONLIncludesExePath
```

Expected: PASS on `ubuntu-latest` with root.

- [x] **Step 3: Commit**

```bash
git add internal/agent/agent_integration_test.go
git commit -m "test(integration): assert exec JSONL carries non-empty exe from BPF"
```

---

### Task 4: nightstalker-demo optional assertion

**Files:**
- Modify: `.github/workflows/nightstalker-demo.yml`

- [x] **Step 1: After existing JSONL checks, require non-empty `exe` on at least one exec line**

Example (bash):

```bash
grep '"type":"exec"' "$j" | grep -q '"exe":"/' || { echo "expected exec JSONL with absolute exe path"; exit 1; }
```

- [x] **Step 2: Commit**

```bash
git add .github/workflows/nightstalker-demo.yml
git commit -m "ci(nightstalker-demo): assert exec JSONL includes exe path"
```

---

### Task 5: Schema / docs touch-up

**Files:**
- Modify: `README.md` (one sentence: exec JSONL includes `exe`, BPF-capped)
- Modify: `AGENTS.md` if you document JSONL fields (optional)

- [x] **Step 1: Document truncation** — BPF cap 256 bytes; digest may truncate further for markdown.

- [x] **Step 2: `SchemaVersion`** — additive `exe` field is backward compatible; **bump only** if you remove/rename fields (YAGNI: leave at `2` unless you have a consumer contract requiring bump).

- [x] **Step 3: Commit**

```bash
git add README.md AGENTS.md
git commit -m "docs: document exec exe path telemetry"
```

---

## Self-review

**1. Spec coverage**

| Requirement | Task |
|-------------|------|
| Executable path beyond `comm` | Task 1–2 |
| Tracepoint-based (no fentry-only gamble) | Task 1 uses existing `tp/sched/sched_process_exec` |
| No kernel mocks | Task 3 integration + real `go generate` |
| JSONL + reporting | Task 2 digest + telemetry |
| CI safety | Task 1 docker generate; Task 3 integration job |

**2. Placeholder scan**

No TBD/TODO; code blocks are complete snippets; commands are explicit.

**3. Type consistency**

- C: `exe_path[256]` ↔ Go: `[256]byte`
- JSON key: `exe` throughout
- `__data_loc` decode matches in-tree `trace_event_raw_sched_process_exec` layout

**Risk note:** If a future kernel encodes `__data_loc` differently, add a one-line kernel-doc reference in `trace_exec.bpf.c` and re-verify with `perf trace` / `bpftool` on oldest supported runner.

---

**Plan complete and saved to `docs/superpowers/plans/2026-04-09-exec-executable-path-bpf.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**

---

## Execution log (2026-04-10)

- **Task 1:** Subagent + Docker — `bpf/trace_exec.bpf.c` extended; `go generate ./internal/bpf/traceexec/...` OK.
- **Tasks 2–5:** Implemented in-repo — Go decode/digest/telemetry/tests, `TestRun_ExecJSONLIncludesExePath`, nightstalker-demo `exe` grep, README. Wire-size test `TestExecEventWireLayout` (280 bytes).
- **Verification (executing-plans close-out):** `docker run ubuntu:24.04 … scripts/docker-ubuntu-test-inner.sh` — `go generate`, `gofmt`, `go vet`, `staticcheck`, `go test ./...` — **PASS** (2026-04-10). Root+BPF integration (`NIGHTSTALKER_INTEGRATION=1`) not re-run in this session; use Linux/privileged Docker or CI for that gate.
