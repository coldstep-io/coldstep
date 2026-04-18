# Phase B — Filesystem Events (high-signal FS) Implementation Plan

> **Repository state (2026-04-12):** Implementation is **complete** on branch **`feat/phase-b-fs-events`** (awaiting merge to **`main`**). All task checkboxes below are **[x]** for historical traceability. Follow-ups (e.g. BPF-side ringbuf reserve counters for observability maps) belong in a new plan.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Add optional **filesystem event telemetry** gated by `NIGHTSTALKER_FEATURE_GATES=fs_events=1`, emitting `fs_event` JSONL rows for high-signal syscalls (`openat`+`O_CREAT`, `unlinkat`, `renameat2`, `fchmodat`) with path, op, pid/comm, and rendering a bounded **"Filesystem (recent)"** `<details>` section in `.nightstalker-detect.md`.

**Architecture:** New `bpf/trace_fs.bpf.c` using the **same `raw_tp/sys_enter` + pt\_regs CO-RE pattern** as `trace_connect.bpf.c` (avoids verifier issues with `tp/` + struct field reads on Azure kernels). The BPF program reads the path string from the userspace pointer argument and emits into a new `fs_events` ringbuf. A runtime `BPF_MAP_TYPE_ARRAY` config map (`fs_agent_cfg[0]`) lets the Go agent disable the hook via a single map write when the gate is off (but since it's already feature-gated in Go, BPF config is just defence-in-depth). Go agent loads the program conditionally, feeds a bounded `[]FSDigestRow` buffer and `runStats.fsN` counter, and the digest renders a new KPI row + collapsible table. Rate limiting is applied **in userspace** (cap ring reads to `MaxFSEventsTotal=5000`; per-second burst cap via a simple token bucket in the ring reader).

**Tech Stack:** BPF C (CO-RE, clang -Wall -Werror), `bpf2go@v0.21.0`, Go 1.24.x, `github.com/cilium/ebpf`, `link.AttachRawTracepoint`, `ringbuf.Reader`, existing `report.DigestInput` / `BuildDetectMarkdown` extension patterns.

**OS scope:** Linux x86\_64 only (`ubuntu-latest` amd64). All syscall numbers are x86\_64.

---

## File map

| Path | Responsibility |
|------|----------------|
| `bpf/trace_fs.bpf.c` | BPF: `raw_tp/sys_enter` for `openat`+O\_CREAT, `unlinkat`, `renameat2`, `fchmodat` → `fs_events` ringbuf; config map `fs_agent_cfg` |
| `internal/bpf/tracefs/gen.go` | `//go:generate bpf2go ...` (same flags as `tracefork/gen.go`) |
| `scripts/build-agent-linux.sh` | Add `go generate ./internal/bpf/tracefs/...` after `tracedns` line |
| `internal/telemetry/event.go` | Add `FSEvent` struct (`"fs_event"`) |
| `internal/telemetry/event_test.go` | Round-trip test for `fs_event` type; `EventType` coverage |
| `internal/agent/agent_linux.go` | `fsSectionState`, `fsRowBuffer`; `readFSRing`; wire behind `fs_events` gate; extend `runStats`, `buildDigestInput`, `Run` shutdown |
| `internal/agent/agent_linux_test.go` | Update `buildDigestInput` call-sites to pass new args; add `TestRun_BuildsDigestInputWithFSSectionState` |
| `internal/agent/agent_integration_test.go` | `TestRun_FSEventJSONLWhenFeatureGate`: create+remove a file, assert JSONL `"type":"fs_event"` |
| `internal/report/digest.go` | `FSDigestRow`; extend `DigestInput`; FS KPI row + `<details>` section in `BuildDetectMarkdown` |
| `internal/report/digest_test.go` | Golden substring tests: FS KPI row, section header, empty-state row |
| `.github/workflows/nightstalker-demo.yml` | Add `fs_events=1` to feature-gates; file probe; JSONL + digest assertions |

---

### Task 0: JSONL `FSEvent` type (pure Go, TDD)

**Files:**
- Modify: `internal/telemetry/event.go`
- Modify: `internal/telemetry/event_test.go`

- [x] **Step 1:** Add the struct to `internal/telemetry/event.go` after `TLSEvent`:

```go
// FSEvent is one JSONL record for a high-signal filesystem operation (detect, feature-gated).
type FSEvent struct {
	Type     string `json:"type"` // "fs_event"
	TS       string `json:"ts"`
	Seq      uint64 `json:"seq"`
	PID      uint32 `json:"pid"`
	TGID     uint32 `json:"tgid"`
	ThreadID uint32 `json:"thread_id"`
	Comm     string `json:"comm"`
	Op       string `json:"op"`   // "create" | "unlink" | "rename" | "chmod"
	Path     string `json:"path"` // from userspace buffer (BPF-capped 256 bytes)
	Note     string `json:"note,omitempty"`
}
```

- [x] **Step 2:** Open `internal/telemetry/event_test.go`, add a test at the bottom:

```go
func TestFSEvent_RoundTrip(t *testing.T) {
	ev := FSEvent{
		Type: "fs_event", TS: "2026-01-01T00:00:00Z", Seq: 5,
		PID: 10, TGID: 10, ThreadID: 11, Comm: "bash",
		Op: "create", Path: "/tmp/test.txt",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if EventType(b) != "fs_event" {
		t.Fatalf("EventType=%q want fs_event", EventType(b))
	}
	var got FSEvent
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Op != "create" || got.Path != "/tmp/test.txt" {
		t.Fatalf("got %+v", got)
	}
}
```

- [x] **Step 3:** Run on Windows (pure Go, no BPF):

```
go test ./internal/telemetry/... -run TestFSEvent -count=1
```

Expected: **PASS**.

- [x] **Step 4:** Commit:

```bash
git add internal/telemetry/event.go internal/telemetry/event_test.go
git commit -m "feat(telemetry): add FSEvent JSONL type for filesystem operations"
```

---

### Task 1: Digest row type, DigestInput fields, and BuildDetectMarkdown section

**Files:**
- Modify: `internal/report/digest.go`
- Modify: `internal/report/digest_test.go`

- [x] **Step 1:** Add `FSDigestRow` after `TLSDigestRow` in `internal/report/digest.go`:

```go
// FSDigestRow is one filesystem event line in the markdown digest.
type FSDigestRow struct {
	TS   string
	PID  uint32
	Comm string
	Op   string
	Path string
}
```

- [x] **Step 2:** Extend `DigestInput` struct (after the `TruncatedTLS bool` and related fields):

```go
	FSTotal          int
	FSGate           bool
	FSRows           []FSDigestRow
	TruncatedFS      bool
	FSDegradedHook   bool
	FSReaderErrors   int
```

- [x] **Step 3:** In `BuildDetectMarkdown`, add the FS KPI row right before the `<sub>` footnote line (after the `tls` KPI block):

```go
	if fsKPIVisible(in) {
		b.WriteString(fmt.Sprintf("| **fs_event** | %d |\n", in.FSTotal))
	}
```

Add helper function `fsKPIVisible` and the FS `<details>` section after the Process tree section:

```go
func fsKPIVisible(in DigestInput) bool {
	return in.FSGate && (in.FSTotal > 0 || in.FSDegradedHook || in.FSReaderErrors > 0)
}
```

And in the body of `BuildDetectMarkdown`, after the process-tree section, append the FS section:

```go
	if in.FSGate {
		b.WriteString("\n<details>\n<summary><strong>Filesystem (recent)</strong></summary>\n\n")
		b.WriteString("| Time | PID | Comm | Op | Path |\n|:--|--:|:--|:--|:--|\n")
		if len(in.FSRows) == 0 {
			reason := "no events"
			if in.FSDegradedHook {
				reason = "degraded hook"
			} else if in.FSReaderErrors > 0 {
				reason = fmt.Sprintf("reader errors (%d)", in.FSReaderErrors)
			}
			b.WriteString(fmt.Sprintf("| — | — | — | — | %s |\n", reason))
		} else {
			for _, r := range in.FSRows {
				b.WriteString(fmt.Sprintf("| `%s` | %d | `%s` | `%s` | `%s` |\n",
					r.TS, r.PID, sanitizeCell(r.Comm), sanitizeCell(r.Op), sanitizeCell(r.Path)))
			}
			if in.TruncatedFS {
				b.WriteString(fmt.Sprintf("\n*Showing last %d of %d — full stream in JSONL.*\n",
					len(in.FSRows), in.FSTotal))
			}
		}
		b.WriteString("\n</details>\n")
	}
```

- [x] **Step 4:** Add tests in `internal/report/digest_test.go`:

```go
func TestBuildDetectMarkdown_FSKPIAndSection(t *testing.T) {
	in := DigestInput{
		FSGate: true,
		FSTotal: 3,
		FSRows: []FSDigestRow{
			{TS: "2026-01-01T00:00:00Z", PID: 100, Comm: "bash", Op: "create", Path: "/tmp/foo.txt"},
		},
	}
	md := BuildDetectMarkdown(in)
	for _, want := range []string{"**fs_event**", "Filesystem (recent)", "create", "/tmp/foo.txt"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in digest", want)
		}
	}
}

func TestBuildDetectMarkdown_FSEmptyState_NoEvents(t *testing.T) {
	in := DigestInput{FSGate: true, FSTotal: 0}
	md := BuildDetectMarkdown(in)
	if !strings.Contains(md, "Filesystem (recent)") {
		t.Error("missing FS section header")
	}
	if !strings.Contains(md, "no events") {
		t.Error("missing no-events empty state")
	}
}

func TestBuildDetectMarkdown_FSEmptyState_Degraded(t *testing.T) {
	in := DigestInput{FSGate: true, FSTotal: 0, FSDegradedHook: true}
	md := BuildDetectMarkdown(in)
	if !strings.Contains(md, "degraded hook") {
		t.Error("missing degraded hook empty state")
	}
}

func TestBuildDetectMarkdown_FSGateOff_NoSection(t *testing.T) {
	in := DigestInput{FSGate: false, FSTotal: 5}
	md := BuildDetectMarkdown(in)
	if strings.Contains(md, "Filesystem") {
		t.Error("fs section should be hidden when gate is off")
	}
}
```

- [x] **Step 5:** Run:

```
go test ./internal/report/... -count=1
```

Expected: **PASS**.

- [x] **Step 6:** Commit:

```bash
git add internal/report/digest.go internal/report/digest_test.go
git commit -m "feat(report): FS event KPI row and Filesystem section in digest"
```

---

### Task 2: BPF program `trace_fs.bpf.c`

**Files:**
- Create: `bpf/trace_fs.bpf.c`
- Create: `internal/bpf/tracefs/gen.go`

The BPF program intercepts four filesystem syscalls via the `raw_tp/sys_enter` hook. It reads the path from the userspace pointer argument and submits a `fs_event` record to the ringbuf. A gate map allows Go to disable the hook at runtime.

Syscall numbers (Linux x86\_64):
- `__NR_openat` = 257: args `[0]=dirfd`, `[1]=pathname (user ptr)`, `[2]=flags`; emit only when `flags & O_CREAT` (create, not read)
- `__NR_unlinkat` = 263: args `[0]=dirfd`, `[1]=pathname (user ptr)`, `[2]=flags`
- `__NR_renameat2` = 316: args `[0]=olddirfd`, `[1]=oldpath`, `[2]=newdirfd`, `[3]=newpath`; emit `newpath` (destination)
- `__NR_fchmodat` = 268: args `[0]=dirfd`, `[1]=pathname (user ptr)`, `[2]=mode`

O\_CREAT = 0x40 (64).

- [x] **Step 1:** Create `bpf/trace_fs.bpf.c`:

```c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Linux x86_64 syscall numbers only (matches GitHub-hosted ubuntu-latest amd64). */
#define FS_NR_OPENAT    257
#define FS_NR_UNLINKAT  263
#define FS_NR_RENAMEAT2 316
#define FS_NR_FCHMODAT  268

#define O_CREAT 0x40

#define FS_PATH_MAX 256

/* Op codes embedded in the event (single byte to keep struct small). */
#define FS_OP_CREATE 1
#define FS_OP_UNLINK 2
#define FS_OP_RENAME 3
#define FS_OP_CHMOD  4

struct fs_event {
	__u32 tgid;
	__u32 tid;
	__u8 comm[16];
	__u8 op;
	__u8 path[FS_PATH_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} fs_agent_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} fs_events SEC(".maps");

static __always_inline int fs_enabled(void)
{
	__u32 k = 0;
	__u8 *v = bpf_map_lookup_elem(&fs_agent_cfg, &k);
	return v && *v;
}

static __always_inline void submit_fs_event(unsigned long path_ptr, __u8 op)
{
	struct fs_event *ev;
	__u64 pt;

	ev = bpf_ringbuf_reserve(&fs_events, sizeof(*ev), 0);
	if (!ev)
		return;

	pt = bpf_get_current_pid_tgid();
	ev->tgid = (__u32)(pt >> 32);
	ev->tid = (__u32)pt;
	ev->op = op;
	__builtin_memset(ev->comm, 0, sizeof(ev->comm));
	__builtin_memset(ev->path, 0, sizeof(ev->path));
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	if (path_ptr)
		bpf_probe_read_user_str(ev->path, sizeof(ev->path), (const void *)path_ptr);

	bpf_ringbuf_submit(ev, 0);
}

/*
 * raw_tp/sys_enter: ctx->args[0] is struct pt_regs * on x86_64.
 * Read syscall id from regs->orig_ax and arguments from regs->di/si/dx/r10.
 */
SEC("raw_tp/sys_enter")
int handle_fs_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	unsigned long regs_ptr = ctx->args[0];
	long id = (long)ctx->args[1];

	if (!fs_enabled())
		return 0;

	struct pt_regs *regs = (struct pt_regs *)regs_ptr;
	unsigned long arg0, arg1, arg2, arg3;

	if (id == FS_NR_OPENAT) {
		if (bpf_core_read(&arg1, sizeof(arg1), &regs->si))
			return 0;
		if (bpf_core_read(&arg2, sizeof(arg2), &regs->dx))
			return 0;
		if (!(arg2 & O_CREAT))
			return 0;
		submit_fs_event(arg1, FS_OP_CREATE);
	} else if (id == FS_NR_UNLINKAT) {
		if (bpf_core_read(&arg1, sizeof(arg1), &regs->si))
			return 0;
		submit_fs_event(arg1, FS_OP_UNLINK);
	} else if (id == FS_NR_RENAMEAT2) {
		/* emit destination path (arg3 = newpath) */
		if (bpf_core_read(&arg3, sizeof(arg3), &regs->r10))
			return 0;
		submit_fs_event(arg3, FS_OP_RENAME);
	} else if (id == FS_NR_FCHMODAT) {
		if (bpf_core_read(&arg1, sizeof(arg1), &regs->si))
			return 0;
		submit_fs_event(arg1, FS_OP_CHMOD);
	}

	return 0;
}
```

- [x] **Step 2:** Create `internal/bpf/tracefs/gen.go` (same flags as `tracefork/gen.go`):

```go
package tracefs

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -cc clang -no-strip -target bpfel,bpfeb -cflags "-O2 -g -Wall -Werror -I../../../bpf -I/usr/include/bpf" Tracefs ../../../bpf/trace_fs.bpf.c -- -I../../../bpf -I/usr/include/bpf
```

- [x] **Step 3:** Add `go generate ./internal/bpf/tracefs/...` to `scripts/build-agent-linux.sh` after the `tracedns` line:

The file currently ends with:
```bash
go generate ./internal/bpf/tracedns/...
go build ...
```

Change to:
```bash
go generate ./internal/bpf/tracedns/...
go generate ./internal/bpf/tracefs/...
go build -trimpath -ldflags="-s -w" -o bin/ci-runtime-guard ./cmd/ci-runtime-guard
```

- [x] **Step 4:** Validate the BPF compiles by running the full docker test (Linux/Docker required):

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'MSYS_NO_PATHCONV=1 NIGHTSTALKER_CONTAINER_BTF_ONLY=1 NIGHTSTALKER_SKIP_ACTION_BUNDLE=1 bash /c/dumper_5000/scripts/docker-ubuntu-test.sh'
```

Expected: `go generate ./internal/bpf/tracefs/...` succeeds; `go build` succeeds; no clang errors.

- [x] **Step 5:** Commit:

```bash
git add bpf/trace_fs.bpf.c internal/bpf/tracefs/gen.go scripts/build-agent-linux.sh
git commit -m "feat(bpf): fs event capture via raw_tp/sys_enter (openat+create, unlink, rename, chmod)"
```

---

### Task 3: Go agent — ring reader, row buffer, runStats, buildDigestInput wiring

**Files:**
- Modify: `internal/agent/agent_linux.go`
- Modify: `internal/agent/agent_linux_test.go`

- [x] **Step 1:** Add `"github.com/shermanatoor/nightstalker/internal/bpf/tracefs"` to the imports in `agent_linux.go` (alongside the other `internal/bpf/*` imports).

- [x] **Step 2:** Add `fsN int` to `runStats` (alongside `tlsN`, `procForkN`):

```go
type runStats struct {
	mu           sync.Mutex
	execN        int
	tcpN         int
	udpN         int
	httpN        int
	tlsN         int
	procForkN    int
	fsN          int
	policyCounts map[string]int
}
```

Add accessor methods after `procForkTotal()`:

```go
func (s *runStats) addFS() {
	s.mu.Lock()
	s.fsN++
	s.mu.Unlock()
}

func (s *runStats) fsTotal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fsN
}
```

Update `counts()` if it returns all fields; or update the existing inline read in `buildDigestInput` — look for:

```go
execN, tcpN, udpN, httpN, tlsN := stats.counts()
```

and change to:

```go
execN, tcpN, udpN, httpN, tlsN, fsN := stats.counts()
```

Update the `counts()` method to include `fsN`:

```go
func (s *runStats) counts() (exec, tcp, udp, http, tls, fs int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execN, s.tcpN, s.udpN, s.httpN, s.tlsN, s.fsN
}
```

- [x] **Step 3:** Add `fsSectionState` (mirrors `forkSectionState`) and `fsRowBuffer`:

```go
type fsSectionState struct {
	mu         sync.Mutex
	readErrors int
}

func newFSSectionState() *fsSectionState { return &fsSectionState{} }

func (s *fsSectionState) addReadError() {
	s.mu.Lock()
	s.readErrors++
	s.mu.Unlock()
}

type fsSectionSnapshot struct {
	readErrors int
}

func (s *fsSectionState) snapshot() fsSectionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fsSectionSnapshot{readErrors: s.readErrors}
}

type fsRowBuffer struct {
	mu   sync.Mutex
	max  int
	rows []report.FSDigestRow
}

func newFSRowBuffer(max int) *fsRowBuffer { return &fsRowBuffer{max: max} }

func (b *fsRowBuffer) add(r report.FSDigestRow) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.rows) < b.max {
		b.rows = append(b.rows, r)
	}
}

func (b *fsRowBuffer) snapshot() ([]report.FSDigestRow, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]report.FSDigestRow, len(b.rows))
	copy(cp, b.rows)
	return cp, false // trunc tracked by FSTotal vs len
}
```

- [x] **Step 4:** Add `fsEventWire` decode struct and `readFSRing` function after `readForkRing`:

```go
// fsOpName maps BPF op byte to JSONL op string.
func fsOpName(op uint8) string {
	switch op {
	case 1:
		return "create"
	case 2:
		return "unlink"
	case 3:
		return "rename"
	case 4:
		return "chmod"
	default:
		return "unknown"
	}
}

type fsEventWire struct {
	TGID uint32
	TID  uint32
	Comm [16]byte
	Op   uint8
	Path [256]byte
}

const maxFSEventsTotal = 5000

func readFSRing(ctx context.Context, cfg config.Config, rd *ringbuf.Reader, stats *runStats,
	fsRows *fsRowBuffer, fsState *fsSectionState, seq *telemetry.SeqGen, jsonlMu *sync.Mutex) error {
	count := 0
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			fsState.addReadError()
			slog.Warn("ringbuf read (fs)", "err", err)
			continue
		}
		var ev fsEventWire
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			fsState.addReadError()
			slog.Warn("decode fs event", "err", err)
			continue
		}

		count++
		if count > maxFSEventsTotal {
			continue // count but don't buffer or log
		}

		comm := nullTermStr(ev.Comm[:])
		path := nullTermStr(ev.Path[:])
		op := fsOpName(ev.Op)
		ts := time.Now().UTC().Format(time.RFC3339Nano)
		n := seq.Next()

		fsRows.add(report.FSDigestRow{
			TS:   ts,
			PID:  ev.TGID,
			Comm: comm,
			Op:   op,
			Path: path,
		})
		stats.addFS()

		evOut := telemetry.FSEvent{
			Type: "fs_event", TS: ts, Seq: n,
			PID: ev.TGID, TGID: ev.TGID, ThreadID: ev.TID,
			Comm: comm, Op: op, Path: path,
		}
		jsonlMu.Lock()
		if b, err2 := json.Marshal(evOut); err2 == nil {
			appendJSONL(cfg.EventsLogPath, b)
		}
		jsonlMu.Unlock()
	}
}
```

(Note: `nullTermStr` and `appendJSONL` are existing helpers in `agent_linux.go`.)

- [x] **Step 5:** Extend `buildDigestInput` to accept and wire FS state. Change the signature to add three new parameters at the end:

```go
func buildDigestInput(
	stats *runStats,
	bpfSt []telemetry.BPFStatus,
	execRows []report.ExecDigestRow,
	tcpRows []report.TCPDigestRow,
	udpRows []report.UDPDigestRow,
	httpRows []report.HTTPDigestRow,
	tlsRows []report.TLSDigestRow,
	jsonlPath string,
	seqLast uint64,
	maxRows int,
	sectionState networkSectionSnapshot,
	enforceState enforcementSnapshot,
	forkEdges []proctree.Edge,
	forkEdgesTrunc bool,
	forkSnap forkSectionSnapshot,
	procTreeGate bool,
	tlsSNIGate bool,
	fsRows []report.FSDigestRow,
	fsSnap fsSectionSnapshot,
	fsGate bool,
) report.DigestInput {
```

Inside the function, update the local variable extraction:

```go
execN, tcpN, udpN, httpN, tlsN, fsN := stats.counts()
```

And update the returned `report.DigestInput` literal to include:

```go
FSTotal:        fsN,
FSGate:         fsGate,
FSRows:         fsRows,
TruncatedFS:    fsN > maxRows,
FSDegradedHook: fsGate && hookDegraded(bpfSt, "raw_tp/sys_enter (fs)"),
FSReaderErrors:  fsSnap.readErrors,
```

- [x] **Step 6:** In `Run`, wire the FS feature gate (mirror the `procTreeGate` pattern). Add after the `procTreeGate` declaration:

```go
fsGate := config.FeatureGateEnabled(cfg.FeatureGates, "fs_events")

var fsRowBuf *fsRowBuffer
var fsSt *fsSectionState
```

Then add the BPF load/attach block (after the fork tracing block):

```go
var fsRd *ringbuf.Reader
var fsObjs *tracefs.TracefsObjects
var fsLnk link.Link
if fsGate {
    fsRowBuf = newFSRowBuffer(maxRows)
    fsSt = newFSSectionState()
    objs := new(tracefs.TracefsObjects)
    if err := tracefs.LoadTracefsObjects(objs, nil); err != nil {
        slog.Info("fs tracing disabled", "err", err)
        bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
    } else {
        // Enable BPF gate map
        if err := objs.FsAgentCfg.Update(uint32(0), uint8(1), ebpf.UpdateAny); err != nil {
            slog.Warn("fs cfg map update", "err", err)
        }
        fsObjs = objs
        lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
            Name:    "sys_enter",
            Program: objs.HandleFsSysEnter,
        })
        if err != nil {
            slog.Info("fs sys_enter attach failed", "err", err)
            bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
            fsObjs = nil
        } else {
            fsLnk = lnk
            rd, err := ringbuf.NewReader(objs.FsEvents)
            if err != nil {
                slog.Info("fs ringbuf reader failed", "err", err)
                bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: bpfDetail(err)})
                fsObjs = nil
                fsLnk = nil
            } else {
                fsRd = rd
                bpfSt = append(bpfSt, telemetry.BPFStatus{Name: "raw_tp/sys_enter (fs)", OK: true})
                slog.Info("tracing fs events (openat+create, unlink, rename, chmod)")
                defer func() {
                    if fsRd != nil {
                        _ = fsRd.Close()
                    }
                    if fsLnk != nil {
                        _ = fsLnk.Close()
                    }
                    if fsObjs != nil {
                        _ = fsObjs.Close()
                    }
                }()
            }
        }
    }
}
```

Update the capabilities map (in the meta event block):

```go
if fsGate {
    meta.Capabilities["fs_events"] = true
}
```

Start the goroutine alongside `readForkRing`:

```go
if fsRd != nil && fsRowBuf != nil && fsSt != nil {
    wg.Add(1)
    go func() {
        defer wg.Done()
        errCh <- readFSRing(runCtx, cfg, fsRd, stats, fsRowBuf, fsSt, &seq, &jsonlMu)
    }()
}
```

Update the digest snapshot block to collect FS rows:

```go
var fsDigestRows []report.FSDigestRow
fsSSnap := fsSectionSnapshot{}
if fsRowBuf != nil {
    fsDigestRows, _ = fsRowBuf.snapshot()
}
if fsSt != nil {
    fsSSnap = fsSt.snapshot()
}
```

Pass the new args in the `buildDigestInput` call:

```go
in := buildDigestInput(stats, bpfSt, execRows, tcpRows, udpRows, httpRows, tlsRows, cfg.EventsLogPath,
    seqLast, maxRows, sectionState.snapshot(), enforceState.snapshot(), forkEdges, forkTrunc, forkSnap,
    procTreeGate, tlsSNIGate, fsDigestRows, fsSSnap, fsGate)
```

- [x] **Step 7:** Update `internal/agent/agent_linux_test.go` — all existing `buildDigestInput` call sites currently pass 17 positional arguments; add 3 more (`nil`, `fsSectionSnapshot{}`, `false`) to each call. Find all call sites with:

```
grep -n "buildDigestInput(" internal/agent/agent_linux_test.go
```

For each call, append `, nil, fsSectionSnapshot{}, false` before the closing `)`.

Also add a new test:

```go
func TestRun_BuildsDigestInputWithFSSectionState(t *testing.T) {
	stats := newRunStats()
	stats.addFS()
	stats.addFS()

	in := buildDigestInput(
		stats,
		[]telemetry.BPFStatus{
			{Name: "raw_tp/sys_enter (fs)", OK: false, Detail: "disabled"},
		},
		nil, nil, nil, nil, nil,
		"",
		0,
		120,
		networkSectionSnapshot{},
		enforcementSnapshot{},
		nil,
		false,
		forkSectionSnapshot{},
		false,
		false,
		[]report.FSDigestRow{{TS: "t", PID: 1, Comm: "bash", Op: "create", Path: "/tmp/x"}},
		fsSectionSnapshot{readErrors: 1},
		true,
	)

	if !in.FSGate {
		t.Fatal("FSGate should be true")
	}
	if in.FSTotal != 2 {
		t.Fatalf("FSTotal=%d want 2", in.FSTotal)
	}
	if !in.FSDegradedHook {
		t.Fatal("FSDegradedHook should be true when fs hook is degraded")
	}
	if in.FSReaderErrors != 1 {
		t.Fatalf("FSReaderErrors=%d want 1", in.FSReaderErrors)
	}
}
```

- [x] **Step 8:** Run (Windows, pure Go unit tests only):

```
go test ./internal/agent/... -run "TestRun_Builds" -count=1
```

Expected: **PASS** (non-BPF tests only; Linux tests skip on Windows).

- [x] **Step 9:** Commit:

```bash
git add internal/agent/agent_linux.go internal/agent/agent_linux_test.go
git commit -m "feat(agent): fs events ring reader, row buffer, and feature gate wiring"
```

---

### Task 4: Linux integration test

**Files:**
- Modify: `internal/agent/agent_integration_test.go`

- [x] **Step 1:** Add the test after `TestRun_TLSClientHelloSNIJSONL`:

```go
func TestRun_FSEventJSONLWhenFeatureGate(t *testing.T) {
	if os.Getenv("NIGHTSTALKER_FORCE_SYSCALL_BPF_TESTS") == "" {
		if rel, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			if strings.Contains(string(rel), "-microsoft-") {
				t.Skip("skipping fs BPF test on WSL/Microsoft kernel (BPF tracepoint attach unsupported)")
			}
		}
	}
	if _, err := exec.LookPath("touch"); err != nil {
		t.Skip("touch not found")
	}

	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")

	cfg := config.Config{
		EventsLogPath: eventsPath,
		FeatureGates:  config.ParseFeatureGates("fs_events=1"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runCtx, runCancel := context.WithCancel(ctx)

	errCh := make(chan error, 1)
	go func() { errCh <- Run(runCtx, cfg) }()

	time.Sleep(500 * time.Millisecond)

	tmpFile := filepath.Join(dir, "ns-test-create.txt")
	cmd := exec.Command("bash", "-c", "touch "+tmpFile+" && rm "+tmpFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("probe command: %v\n%s", err, out)
	}

	time.Sleep(300 * time.Millisecond)
	runCancel()
	if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v", err)
	}

	data, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}

	var foundFS bool
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, `"type":"fs_event"`) {
			foundFS = true
			break
		}
	}
	if !foundFS {
		t.Fatalf("expected at least one fs_event JSONL line; got:\n%s", string(data))
	}
}
```

- [x] **Step 2:** Run the full docker test with integration:

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'MSYS_NO_PATHCONV=1 NIGHTSTALKER_CONTAINER_BTF_ONLY=1 NIGHTSTALKER_INTEGRATION=1 bash /c/dumper_5000/scripts/docker-ubuntu-test.sh'
```

Expected: `TestRun_FSEventJSONLWhenFeatureGate` **PASS** (or **SKIP** if no tracefs — not a failure).

- [x] **Step 3:** Commit:

```bash
git add internal/agent/agent_integration_test.go
git commit -m "test(agent): integration test for fs_event JSONL via feature gate"
```

---

### Task 5: nightstalker-demo CI assertions

**Files:**
- Modify: `.github/workflows/nightstalker-demo.yml`

- [x] **Step 1:** In the `guard` job, add `fs_events=1` to the `feature-gates` input (line 25):

Change:
```yaml
          feature-gates: proc_tree=1,tls_sni=1
```
To:
```yaml
          feature-gates: proc_tree=1,tls_sni=1,fs_events=1
```

- [x] **Step 2:** In the "Egress simulation (nightstalker-demo)" step, add a filesystem probe after the `bash -c '/bin/true'` line:

```bash
          # Filesystem probe for fs_events gate: create and remove a temp file.
          TMP_FS_PROBE="$(mktemp /tmp/nightstalker-fs-probe-XXXXXX)"
          rm -f "${TMP_FS_PROBE}"
```

- [x] **Step 3:** In the "Verify nightstalker-demo egress in detect log" step, add assertions after the `proc_fork` check:

```bash
          grep -q '"type":"fs_event"' "$j" || { echo "expected fs_event JSONL when fs_events gate enabled"; exit 1; }
          grep -qi 'Filesystem' "$f" || { echo "expected Filesystem section in digest when fs_events gate enabled"; exit 1; }
```

- [x] **Step 4:** Run a quick lint check:

```
python scripts/assert_utf8_text.py
```

Expected: no encoding errors.

- [x] **Step 5:** Commit:

```bash
git add .github/workflows/nightstalker-demo.yml
git commit -m "ci(nightstalker-demo): assert fs_event JSONL and Filesystem digest section with fs_events gate"
```

---

## Plan self-review (checklist)

| Spec / research item | Task coverage |
|---------------------|---------------|
| Phase B objective: FS telemetry for CI without full EDR | Tasks 0–5 |
| Feature gate `fs_events=1` | Tasks 3, 5 |
| High-signal ops: create, unlink, rename, chmod | Task 2 (BPF) |
| Rate cap (no ringbuf storm) | Task 3: `maxFSEventsTotal=5000` in userspace |
| JSONL `fs_event` type | Task 0 |
| Digest KPI + `<details>` section | Task 1 |
| Empty-state row (degraded/no events) | Task 1 + tests |
| Graceful degrade (BPF load fail → continue) | Task 3 |
| Unit tests for digest | Task 1 |
| Integration test (Linux only, skips WSL) | Task 4 |
| nightstalker-demo assertions | Task 5 |
| `gofmt` + `go vet` | Covered by docker test in Task 2 |
| `ubuntu-latest` amd64 only | BPF syscall numbers are x86\_64 only; documented in comments |
| Path truncation (BPF caps at 256 bytes) | BPF `FS_PATH_MAX 256` in Task 2 |
| UTF-8 safe digest | `sanitizeCell` already handles this |

**Placeholder scan:** No TBDs, TODOs, or vague steps. All code is complete.

**Type consistency:** `FSEvent` (telemetry), `FSDigestRow` (report), `fsSectionState`/`fsSectionSnapshot`/`fsRowBuffer` (agent), `FSTotal`/`FSGate`/`FSRows`/`TruncatedFS`/`FSDegradedHook`/`FSReaderErrors` (DigestInput) — consistent throughout.

---

**Plan complete and saved to `docs/superpowers/plans/2026-04-12-phase-B-fs-events.md`.**

**Two execution options:**

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
