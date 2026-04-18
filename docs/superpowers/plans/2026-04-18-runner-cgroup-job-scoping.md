# Runner Cgroup Job Scoping (Plan C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce **cross-job noise** and tighten **enforce attach semantics** on **shared GitHub-hosted runners** by attaching cgroup BPF programs to a **job-scoped cgroup path** when deterministically discoverable, instead of always using **`/sys/fs/cgroup`** root (current `internal/agent/agent_linux.go` uses `Path: "/sys/fs/cgroup"` for `AttachCgroup`).

**Architecture:** Phase **1** (always shippable): introduce config **`COLDSTEP_CGROUP_PATH`** (or `cfg.CgroupPath`) resolved from **`/proc/self/cgroup`** best-effort parser + optional explicit override; **log + meta JSONL** the chosen path when **non-default**. Phase **2**: attach `enforce_connect4` / `enforce_sendmsg4` (and future IPv6) to resolved path **only when** directory exists and `openat`/`stat` confirms cgroup v2 unified hierarchy compatibility; **fallback** to root attach on failure **with degraded BPFStatus Detail**.

**Tech Stack:** Go `os`, `path/filepath`, `ebpf/link` cgroup attach, systemd cgroup path patterns documented from GitHub Actions runner docs.

---

## File Structure / Responsibility Map

- Modify: `internal/config` — add optional `CgroupAttachPath string` field with env binding `COLDSTEP_CGROUP_PATH`.
- Modify: `internal/agent/agent_linux.go` — helper `resolveCgroupAttachPath(cfg) string`, replace string literal `"/sys/fs/cgroup"` in `link.AttachCgroup(link.CgroupOptions{ Path: ... })`.
- Modify: `internal/agent` tests — unit tests for cgroup path resolution with mocked `/proc` (use `testdata` fixture strings).
- Optional: `.github/workflows` doc snippet — no workflow edit required for feature to work.

---

### Task 1: Path resolution helper + tests

**Files:**
- Create: `internal/agent/cgroup_path_linux.go` (build tag `linux`) — `func cgroupAttachPathFromProc(procPath string, override string) string`
- Create: `internal/agent/cgroup_path_linux_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestCgroupAttachPathFromProc_UnifiedSingleLine(t *testing.T) {
	got := cgroupAttachPathFromProc("testdata/cgroup/unified.sample", "")
	if got == "" {
		t.Fatal("expected non-empty path")
	}
	if !strings.HasPrefix(got, "/sys/fs/cgroup") {
		t.Fatalf("unexpected %q", got)
	}
}
```

Add `internal/agent/testdata/cgroup/unified.sample` with a realistic line:

```text
0::/actions_job/abc123
```

- [ ] **Step 2: Implement parser**

Rules:

1. If `override != ""`, return `override`.
2. Else read first `0::/...` **cgroup v2** line from `/proc/self/cgroup` content (from parameter for tests).
3. Join `/sys/fs/cgroup` + suffix.

- [ ] **Step 3: Run test**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./internal/agent -run TestCgroupAttachPathFromProc -count=1 -v`  
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/agent/cgroup_path_linux.go internal/agent/cgroup_path_linux_test.go internal/agent/testdata/cgroup/unified.sample
git commit -m "feat(agent): resolve cgroup v2 attach path from /proc/self/cgroup"
```

---

### Task 2: Wire enforce attach + telemetry

**Files:**
- Modify: `internal/config/config.go` (or equivalent) — new field
- Modify: `internal/agent/agent_linux.go` — use helper for `AttachCgroup` `Path`

- [ ] **Step 1: Thread config**

Bind env `COLDSTEP_CGROUP_PATH` to `cfg.CgroupAttachPath` (empty means auto).

- [ ] **Step 2: Attach**

Replace:

```go
Path:    "/sys/fs/cgroup",
```

with:

```go
Path:    cgroupAttachPathFromProc("/proc/self/cgroup", cfg.CgroupAttachPath),
```

Use local wrapper reading real `/proc/self/cgroup` on Linux only.

- [ ] **Step 3: Meta emission**

When path differs from `"/sys/fs/cgroup"` or override set, append one **log line** at Info level: `cgroup_attach_path=...`.

- [ ] **Step 4: Verification**

Run: `docker run --rm -v "c:/GitHub/coldstep:/workspace" -w /workspace golang:1.24-bookworm go test ./... -count=1`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config internal/agent/agent_linux.go
git commit -m "feat(enforce): attach cgroup BPF to resolved job cgroup path"
```

---

## Self-Review

- Plan C does **not** guarantee GitHub exposes a stable per-job path on all images; fallback preserves today’s behavior.
- No `TBD`; parser rules explicit.
