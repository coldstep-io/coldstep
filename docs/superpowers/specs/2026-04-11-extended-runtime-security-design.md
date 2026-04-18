# Extended runtime security: process tree, FS events, file integrity, memory protection, hardening (umbrella design)

> **Scope:** Single **umbrella** specification for five feature tracks on **GitHub-hosted `ubuntu-latest` (amd64) only**, aligned with Nightstalker’s existing **detect-first** composite Action + Go agent + eBPF model. **Clean-room:** behavioral inspiration from public CI security products is acceptable; **no** copying proprietary third-party code or rule packs.

> **Status:** Design for phased implementation. **Does not** change code until a separate implementation plan is approved.

**Repository state (2026-04-12):** **Process tree (Phase A)** is **partially shipped** on **`main`** behind **`feature-gates: proc_tree=1`** (`proc_fork` JSONL, digest **Process tree**, **`bpf/trace_fork.bpf.c`** as **`raw_tp/sched_process_fork`**—see **`docs/superpowers/plans/2026-04-11-phase-A-process-tree.md`**). **FS events, file integrity, memory protection, hardening engine** tracks in this umbrella remain **design-only** until each gets its own plan + branch.

---

## 1. Goals and non-goals

### 1.1 Goals

- **Process tree:** Reconstruct parent/child relationships and a bounded **spawn tree** view for the job (for digest + JSONL), without claiming perfect global attribution on shared runners.
- **Filesystem (FS) events:** High-signal, **rate-capped** visibility into security-relevant file operations (open/create/unlink/rename/chmod/exec path), suitable for CI triage.
- **File integrity:** Detect **unexpected modifications** to a declared baseline (paths or content hashes), scoped to the workspace and explicit allow/deny semantics.
- **Memory protection (v1):** **Detect** suspicious **W^X / RWX** transitions and **memfd**/`mmap` anomalies where hooks exist; **enforcement** only behind explicit mode + policy (later sub-phase).
- **Hardening engine:** **Open**, in-repo **rule IDs** with **tiers** (critical/high/defense-in-depth), mapping to **categories** (e.g. suspicious exec chain, unexpected interpreter, path tricks)—**not** proprietary remote rule feeds.

### 1.2 Non-goals (explicit)

- **TLS decryption**, **perfect cgroup isolation**, or **kernel portability** beyond `ubuntu-latest` Azure-patched kernels (see §2).
- **macOS / Windows** agents or self-hosted matrix expansion (per `AGENTS.md` unless the project widens scope later).
- **Third-party SaaS** auth, remote rule distribution, or vendored competitor implementations.
- **“Fail the job on every policy finding”** as default behavior (remains a **separate** product decision; v1 stays aligned with operational `fail-on-error` semantics unless a new input is specified in a later spec).

---

## 2. Runner and kernel reality (research anchor)

Nightstalker CI and nightstalker-demo target **`runs-on: ubuntu-latest`**. Runner images move forward on **Azure-tuned** kernels; treat **feature availability as probe + degrade**, not compile-time certainty.

### 2.1 Observed runner-image signals (indicative, not a contractual SLA)

Public **actions/runner-images** release notes show **Ubuntu 24.04** images shipping **6.17.x-class Azure** kernels (e.g. `6.17.0-1008-azure` cited on a **20260329** image tag in third-party release aggregators). **Ubuntu 22.04** lines have historically lagged (e.g. **6.8.x Azure** kernels cited for early-2026 22.04 tags). **GitHub’s `ubuntu-latest` label** has been migrating toward **24.04**; Nightstalker already standardizes on **`ubuntu-latest`** only.

**Design consequence:** document and test against **the kernel on the runner at CI time**, not a fixed LTS kernel number in prose.

### 2.2 BPF LSM (file integrity / memory hooks)

Kernel documentation describes **BPF LSM** programs (`BPF_PROG_TYPE_LSM`) attached to **LSM hooks** such as **`file_mprotect`** with context `(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot, int ret)` and `SEC("lsm/file_mprotect")`, loaded/attached via **`bpf_program__attach_lsm`** (see [LSM BPF Programs — The Linux Kernel documentation](https://docs.kernel.org/bpf/prog_lsm.html)).

**Operational requirement:** `CONFIG_BPF_LSM=y` (and the LSM stack ordering that exposes `bpf` as an active LSM) must be true on the runner or **LSM attach fails** → **graceful degrade** (digest “skipped/degraded”, no job failure in detect mode).

### 2.3 Process lifecycle hooks

Community and vendor practice converges on **`sched:sched_process_fork`** (and related **sched** tracepoints) for **fork/clone** lineage, complementing **`sched_process_exec`** for exec boundaries. Parent/child identifiers are available at the tracepoint; **full executable paths for parent** may require additional kernel helpers / kfuncs and stricter verifier constraints—plan assumes **PID/comm + optional path** with **best-effort** enrichment.

### 2.4 Filesystem visibility tradeoffs

`security_file_open` and similar hooks are **hot-path-adjacent**; industry write-ups emphasize **kernel-side filtering** before userspace to control overhead (e.g. Tracee discussions on `security_file_open` decoupling from syscall tracepoints). Kernel mailing list traffic has long noted tension around **VFS tracepoint** coverage vs. performance ([LWN: “Tracepoints for the VFS?”](https://lwn.net/Articles/1017573/) — conceptual background).

**Design consequence:** FS phase ships **sampling + PID/cgroup scoping + workspace path prefix filters** first; expand only with measured CPU budgets on nightstalker-demo.

---

## 3. Shared platform (all phases)

### 3.1 Event model and versioning

- Extend **JSONL** with new **`type`** values (examples): `proc_fork`, `proc_tree` (aggregated snapshot rows are optional), `fs_open`, `fs_rename`, `integrity`, `mem_mprotect`, `harden`.
- Bump **`meta.schema_version`** (or introduce **`capabilities`** map) whenever a phase adds optional streams.
- Preserve **append-only JSONL** + **shutdown digest** pattern (digest remains **bounded**; UTF-8 safe truncation per existing `internal/report` helpers).

### 3.2 Rate limits, rings, and drops

- Every high-volume stream gets: **per-second cap**, **per-job cap**, **ringbuf backpressure counters**, and digest **“degraded / dropped”** footers (same UX pattern as UDP/HTTP empty states today).
- **Never** silently claim completeness when sampling is active—emit explicit **sampled=true** in JSONL meta or per-batch sidecar counters.

### 3.3 `feature-gates` integration

- Gate each subsystem behind **`NIGHTSTALKER_FEATURE_GATES`** keys (e.g. `proc_tree=1`, `fs_events=1`, `integrity=1`, `mem_prot=1`, `harden=1`) **in addition** to Action inputs, so CI can flip probes without YAML churn when acceptable.

### 3.4 Testing strategy (cross-cutting)

- **Unit tests** for every pure-Go parser, graph reducer, hash canonicalization, and rule matcher.
- **Integration (`linux`, `integration`)** for attach success on real runner-class kernels **where feasible**; otherwise **CI-only** attach checks with **skip + reason** when hooks are absent.
- **nightstalker-demo** adds **incremental** assertions per phase (never a single monolithic job that times out on cold kernels).

---

## 4. Phased roadmap (umbrella)

Each phase is intended to be **shippable independently** with **detect** defaults.

### Phase A — Process tree (observability spine)

**Objective:** Build a **DAG/forest** of `(parent_tgid, child_tgid)` edges for processes observed during the job, correlated with existing **`exec`** rows.

**Primary hooks (research-backed):**

- **`sched:sched_process_fork`** (and related **sched** lifecycle tracepoints as needed) for lineage.
- Continue using **`sched_process_exec`** for **post-exec** identity; merge edges in userspace with **TTL** and **max node/edge caps**.

**Outputs:**

- Digest `<details>`: **“Process tree (recent)”** with collapsed subtrees + “+N more” behavior.
- JSONL: `proc_fork` raw edges + optional periodic **`proc_tree`** summary rows (if volume warrants).

**Risks:** namespace confusion on shared runners → label events **best-effort** and scope rollups to **cgroup/job** when cgroup metadata is available.

**Exit criteria:** nightstalker-demo shows non-empty tree for a **controlled** spawn chain (`bash` → `child`), bounded memory, unit tests for graph reducer edge cases.

---

### Phase B — Filesystem events (high-signal FS)

**Objective:** Provide **actionable** FS telemetry for CI workspaces without turning into a full EDR.

**Candidate hook strategies (pick per kernel probe, degrade gracefully):**

- **LSM audit path:** attach to **`lsm/file_open`** (and related file hooks documented alongside `file_mprotect` in kernel BPF LSM docs) for **open** visibility with filtering.
- **Syscall/tracepoint path:** complement with **rename/unlink/chmod** coverage where stable tracepoints exist on the runner kernel (exact syscall set comes from a small **kernel-inventory spike** on `ubuntu-latest`).

**Outputs:** JSONL `fs_*` rows + digest section **“Filesystem (recent)”** with path caps and workspace-root relativization.

**Exit criteria:** measurable overhead budget on nightstalker-demo (CPU wall clock + row caps) + at least one **rename** and **unlink** probe appears in JSONL on CI.

---

### Phase C — File integrity (baseline + drift)

**Objective:** Detect **unexpected content or metadata changes** against a **declared baseline**.

**Approaches (trade-offs):**

1. **Userspace baseline scan** at agent start/end (simple, portable) — misses mid-job malicious writes unless combined with Phase B.
2. **BPF-assisted hashing** on selected `file_open`/`mmap` paths (expensive) — high fidelity, higher risk of CPU blowups.
3. **Hybrid (recommended):** Phase B events drive **“touch sets”**; periodic **userspace hash** of touched files under workspace cap.

**Outputs:** JSONL `integrity` events with **path**, **hash algo**, **expected vs actual**, **rule id**.

**Exit criteria:** controlled CI fixture modifies a tracked file; digest shows **integrity violation** row; enforce path (if any) remains **explicitly opt-in**.

---

### Phase D — Memory protection (detect-first)

**Objective:** Surface **RWX / W^X** transitions and suspicious **`mprotect`**/`mmap` patterns consistent with loader tricks, using **`lsm/file_mprotect`** (and additional mmap-related hooks as verified) per kernel documentation patterns ([`file_mprotect` example](https://docs.kernel.org/bpf/prog_lsm.html)).

**Outputs:** JSONL `mem_mprotect` rows + digest section with **explainable** flags (heap RWX, anonymous exec mapping, etc.—wording must remain honest about uncertainty).

**Exit criteria:** a **benign** repro emits a detect row on CI; missing LSM → clean degrade with BPF status.

---

### Phase E — Hardening engine (open rules)

**Objective:** Ship an **in-repo** rule catalog with **IDs**, **tiers**, and **disable list** (familiar CI-security **UX** shape, not content cloning).

**Rule categories (examples, not exhaustive):**

- **Exec chain anomalies** (e.g. interpreter → downloader → `chmod` → exec) built from Phase A+B signals.
- **Path tricks** (workspace escape attempts, suspicious tmp paths) from FS events.
- **Typosquatting / suspicious argv** heuristics (strictly **local** string tables; no external feeds in v1).

**Outputs:** JSONL `harden` rows + digest **“Hardening findings”** section; `telemetry.Summary` rollups by rule id.

**Exit criteria:** at least **three** rules with unit tests + one nightstalker-demo scenario per tier; **no** network dependency for rule evaluation.

---

## 5. Security, privacy, and abuse resistance

- **Secrets redaction:** never emit env vars, `.git` credentials, or `GITHUB_TOKEN` patterns into JSONL/digest (extend existing redaction utilities used in meta lines).
- **Path exfiltration:** cap path bytes, normalize with workspace-relative roots, avoid dumping `/proc` contents.
- **Denial-of-service:** attacker-controlled high-frequency FS must not **starve** ringbuf readers—hard per-class caps + cooperative dropping.

---

## 6. Open questions (tracked, not blocking this umbrella)

- Exact **stable** syscall/tracepoint set on the **current** `ubuntu-latest` kernel for rename/unlink/chmod (requires a small **spike job** or `bpftrace -l` inventory in CI).
- Whether **cgroup scoping** can reliably restrict FS noise to the job’s workload on shared runners without conflicting with Actions’ own processes (likely **partial**).
- Whether **memory enforcement** (`-EPERM` returns) belongs in Nightstalker at all vs. staying **detect-only** forever—product decision; this spec keeps **detect** default.

---

## 7. References (external)

- Linux kernel docs: [LSM BPF Programs](https://docs.kernel.org/bpf/prog_lsm.html) (`lsm/file_mprotect`, attachment notes).
- Industry background: [LWN — Tracepoints for the VFS?](https://lwn.net/Articles/1017573/) (why VFS-wide tracepoints are contentious).
- Ecosystem patterns: Tracee / Velociraptor discussions on **`security_file_open`** overhead and filtering (public issues/PRs; **reference only**, no code import).

---

## 8. Self-review (spec quality)

- **Placeholders:** none left vague on purpose; remaining unknowns are listed in §6 as **explicit** spike items.
- **Consistency:** phased ordering places **observability** (A/B) before **integrity/memory** (C/D) and **rules** (E), matching dependency reality.
- **Scope:** umbrella is large but **phased** with **exit criteria** per phase; implementation plans should be **one plan file per phase** when coding starts.

---

**Next step (process):** After maintainer review of this document, use **writing-plans** to author **`docs/superpowers/plans/YYYY-MM-DD-phase-A-process-tree.md`** (then B, …) rather than one mega-plan.
