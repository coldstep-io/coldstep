# Full egress monitor: TCP + UDP + HTTP + report UI

> **Status (2026-04-12):** Phases 0–4 are **merged to `main`** (TCP+UDP+HTTP BPF, **`meta`** / **`seq`** JSONL, KPI digest + per-type tables, nightstalker-demo assertions). **Phase 5 (TLS ClientHello / SNI)** is **shipped on `main`** behind `NIGHTSTALKER_FEATURE_GATES=tls_sni=1` (see `2026-04-12-tls-clienthello-sni-detect.md`). **Open product gaps:** richer **`sport` / `saddr` / `flow_id`** in JSONL; **ringbuf drop / reserve-failure** counters beyond enforce-mode deny path (see implementation checklist note). The historical feature branch name was `feat/egress-full-stack`.  
> **Scope:** GitHub-hosted **`ubuntu-latest` (amd64)**, **detect-only** (observe, never block). **Clean-room** (original code; no copied third-party implementations).  
> **Goal:** No “shortcut” story in the product: users can see **TCP**, **UDP**, and **HTTP (cleartext v1; TLS metadata later)** as **first-class signals**, with tests and a **readable** presentation—not a single overloaded Markdown table.

**Repository state (2026-04-12):** Phases **0–4** match **`main`** today (see blockquote **Status**). **Open product gaps** tracked here: **Phase 5** TLS/SNI (optional); richer **4-tuple** / **`flow_id`** in JSONL; first-class **ringbuf drop** counters in shutdown telemetry if we expand forensics.

---

## Product constraint: report must appear in **Actions output** (no HTML download)

**Requirement:** The useful report is **fully visible** on the workflow run **Summary** tab (content merged from **`GITHUB_STEP_SUMMARY`**). Users must **not** depend on downloading an HTML file or opening a separate artifact to understand the run.

**What GitHub actually supports** (see [Adding a job summary](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary) and [Job Summaries blog](https://github.blog/news-insights/product-news/supercharging-github-actions-with-job-summaries/)):

| Mechanism | Implication for Nightstalker |
|-----------|--------------------------------|
| Rendering = **GitHub Flavored Markdown** (+ same general rules as issues/PRs for **limited raw HTML**) | Design for **GFM-first**: headings, tables, lists, **`<details>` / `<summary>`**, links. **No `<script>`**; **no** reliance on custom SPA/CSS like a downloaded HTML page. **Mermaid** diagrams are in scope for high-level views. |
| **1 MiB per step** summary payload | Implement **hard caps** and **truncation** with explicit footers (“*Showing last N of M — full stream in JSONL in workspace*”). Prefer **aggregates + top-N** in Summary, **full fidelity** remains in **`.nightstalker-events.jsonl`** on disk. |
| **Up to 20 step summaries** shown per job | Prefer **one** consolidated write path for the detect report (today: **post** step merges workspace markdown into Summary—keep consolidation, avoid scattering huge reports across many steps). |
| **Secrets masking** | Avoid leaking tokens in Summary text; sanitize or omit sensitive URL/query parts in HTTP rows. |

**Optional:** A generated `.html` may still exist for **advanced** users or mirroring, but it is **not** part of the default “success” UX and **must not** be required.

---

## Problem statement

Today, the job Summary / `.nightstalker-detect.md` is effectively:

- **`exec`** rows + **`tcp`** rows only.
- **DNS/UDP** work exists under the hood but surfaces mainly as **`fqdn`** hints inside **TCP Notes**.
- **HTTP** is only a **`cleartext-http`** tag when `dport == 80`, still on a **TCP** row.

That is **confusing** when the roadmap language says “TCP / UDP / HTTP,” and it is **easy to mistake** for “broken reporting” rather than “intentionally folded into Notes.”

This plan defines **full capabilities** (real BPF events + schema + UI) in **phases**, each phase shippable and testable.

---

## Non-goals (explicit)

| Item | Reason |
|------|--------|
| TLS payload decryption | Illegal/impractical for this action; out of scope |
| Blocking / killing processes | Detect-only product direction |
| Non-`ubuntu-latest` runners | Unsupported unless you expand support later |
| Perfect cgroup-scoped attribution on shared runners | Hostile to shared CI; best-effort PID/comm only |
| QUIC / HTTP/3 full parse | High complexity; later track |

**TLS without decrypt (optional later phase):** extracting **SNI** from plaintext **ClientHello** (first TLS record) is a **separate** BPF+parse track—not part of “HTTP” cleartext.

---

## Design principles

1. **One canonical event stream** — append-only **JSONL** (or equivalent) with a **discriminated `type`** field (`exec` | `tcp` | `udp` | `http` | …). Markdown/HTML are **views** over that stream (or over aggregated counters + recent rows).
2. **No fake rows** — if we claim “UDP,” we emit **UDP-shaped events** from BPF (or clearly label DNS as `dns` subtype of UDP).
3. **Tests match claims** — nightstalker-demo + integration assert **each** major signal class the UI promises (not only `**tcp**` + `fqdn`).
4. **UI: progressive disclosure** — KPI block up front; **per-protocol** `<details>` sections; **separate GFM tables** per type (columns match the data).
5. **Summary-native “beauty”** — maximize clarity **inside** Job Summary: hierarchy, spacing, consistent column order, **monospace** for IPs/ports via backticks, **badges** via Unicode or short text (not images), optional **Mermaid** for “signal flow” or counts. **No** dependency on downloaded HTML for core value.
6. **Forensics-first canonical log** — the **JSONL** stream is the **source of truth** for incident review; the Job Summary is a **digest** that must **not contradict** counts/ordering and must **state truncation** and **tool version** so reviewers know what they are missing.

---

## Forensics / DFIR bar (senior security staff engineer)

**Goal:** After a workflow run, a reviewer can answer—**from artifacts we control**—the usual investigation questions **within honest limits** of eBPF on **shared GitHub-hosted runners**.

### Questions the design must support

| Question | Where answered | Notes |
|----------|----------------|--------|
| **When** did it happen? | Every JSONL line: **`ts`** (UTC, **RFC3339Nano**); optional **`mono_ns`** later for ordering | Wall clock + monotonic if we add kernel-side or userspace seq |
| **What** process? | **`pid`**, **`tgid`**, **`comm`**; **`ppid`** when BPF/trace data allows | `comm` is 16-byte task name—not argv; document gap |
| **What** network action? | **TCP** / **UDP** / **HTTP** typed events with **4-tuple** where available (**src IP/port**, **dst IP/port**), **direction** (`egress` / `ingress` / `unknown`) | Today TCP path may be **connect-only**; plan to add **success/fail** if `sys_exit_connect` (or equivalent) is portable |
| **Where** (remote)? | **IP**, **port**, **FQDN** (from DNS cache, with **provenance**: `dns_observed` vs `unknown`) | FQDN is **best-effort** correlation, not a guarantee |
| **What** HTTP (cleartext)? | **`http`** records: **method**, **host**, **path** (truncated), **`dport`**, link to **TCP tuple** or **`flow_id`** | **Redact** query strings / cookies by default in Summary; full policy in JSONL config |
| **Policy / classification** | **`policy`** (or equivalent) on relevant rows; **shutdown summary** aggregates | Must match what SecOps configured (`allowed-hosts` / `allowed-ips`) |
| **What** ran (exec)? | **`exec`** JSONL rows: at least **pid, comm, ts**; extend toward **filename/argv** only if BPF/kernel exposes reliably | `sched_process_exec` gives path-like info in kernel structs—evaluate CO-RE fields |
| **Which** run / environment? | **Run provenance** block (see below) | Binds log to **one** Actions invocation |

### Canonical artifact: **append-only JSONL**

- **One JSON object per line**, UTF-8, **append-only** during the job (no rewrite of past lines).
- **First line (recommended):** a **`type: "meta"`** (or `"run_context"`) object written once at agent start, including at minimum:
  - **`schema_version`**, **`agent_version`** (git tag / build id), **`nightstalker` semver**
  - **`kernel_release`** (from `uname` or `/proc/version` in agent)
  - **`github`** object: `repository`, `workflow`, `run_id`, `run_attempt`, `job`, **`sha`**, `ref`, `actor` (from `GITHUB_*` env—**no secrets**)
  - **`bpf`**: list of attached programs and **degraded/skipped** hooks with **reason** (forensics must know blind spots)
- **Every event line** includes: **`type`**, **`ts`**, **`seq`** (monotonic integer per run, assigned in userspace) for **stable sort** and dedup in SIEM.
- **Shutdown artifact** (`.nightstalker-telemetry.json` or successor): **counts**, **first/last ts**, **per-type totals**, **ringbuf drops** if exposed, **`finished`**, **`version`**.

### Job Summary vs JSONL (reviewer expectations)

- **Summary:** human **triage**—KPIs, top-N, collapsible tables—explicit **“truncated”** footer with **path to JSONL** on workspace and **seq** range shown.
- **JSONL:** **complete** (subject to **kernel visibility**, **sampling**, and **caps**). SecOps should **ingest JSONL** (artifact upload, log forwarder, or checkout) for **full** review; Summary alone is **not** a legal “complete log” claim.

### Limitations we must document (honesty for staff engineers)

- **Shared runner:** other jobs’ noise is absent, but **PID reuse** and **missing cgroup** attribution are real; we do **not** claim process-tree perfection.
- **Connect attempt vs success:** until **exit syscall** correlation ships, TCP may log **intent**, not **established socket**—doc explicitly.
- **DNS:** cache is **TTL-bounded**; late answers may be missing; **NXDOMAIN** still matters for investigations—emit when parseable.
- **TLS:** **no** URL for `https://` without **SNI** / metadata phase; do not imply visibility we do not have.
- **No anti-tamper by default:** workspace on runner is **trusted to GitHub**; out-of-band integrity (signed artifacts, WORM storage) is **consumer responsibility**.

### Implementation checklist (add to phases)

- [x] **`meta`** JSONL line + **`seq`** on all events.
- [x] Extend **`TCPEvent`** / related structs on **`main`**: **`tgid`**, **`direction`**, **`fqdn_provenance`** (plus UDP/HTTP analogs). **`sport`**, **`saddr`**, and **`flow_id`** remain **future** optional fields.
- [x] **Redaction** for Summary HTTP paths: query strings stripped via **`RedactPathForSummary`** (userspace); full paths remain in JSONL unless further policy is added later.
- [x] **Telemetry summary** (`.nightstalker-telemetry.json`) includes **BPF health**, totals, **kernel_release**, **schema_version** — ringbuf **drop** counters are not yet a first-class field everywhere.
- [x] README **“Forensics (honest limits)”** subsection documents correlation expectations and blind spots.

---

## Target architecture

```text
┌─────────────────────────────────────────────────────────────┐
│  eBPF (CO-RE, tracepoints / approved attach types)          │
│  trace_exec │ trace_tcp_connect │ trace_udp_* │ trace_http_* │
└─────────────┬───────────────────────────────────────────────┘
              │ ringbuf / maps
              ▼
┌─────────────────────────────────────────────────────────────┐
│  Go agent (agent_linux.go + small packages)                  │
│  decode → normalize → policy (where applicable) → sinks      │
└─────────────┬───────────────────────────────────────────────┘
              │
     ┌────────┴────────┬────────────────────────────┐
     ▼                 ▼                            ▼
 .jsonl (canonical)  .nightstalker-detect.md       (optional) .html
     │                 (GFM: KPI + sections)        archive only
     │                            │
     └────────────────────────────┴────────────────────────────┘
                                  ▼
              Actions **post** step → `GITHUB_STEP_SUMMARY`
              (single merged Job Summary — primary UX)
```

---

## Phase 0 — Inventory & hook research (short)

- Document which **syscalls / tracepoints** on `ubuntu-latest` give:
  - **TCP:** already `connect` via `raw_syscalls/sys_enter` pattern; consider **`accept4`** / **`bind`** for server-side visibility (optional).
  - **UDP:** `sendto` / `recvfrom` (or `sendmsg`/`recvmsg`) with **IPv4** sockaddr, **PID/comm**.
  - **HTTP:** no single “HTTP tracepoint”; need **payload-adjacent** hook (see Phase 3).
- Output: extend [`docs/superpowers/specs/2026-04-10-network-hook-notes.md`](../specs/2026-04-10-network-hook-notes.md) with UDP + HTTP candidate matrix and **reject reasons**.

**Exit:** written spike; no user-facing change.

---

## Phase 1 — Unified event model & sinks

- Define **`internal/telemetry/event.go`** (or similar): common header **`type`**, **`ts`** (RFC3339Nano UTC), **`seq`** (monotonic), **`pid`**, **`tgid`**, **`comm`**, plus type-specific payloads.
- Emit a single leading **`meta` / `run_context`** JSONL record (agent/kernel/GitHub/BPF status—**no secrets**).
- Extend JSONL to emit **`udp`**, **`dns`** (if split from generic UDP), **`http`** when available.
- Extend shutdown **`Summary`** JSON: counts per type, policy rollups, **`kernel_release`**, **BPF attach/degrade** notes, **ringbuf drops** if available.
- **Backward compatibility:** bump `summary.version` / **`schema_version`** in `meta`; document breaking changes in README.

**Tests:** unit tests for marshal/unmarshal and for “unknown type ignored safely” in consumers.

**Exit:** schema ready; agent still may only emit subset until later phases.

---

## Phase 2 — UDP (generic + DNS)

**BPF:** New program(s) (e.g. `bpf/trace_udp.bpf.c` + `internal/bpf/traceudp/`) attached with same portability rules as TCP (prefer **tracepoints**, avoid flaky `fentry` on runners).

**Emit:**

- **`udp`** events: `dst_ip`, `dport`, `sport` (if available), direction hint (`egress`/`ingress` if derivable), raw length (optional).
- Optionally **`dns`** as `udp` with `dport=53` and **parsed** qname/rcode in userspace (reuse/extend `dns_wire.go`), or keep DNS as cache-only **plus** optional **`dns`** JSONL rows for visibility.

**Report:** new table section **“UDP”** (or **“UDP / DNS”**) with columns that match the data (not TCP’s columns forced onto UDP).

**Tests:**

- **Unit:** DNS/UDP parsers (fixtures).
- **Integration (linux):** `dig` / `nc -u` style probe; assert JSONL type `udp` or `dns` and Summary counts.
- **nightstalker-demo:** `grep` for section header or JSONL type (choose one stable contract).

**Exit:** users can see **UDP** without inferring it from TCP Notes.

---

## Phase 3 — HTTP (cleartext), no illusions

**Reality:** “Full HTTP” means **parsing HTTP/1.x on cleartext paths** (typically **port 80** or known plaintext). It does **not** mean “see HTTPS URLs” without TLS metadata work.

**Recommended approach (full, not a fake flag):**

1. **Flow association:** reuse TCP connect events `(pid, 4-tuple)` as key (best-effort).
2. **Payload capture (bounded):** BPF on a **supported** hook to copy **first N bytes** (e.g. 256–512) of **egress** data on **sockets that are IPv4 TCP and dport 80** (and optionally **sport 80** for responses). Candidate families: `tracepoint/syscalls/sys_enter_sendto` / `sendmsg` / `write` (evaluate portability per Phase 0).
3. **Userspace parse:** identify `GET`, `POST`, `Host:` header, request line; emit **`http`** JSONL: `method`, `host`, `path` (truncated), `http_version`, `ts`, `pid`, `comm`, `dst`, `dport`.

**Emit separate `http` rows** in the rich report (and/or annotate linked TCP row ID if you add event IDs).

**Tests:**

- **Unit:** HTTP parser on captured fragments (fixtures including partial packets).
- **Integration:** curl to `http://` endpoint; assert `http` events.
- **nightstalker-demo:** assert presence of **`http`** section or JSONL type (in addition to TCP :80).

**Exit:** HTTP is **visible as its own signal**, not only `cleartext-http` in Notes.

---

## Phase 4 — Report UI (**Job Summary only**, maximum usefulness)

**Deliverable:** Everything the user needs is in **`.nightstalker-detect.md`** (and copied into **Summary** by the existing post step). Format is **GFM + allowed HTML** only.

### 4.1 Document shape (top → bottom)

1. **Title + one-line legend** (what is detect-only, what `comm` means).
2. **KPI table** (GFM): rows or columns for **exec / tcp / udp / http** counts, **policy** rollups (if applicable), **run wall time** if available, **BPF programs loaded** (ok/degraded).
3. **Optional Mermaid** block: simple diagram or **pie** of event mix (if Mermaid syntax stays small—watch **1 MiB** budget).
4. **`<details open>` for “Exec (last N)”** — short table: time, PID, comm.
5. **`<details>` for “TCP (last N)”** — columns: time, PID, comm, remote, notes (fqdn / cleartext hint), policy.
6. **`<details>` for “UDP / DNS (last N)”** — columns appropriate to Phase 2 schema.
7. **`<details>` for “HTTP (last N)”** — method, host, path (truncated), pid, comm, dst:port.
8. **Footer:** exact **truncation** message + pointer to **`NIGHTSTALKER_EVENTS_LOG`** / default JSONL path for full export inside the workspace (still **no download required** for overview; power users can `actions/checkout` or artifact if they choose).

### 4.2 Size & performance strategy (required)

- Constants in config or report package: e.g. `SummaryMaxBytes` target **well under 1 MiB** (reserve margin for step overhead).
- **Per-section row caps** (e.g. 100–200 each); **newest-first** or **most-recent-by-type** policy documented.
- **Deduplication** optional for noisy UDP (collapse identical 4-tuple bursts into count—later optimization).

### 4.3 Implementation sketch

- **`internal/report/`**: builders that take **in-memory rollups + ring buffers of last N events** (fed from agent) and emit **one** markdown string or incremental writes to `.nightstalker-detect.md`.
- **Post step** unchanged in spirit: **append/merge** workspace detect file into **`GITHUB_STEP_SUMMARY`** (ensure final payload respects size limits—if file too large, post step could **truncate** with warning—design explicitly).

### 4.4 Tests

- **Golden tests** for generated markdown sections (stable headers + sample rows).
- **nightstalker-demo** `grep` / assertions on **section headers** and **KPI table** markers, not only `**tcp**`.

**Exit:** Summary tab is **useful, structured, and honest** about truncation; JSONL remains **canonical** for completeness.

---

## Phase 5 — TLS ClientHello / SNI (**shipped**)

- **Implemented:** BPF capture on `write(2)` / `sendto(2)` with userspace **`ParseClientHelloSNI`**; JSONL **`type":"tls"`** with **`sni`**; digest **TLS ClientHello** section + KPI row; feature gate **`tls_sni=1`**; nightstalker-demo **`curl --http1.1`** probe (avoids QUIC bypassing TCP sniff).
- **Report:** own section; never labeled as “HTTP.”

---

## CI / nightstalker-demo requirements (cross-cutting)

- Every new **type** must have:
  - **Unit tests** (parse/format).
  - **nightstalker-demo assertion** OR **integration test** on Linux CI (live network where required per AGENTS).
- **`scripts/docker-ubuntu-test-inner.sh`:** keep **generate / vet / staticcheck / test** green; document if new packages need `go generate`.

---

## Migration / rollout

1. Ship **schema + empty Summary sections** (explicit “0 UDP / 0 HTTP” in KPI) before BPF fills them.
2. Turn on **UDP BPF** → populate UDP `<details>` + KPI.
3. Turn on **HTTP parse** → populate HTTP `<details>` + KPI.
4. Tune **N** and **byte cap** after nightstalker-demo runs on real jobs; document limits in README.

---

## Open decisions (resolve before coding)

| # | Question |
|---|----------|
| 1 | **UDP default:** log **all** UDP datagrams (noisy) vs **sample** vs **ports-of-interest** list (configurable)? |
| 2 | **HTTP response** parsing (status line) in v1 or defer to v2? |
| 3 | **Summary row caps:** default **N** per section (e.g. 100 vs 250) and whether **exec** is capped the same as network. |
| 4 | **Mermaid in Summary:** yes/no (adds clarity vs bytes and render risk on very large diagrams). |
| 5 | *(Optional)* **Offline HTML** for enterprise mirrors only—off by default, not part of core UX. |

---

## Success criteria (definition of done)

- [x] JSONL contains **`tcp`**, **`udp`**, and **`http`** (cleartext) events on a nightstalker-demo run with **no manual interpretation** of Notes.
- [x] **Forensics:** JSONL opens with **`meta`**, events carry **`seq`** + **`ts`**, shutdown JSON includes **BPF health** and **counts**; README documents **limitations** (connect vs established, FQDN provenance, PID semantics).
- [x] **Job Summary** (via merged markdown) includes a **KPI table** + **per-type** collapsible sections with **appropriate columns**—not one overloaded mega-table.
- [x] Truncation is **explicit** in the Summary footer; full stream remains in **JSONL** on the workspace.
- [x] **Tests** cover markdown KPI/sections (`digest_test`); nightstalker-demo asserts **udp** / **http** in digest + JSONL.
- [x] README states **Summary-only** UX and **GitHub limits** (size, no scripts).
- [x] Docs honestly describe **HTTPS limits** and what “HTTP monitoring” means.

### Open decisions (resolved for v1)

| # | Resolution |
|---|-------------|
| 1 | UDP: log **all** IPv4 `sendto` egress in v1 (ringbuf-bounded); tune ports/sampling later if needed. |
| 2 | HTTP **response** parsing: **deferred** (requests-only v1). |
| 3 | Summary row cap: **`DefaultMaxRowsPerSection = 120`** per collapsible table. |
| 4 | **Mermaid:** **no** in v1 (byte budget + render risk). |

---

## Suggested next step (process)

1. Review this plan and answer **Open decisions**.
2. Run **Phase 0** hook spike (short doc update).
3. Use **writing-plans** to break Phases 1–4 into checkbox tasks (BPF, Go, **Summary markdown builders**, post-step size guard, workflows).
4. Implement on a **feature branch**; merge after CI + nightstalker-demo green.
