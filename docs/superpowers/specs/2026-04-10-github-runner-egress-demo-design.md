# GitHub runner egress demo: detect + enforce, TCP / UDP / HTTP

**Repository state (2026-04-12):** Detect/enforce behaviors, bounded **deny-ring draining**, and nightstalker-demo ordering described here are **implemented on `main`**. Executable checklist: **`docs/superpowers/plans/2026-04-10-github-runner-egress-demo.md`**.

## Summary

Make **nightstalker** demonstrable on **GitHub-hosted `ubuntu-latest` (amd64)** with:

- **Detect mode:** visible **TCP**, **UDP**, and **HTTP** (cleartext) telemetry in `.nightstalker-events.jsonl` and `.nightstalker-detect.md`.
- **Enforce mode:** **IPv4 allowlist** proven by **allow** + **deny** behavior, with **TCP** and **UDP** deny evidence; **HTTP** visibility comes from **cleartext** traffic to an **allowlisted** host (same limitation as detect).

**Scope:** IPv4-only for enforcement and domain resolution in v1. **IPv6** is out of scope for this spec (document explicitly).

This spec **extends** [2026-04-10-enforce-mode-egress-allowlist-design.md](./2026-04-10-enforce-mode-egress-allowlist-design.md): that document specified **fail fast on first deny**. For **demo and CI**, we require **enough deny telemetry** to show **both** TCP and UDP blocks in one run; see **Enforce runtime behavior** below.

## Non-goals

- TLS decryption or HTTP semantics on **HTTPS** (port 443).
- Perfect cgroup isolation on shared runners.
- Replacing `dig` / `/dev/udp` with `curl` for raw UDP (UDP is not HTTP; `curl` is for TCP HTTP(S) only).

## Telemetry semantics (what “HTTP” means)

| Traffic | Appears as | Notes |
|--------|------------|--------|
| `curl http://…` (cleartext, typically port 80) | **http** events (when sniff path fires) + **tcp** | L7 preview is **best-effort** and **bounded**; may be partial. |
| `curl https://…` | **tcp** (connect path) | No HTTP body visibility without TLS termination. |
| DNS / generic UDP (e.g. `dig`) | **udp** | Port 53 often used as a high-signal DNS pattern in digest checks. |

**Detect:** Run **cleartext HTTP**, **HTTPS**, and **UDP** probes so all three classes appear in artifacts.

**Enforce:** Run **cleartext HTTP** and **HTTPS** only to **allowlisted** destinations so **http** and **tcp** rows can still be emitted **before** disallowed probes trigger denies. Disallowed **`curl`** produces **tcp** deny events (and may not emit **http** lines for that attempt).

## eBPF capability checklist (v1, IPv4)

| Capability | Mechanism | Detect | Enforce |
|------------|-----------|--------|---------|
| TCP observe | Syscall tracepath (`connect`, etc.) | Yes | Yes (allowed traffic); denied connect → **deny** |
| UDP observe | Syscall tracepath (`sendto` path) | Yes | Yes (allowed); denied sendmsg path → **deny** |
| Cleartext HTTP sniff | Syscall buffer sniff (port 80–style path in agent BPF) | Yes | Yes for **allowed** cleartext only |
| TCP block | `cgroup/connect4` + `allowed_ipv4` map | No | Yes |
| UDP block | `cgroup/sendmsg4` + same map | No | Yes |
| Deny stream | `deny_events` ringbuf → JSONL / digest | No | Yes |

**Runner assumptions:** CO-RE/BTF as today; attach cgroup programs at the **root cgroup** path used by the agent (current implementation); **no** claim of NIC XDP or per-job network isolation.

## CI layout (`nightstalker-demo.yml`)

Keep **two jobs** (isolated failure domains, readable logs):

1. **Detect job** (existing pattern, tightened):
   - **TCP / HTTPS:** `curl -fsS --max-time … https://…` (bounded attempts per AGENTS.md).
   - **Cleartext HTTP:** `curl -fsS --max-time … http://…` (host must respond on HTTP; may follow redirects—document if assertions are fragile).
   - **UDP:** `dig +time=1 +tries=1 @…` (or equivalent bounded DNS UDP) instead of relying on `nc` where possible.
   - Assertions: extend current `grep` / shape checks so **tcp**, **udp**, and **http** sections or JSONL types are **present** (exact patterns aligned with `internal/report/digest.go` labels).

2. **Enforce job:**
   - **Allowlist** one real domain (e.g. `google.com`)—must resolve to **at least one IPv4** at agent start.
   - **Allow — TCP:** `curl` HTTPS to allowlisted host.
   - **Allow — HTTP:** `curl` HTTP to same or other allowlisted host (cleartext) so **http** telemetry can appear.
   - **Deny — TCP:** `curl` HTTPS to a **non-allowlisted** host (e.g. `microsoft.com`)—expect **deny** with `protocol` tcp.
   - **Deny — UDP:** bounded UDP to a destination **not** in the IPv4 map (e.g. prior pattern `1.1.1.1:53` via `/dev/udp` or `dig`)—expect **deny** with `protocol` udp.
   - Log **resolved A records** for allowlisted and probe hosts in the job log (debuggability, IPv4-only honesty).

**Ordering:** Perform **allowed** cleartext HTTP and HTTPS **before** deny probes so **http** / **tcp** detect telemetry is flushed while the agent is still healthy; then run deny probes.

## Enforce runtime behavior (deny drain for CI)

The prior enforce design specified **fail fast on first deny**. That leaves **at most one** deny line in JSONL if the first deny cancels readers immediately—insufficient to prove **both** TCP and UDP enforcement in one job.

**Requirement:** In **enforce** mode, after a deny is observed, userspace **drains additional deny events** for a **bounded** window (e.g. a few hundred milliseconds to ~2 seconds, or until the ring buffer has no pending deny records up to a **max event cap**), appends each to JSONL, updates digest state, **then** fails the run (non-zero) if any deny occurred (or follow existing product rule: fail on any deny).

**Constraints:**

- Bounded time and max events to avoid hanging CI.
- No change to **verdict** semantics in BPF—only **userspace read loop** behavior.

If drain is undesirable for non-CI use, the implementation may gate extended drain behind an env flag; the spec’s **default for enforce** should still satisfy **one** nightstalker-demo job showing **tcp + udp** denies unless we explicitly split jobs (avoid unless drain is rejected).

## Assertions (enforce job)

- `.nightstalker-events.jsonl` contains:
  - At least one **`"type":"http"`** or digest shows HTTP section populated (allowed cleartext probe).
  - At least one **`"type":"deny"`** with **`"protocol":"tcp"`** (disallowed HTTPS probe).
  - At least one **`"type":"deny"`** with **`"protocol":"udp"`** (disallowed UDP probe).
  - Deny lines include **`reason":"dst_not_allowlisted"`** and **`mode":"enforce"`**.
- `.nightstalker-detect.md` includes enforcement section and **First deny** / rollup consistent with JSONL.

## Demo narrative (operator-facing)

- **Detect:** “We see **TCP** (including HTTPS connects), **UDP** (e.g. DNS), and **cleartext HTTP** where the stack exposes bytes.”
- **Enforce:** “**Allowlisted** destinations work; **others** are blocked; denies are **tcp** or **udp**; **HTTP** lines in the log come from **allowed** `http://` probes, not from blocked HTTPS.”

## Testing outside CI

- Prefer **`bash scripts/docker-ubuntu-test.sh`** (or project-documented Linux path) for local parity; Windows remains build-only for Go where tagged.

## Open implementation tasks (for planning phase)

1. **Agent:** Implement **bounded deny drain** in the deny ringbuf reader path for enforce mode (details in plan).
2. **nightstalker-demo.yml:** Replace `nc` with **`curl`** / **`dig`** per matrix; set allowlist and deny hosts; add greps for **http** + **tcp** + **udp** denies.
3. **Docs / AGENTS:** One short paragraph on **HTTP = cleartext**, **HTTPS = TCP-only** for L7, and **IPv4-only** enforcement.

## Self-review

- **Placeholders:** None; hosts are examples—implementation may fix exact domains to match AGENTS egress caps.
- **Consistency:** Aligns with IPv4 map + cgroup programs; extends first-deny-only story for CI proof.
- **Scope:** Single implementation track (agent + workflow + minor doc); IPv6 explicitly excluded.
- **Ambiguity:** **HTTP in enforce** is only guaranteed for **allowlisted cleartext** probes; denied HTTPS shows as **tcp deny**, not http.
