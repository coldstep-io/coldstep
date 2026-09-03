# Coldstep Quick Start

**v1:** the composite agent is validated and supported on **`runs-on: ubuntu-latest`** only. Pin the published action at **`coldstep-io/coldstep@v0.6.2`** (or a newer tag from [Releases](https://github.com/coldstep-io/coldstep/releases)). **Repository changes** are validated via **GitHub Actions** (open a PR or use **`workflow_dispatch`** on **`coldstep-ci`**, **`coldstep-demo`**, **`coldstep-demo-detect`**, or **`coldstep-demo-defend`**). There is no maintained local build path for the Linux agent.

## Two modes (read this first)

Coldstep exposes **two** mode names in `with:` and env **`CI_GUARD_MODE`**: **`detect`** and **`defend`**. Use **`defend`** for blocking.

| You want… | Set |
| :-------- | :-- |
| Observe-only telemetry (default) | `mode: detect` or omit `mode` |
| Block egress not on the allowlist | `mode: defend` + non-empty **`allow`** / **`allow-file`** |

> **Coverage scope:** **detect** mode observes **IPv4 TCP/UDP** only (IPv6 not observed). **defend** mode enforces **IPv4 _and_ IPv6 TCP/UDP** — cgroup `connect4`/`sendmsg4` plus `connect6`/`sendmsg6`, with native IPv6 gated against an AAAA-resolved `allowed_ipv6` LPM trie; `::1` and `fe80::/10` bypass by design. **QUIC/HTTP3 and Unix socket traffic remain uncovered** (QUIC inner framing uninspected; AF_UNIX silently bypassed). See **[SECURITY.md → Coverage Boundaries](SECURITY.md#coverage-boundaries)** for the full matrix.

---

## Promoting detect observations to an allowlist

Detect mode records **everything** your build talks to. The whole point is to use those JSONL records to build the `allow:` list you will run in `defend`. **A supply-chain compromise that occurs while you are still recording will get baked straight into the allowlist** — there is no built-in trust signal that says "this domain is legitimate, that one is the attacker." Treat allowlist promotion as a code change with the same review bar as any other security-sensitive merge.

Recommended workflow:

1. **Collect ≥ 3 builds.** Run detect across at least three different PRs or branches (preferably touching different parts of the codebase). One short run on one branch is the easiest poisoning target.
2. **Diff against a baseline.** Before promoting domains to `allow:`, compare the new JSONL against a known-good baseline:
   ```bash
   coldstep diff \
     --baseline baseline.jsonl \
     --current  .coldstep-events.jsonl \
     --summary  diff-summary.md \
     --fail-on-new-domain
   ```
   `--fail-on-new-domain` exits non-zero when any destination FQDN appears in the current run but not the baseline. Wire it into CI on PRs that touch `.github/coldstep/egress-allow.txt`.
3. **Require a second-engineer review.** Newly observed domains in the diff output get a separate human approval before they land in the `allow:` list. Treat the diff as a code review, not as an automated step that closes itself.

> **Note (report pipeline change):** the older `coldstep-report build-model` model — including the `suspicious_domains` / `risk_hint` heuristics (high-entropy/DGA labels, single-observation, port anomalies) and the `--min-observation-hours` window gate — was removed when reporting was consolidated into a single pure-markdown path. The surviving programmatic gates are `coldstep diff --fail-on-new-domain` (baseline new-domain) and `coldstep assert-integrity` (required event types). The manual-review discipline below still applies; the entropy/window heuristics are a candidate to reintroduce in the markdown generator if needed.

### Building a safe allowlist (manual review discipline)

The baseline diff catches **new** domains, but a human should still review newly observed destinations before promoting them to `allow:`. Two shapes warrant extra scrutiny:

- **DGA-shaped hosts** — a leftmost label that is long, high-entropy, or hash-like is characteristic of malware C2 / ephemeral exfil. Confirm it is a legitimate object-store / CDN URL.
- **Single-observation domains** — a host seen exactly once is the fingerprint of a briefly-poisoned learning run. Compare against a longer-window baseline before promoting.

Recommended bar before promoting any new domain:

- **Baseline diff with `--fail-on-new-domain`** on the PR that edits `allow:` / `allow-file` — the one step that catches a domain a single reviewer might wave through.
- **Collect several builds** across different PRs before trusting the observed set; one short run on one branch is the easiest poisoning target.
- **Manual review of DGA-shaped / single-observation hosts** — reviewer-driven by design.

---

## Bare minimum

Smallest workflow that runs Coldstep in **detect** mode: **`checkout` → single `uses:` block → your steps**. The action's node24 `pre` hook starts the agent before your build steps; `post` flushes the digest at job end.

```yaml
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: coldstep-io/coldstep@v0.6.2
      - run: echo "your build/test steps here"
```

You get default **detect** telemetry, **`.coldstep-events.jsonl`**, and the digest merged into the **Job Summary** (default **`report: job-summary`**).

---

## Recommended starter (copy/paste)

Same single-block lifecycle, with explicit **`name`/`on`** for a full job you can drop into a repo:

```yaml
name: coldstep

on:
  push:
  pull_request:

jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: coldstep-io/coldstep@v0.6.2
      - run: echo "build/test/deploy steps"
```

---

## All action inputs (summary)

Every `with:` key the action accepts (defaults are what you get if you omit the key). Use **one `uses:` block per job** — node24 pre/post hooks start the agent before your steps and flush the digest at job end.

| Input | Default | Summary |
| :---- | :------ | :------ |
| **`mode`** | `detect` | **`detect`** — observe only. **`defend`** — block non-allowlisted egress. |
| **`allow`** | *(empty)* | Comma/newline-separated egress allowlist. Accepts plain domains (`example.com`), wildcard domains (`*.example.com` — **detect only**, rejected at parse time when `mode: defend`), IPv4/IPv6 literals (`1.2.3.4`, `2001:db8::1`), and CIDRs (`10.0.0.0/8`, `2001:db8::/32`). Prefix a CIDR with `!` to ignore that net (e.g. `!192.168.0.0/16`). Entries are auto-classified. |
| **`allow-file`** | *(empty)* | Comma-separated workspace paths to UTF-8 files; same format as `allow`. Merged after inline `allow`. |
| **`no-default-ignored-nets`** | `false` | If **`true`**, do **not** add implicit **`10.0.0.0/8`** and **`172.16.0.0/12`** ignores. Add your own ignores as **`!CIDR`** entries in **`allow`** / **`allow-file`** (the only ignore mechanism; max **128** CIDRs). |
| **`detect-profile`** | `standard` | **`detect` only**: `standard` (default) or `enhanced`. Enhanced enables `proc_tree`, `tls_sni`, and `fs_events`, and tightens report-model integrity. |
| **`report`** | `job-summary` | Where to post the detect digest: `job-summary`, `pr-comment`, `both`, or `none`. |
| **`fail-on-error`** | `false` (detect) / `true` (defend) | If **`true`**, fail when the agent never reaches **operational readiness** (BPF/trace/cgroup). Does **not** fail on policy/deny traffic alone. With the detect default (`false`) the workload starts without waiting for BPF attach — a short job can finish before anything is captured (the stop step emits a "no events captured" warning). **Set `true` for short detect jobs.** |
| **`ready-timeout-seconds`** | `1500` | Only when **`fail-on-error`** is **`true`**: max seconds to wait for **`.coldstep-ready.json`** (`ok:true`). Clamped **60–2700**; malformed **`ok:false`** fails fast. |
| **`log-level`** | `info` | Agent stderr log level: **`debug`**, **`info`**, **`warn`**, **`error`**. |
| **`github-token`** | `${{ github.token }}` | Token for PR comments when **`report`** is **`pr-comment`** or **`both`**. |
| **`signing-key`** | *(empty)* | Optional base64 **Ed25519** seed/key; when set, JSONL events are signed. |

**Environment (job-level):** workflows may set **`CI_GUARD_MODE`** to **`detect`** or **`defend`** instead of **`mode:`** in `with:` — same validation rules as **`mode`**.

---

## Validation (what automation proves)

Coldstep’s CI and tests prove **specific scenarios on GitHub-hosted Linux**, not every sentence in the docs. Read **[VALIDATION.md](VALIDATION.md)** for the detect vs defend matrix, job names (`detect-mode`, `defend-mode`, …), and honest limits (self-hosted, adversarial bypass, …).

---

## Versioning

- Prefer **`coldstep-io/coldstep@v0.6.2`** (or a **newer tag** you publish). **`@main`** tracks the default branch and can change without notice.
- The early **`v0.1.0`** tag is not usable (it lacks repo-root **`action.yml`**); use **`v0.2.1`** or a newer published tag that includes **`action.yml`**.

**Example workflows in this repo** (all use `uses: ./` and are triggered with **`workflow_dispatch`** except **`coldstep-detect-demo-dev`** which also runs on **`push` to `dev`**): **[`coldstep-demo-detect.yml`](.github/workflows/coldstep-demo-detect.yml)** (minimal detect), **[`coldstep-demo-defend.yml`](.github/workflows/coldstep-demo-defend.yml)** (minimal **defend**), **[`coldstep-demo.yml`](.github/workflows/coldstep-demo.yml)** (full integration / drift), and **[`coldstep-detect-demo-dev.yml`](.github/workflows/coldstep-detect-demo-dev.yml)** — same agent detect setup on **`dev`** with full BLUF + HTML artifact plus an extra **IP classification** Job Summary section.

---

## Add useful controls

```yaml
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: coldstep-io/coldstep@v0.6.2
        with:
          detect-profile: enhanced
          report: job-summary
          fail-on-error: true
          log-level: info
      - run: echo "your build/test/deploy steps"
```

### What these controls do

- `detect-profile: enhanced`: enables `proc_tree` (fork edges + process tree), `tls_sni` (TLS ClientHello / SNI rows, `"type":"tls"`), and `fs_events` (filesystem events, `"type":"fs_event"`). Precedence is resolved once (`config.ResolveDetectProfile`): an explicit `--detect-profile` flag wins, then the `COLDSTEP_DETECT_PROFILE` env, then the `standard` default — the same resolution applies to the agent, `coldstep start`, `coldstep stop --strict`, and `coldstep assert-integrity`. The feature gates above are derived from this single value (there is no separate `feature-gates` input).
- `report: job-summary` (default): merge the digest into the Job Summary tab. Use `pr-comment`, `both`, or `none` for other surfaces.
- `fail-on-error: true`: fail the step if agent **operational** readiness cannot be established (BPF/load), not merely on policy noise.

### SNI extraction limits

`tls_sni` parses the **ClientHello SNI** from cleartext bytes on the userspace-syscall write path; TLS is not decrypted. A SNI row may be missing or non-authoritative under these conditions:

- **Fragmented ClientHello** (split across multiple `write(2)` / `writev(2)` calls): **handled** by inter-syscall reassembly plus a bounded `iov[1]` peek on the same `(tgid,fd)` for the supported syscall set. Heavy fragmentation across many small segments, or fragmentation on a syscall not in the supported set, may produce a `partial` SNI confidence row rather than a full match.
- **KTLS offload** (kernel TLS, `setsockopt(SOL_TLS, …)`): encryption moves into the kernel after the upgrade; affected sockets surface as TCP connect events (destination IP + port) with no SNI. The digest counts these upgrades in a dedicated **KTLS offload** KPI row.
- **TLS 1.3 Encrypted ClientHello (ECH):** only the **outer** (CDN/proxy) SNI is visible (e.g., `cloudflare-ech.com`); the **real** server name is encrypted and **cannot** be recovered by BPF inspection. Cross-reference DNS HTTPS records or app-level logs for the true destination.
- **`io_uring` submissions** bypass per-syscall tracepoints. Default **`io-uring-disable: true`** blocks `io_uring_setup(2)` via sysctl and records the attempt; with that hardening off, ClientHello bytes submitted through io_uring will not produce a SNI row.

---

## Defend mode (optional)

Detect mode is default. For defend behavior (block non-allowlisted egress), reuse the same **`env`** / **`checkout`** / **`coldstep-io/coldstep@v0.6.2`** pin as above, then configure `with:` (**`mode: defend`**):

```yaml
- uses: coldstep-io/coldstep@v0.6.2
  with:
    mode: defend
    allow: |
      google.com
      github.com
      api.example.com
      *.svc.example.com
      1.1.1.1
      8.8.8.8
- run: echo "your build/test/deploy steps"
```

Denied egress appears as `"type":"deny"` in JSONL and in the digest.

### Allowlist files (long lists in the repo)

For large allowlists, keep **UTF-8 text files** in the repository and pass **comma-separated paths** to **`allow-file`** relative to **`GITHUB_WORKSPACE`** (no path escape outside the workspace).

**File format:** optional `#` full-line or end-of-line comments; tokens separated by newlines, commas, and/or spaces (same as editing a long inline `allow:` list, but reviewable in PRs as a file). Entries are auto-classified into domains, wildcard hosts, IPv4/IPv6 literals, and `!`-prefixed ignore CIDRs.

**Starter packs:** reference domain/IP packs live in **`scripts/coldstep_bootstrap/`** in the repo. Copy the lines you want into your own **`allow-file`** — there is no separate input to merge them (the `bootstrap-allowlist` input was removed).

**Example**

```yaml
- uses: coldstep-io/coldstep@v0.6.2
  with:
    mode: defend
    allow: api.github.com
    allow-file: .github/coldstep/egress-allow.txt
    fail-on-error: true
```

---

## Where to look after a run

- **Summary tab:** the pure-markdown simple report (written by the action's stop step from `.coldstep-events.jsonl`).
- **Workspace:** `.coldstep-events.jsonl`, `.coldstep-telemetry.json`, `.coldstep-report.md` (detailed markdown report), and `.coldstep-<mode>.md` — the same digest under a mode-named path (`.coldstep-detect.md` / `.coldstep-defend.md`), written by default so you can read or upload it without extra config (override the path with the `digest-output` input).

Start with default **detect**, then set **`detect-profile: enhanced`** when you need `proc_tree` / `tls_sni` / `fs_events` streams.

### Report pipeline (maintainers)

Reporting is one pure-markdown path in the combined `coldstep` binary (no separate `coldstep-report` binary, no HTML): `coldstep stop` renders the simple report to the Job Summary and the detailed report to `.coldstep-report.md`; `coldstep diff` and `coldstep assert-integrity` are the baseline / anti-blindness gates. Demo/CI workflows upload `.coldstep-report.md` as the downloadable artifact.

Consumers copying **`QUICK_START`** alone only need the default digest + JSONL unless they opt into maintainer workflows.

---

## Advanced (optional): previous-run drift diff

The **[`coldstep-demo`](.github/workflows/coldstep-demo.yml)**-style detect job can emit a **previous-run drift** report when a workflow sets:

```yaml
env:
  COLDSTEP_DIFF_PREV_RUN: '1'
```

Typical needs: `permissions: actions: read, contents: read` for baseline lookup (see **`coldstep-ci.yml`** / detect jobs in **`coldstep-ci-runner.yml`**). When enabled, the job may compare the current **`.coldstep-events.jsonl`** to a prior artifact (traffic-shape style deltas; **not** PID-for-PID equality). If no baseline exists yet, the report should say so and must not fail the job by itself.

---

## Status indicators in Markdown

GitHub Summary rendering is Markdown-first; use short labels or optional emoji in tables if you want quick visual status (for example pass / warn / fail columns). Keep content copy-paste friendly for internal runbooks.

---

## FAQ

**Why one `uses: coldstep-io/coldstep` block instead of two?**  
The action is a node24 JavaScript action with `pre` / `main` / `post` hooks. GitHub runs `pre` before your build steps (starts the agent), `main` at the step's position (a status check), and `post` at job end (flushes digest, optional PR comment). One `uses:` block is all you need — no explicit start/stop. In-repo CI workflows use `phase: start` / `phase: stop` because `uses: ./` (local refs) do not fire node24 pre/post hooks; consumer workflows pin a published tag and omit `phase`.

**Does `fail-on-error: true` fail when someone hits a blocked URL in defend mode?**  
No for **v1** — it fails when the **agent** cannot become operationally ready (BPF/trace/cgroup), not when policy denies traffic.

**Can I pin `coldstep-io/coldstep@main`?**  
You can, but **`main` moves**; prefer a **release tag** per **[README](README.md)** and **[RELEASE_PROCESS.md](RELEASE_PROCESS.md)**.

**Does Coldstep support Windows or macOS runners?**  
**No** for this **v1** quick path — use **`ubuntu-latest`** only.

**How do I get a PR comment with the digest?**  
Set **`report: pr-comment`** (or **`both`** for Summary + PR comment) and ensure the workflow is a **`pull_request`** event. **`github-token`** defaults to **`github.token`**.

**Where is the full honesty matrix for CI?**  
**[VALIDATION.md](VALIDATION.md)** — what is proven in-repo vs not.
