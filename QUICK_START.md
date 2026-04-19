# Coldstep Quick Start

**v1:** the composite agent is validated and supported on **`runs-on: ubuntu-latest`** only. Pin the published action at **`coldstep-io/coldstep@v0.1.6`** (or a newer tag you publish). **Repository changes** are validated via **GitHub Actions** (open a PR or use **`workflow_dispatch`** on **`coldstep-ci`**, **`coldstep-demo`**, **`coldstep-demo-detect`**, or **`coldstep-demo-enforce`**); there is no maintained local build path for the Linux agent.

## TL;DR (copy/paste)

Add this to your workflow:

```yaml
name: coldstep

on:
  push:
  pull_request:

# Matches coldstep-ci / coldstep-demo: composite action runs on Node 24 (`node24` in action.yml).
env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true

jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: coldstep-io/coldstep@v0.1.6
```

That is enough to get:

- detect-mode runtime telemetry
- `.coldstep-detect.md` (digest merged into the job Summary when `report-job-summary` is true)
- `.coldstep-events.jsonl` (machine-readable stream)

---

## Versioning

- Prefer **`coldstep-io/coldstep@v0.1.6`** (or a **newer tag** you publish, for example **`v0.2.0`**). **`@main`** tracks the default branch and can change without notice.
- **`v0.1.0`** is not usable with `uses: coldstep-io/coldstep@v0.1.0` (that tag lacks repo-root **`action.yml`**); use **`v0.1.6`** or later.

**Example workflows in this repo** (all use `uses: ./` and are triggered with **`workflow_dispatch`**): **[`coldstep-demo-detect.yml`](.github/workflows/coldstep-demo-detect.yml)** (minimal detect), **[`coldstep-demo-enforce.yml`](.github/workflows/coldstep-demo-enforce.yml)** (minimal enforce), and **[`coldstep-demo.yml`](.github/workflows/coldstep-demo.yml)** (full integration / drift).

---

## Add useful controls

```yaml
env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true

jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: coldstep-io/coldstep@v0.1.6
        with:
          feature-gates: proc_tree=1,tls_sni=1,fs_events=1
          report-job-summary: true
          report-pr-summary: false
          fail-on-error: true
          log-level: info
```

### What these controls do

- `proc_tree=1`: emits `proc_fork` events and a process tree section in the digest.
- `tls_sni=1`: adds TLS ClientHello / SNI rows (`"type":"tls"` in JSONL).
- `fs_events=1`: adds filesystem events (`"type":"fs_event"`).
- `fail-on-error=true`: fails the step if agent **operational** readiness cannot be established (BPF/load), not merely on policy noise.

---

## Enforce mode (optional)

Detect mode is default. For enforce behavior, reuse the same **`env`** / **`checkout`** / **`coldstep-io/coldstep@v0.1.6`** pin as above, then configure `with:`:

```yaml
- uses: coldstep-io/coldstep@v0.1.6
  with:
    mode: enforce
    allowed-domains: google.com,github.com
    # optional:
    # allowed-hosts: api.example.com,*.svc.example.com
    # allowed-ips: 1.1.1.1,8.8.8.8   # IPv4 literals
```

Denied egress appears as `"type":"deny"` in JSONL and in the digest.

---

## Where to look after a run

- **Summary tab:** digest from `.coldstep-detect.md` (when enabled).
- **Workspace:** `.coldstep-events.jsonl`, `.coldstep-telemetry.json`.

Start with default **detect**, then add **`feature-gates`** when you need those streams.

### Optional: OTX enrichment (detect reports)

Set repo/org secret **`OTX_API_KEY`** for AlienVault OTX lookups in the detect report pipeline. No secret → enrichment skipped. See **`scripts/coldstep_detect_report/README.md`**.

---

## Advanced (optional): previous-run drift diff

The **[`coldstep-demo`](.github/workflows/coldstep-demo.yml)**-style detect job can emit a **previous-run drift** report when a workflow sets:

```yaml
env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true
  COLDSTEP_DIFF_PREV_RUN: '1'
```

Typical needs: `permissions: actions: read, contents: read` for baseline lookup (see **`coldstep-ci.yml`** / detect jobs in **`coldstep-ci-runner.yml`**). When enabled, the job may compare the current **`.coldstep-events.jsonl`** to a prior artifact (traffic-shape style deltas; **not** PID-for-PID equality). If no baseline exists yet, the report should say so and must not fail the job by itself.

---

## Status indicators in Markdown

GitHub Summary rendering is Markdown-first; use short labels or optional emoji in tables if you want quick visual status (for example pass / warn / fail columns). Keep content copy-paste friendly for internal runbooks.
