# Coldstep Quick Start

**v1:** the composite agent is validated and supported on **`runs-on: ubuntu-latest`** only. Pin the published action at **`coldstep-io/coldstep@v0.2.0`** (or a newer tag you publish). **Repository changes** are validated via **GitHub Actions** (open a PR or use **`workflow_dispatch`** on **`coldstep-ci`**, **`coldstep-demo`**, **`coldstep-demo-detect`**, or **`coldstep-demo-enforce`** — that last workflow file name is historical; it runs **`mode: defend`**). There is no maintained local build path for the Linux agent.

## Two modes (read this first)

Coldstep exposes **two** mode names in `with:` and env **`CI_GUARD_MODE`**: **`detect`** and **`defend`**. There is no **`enforce`** mode string anymore — use **`defend`** for blocking.

| You want… | Set |
| :-------- | :-- |
| Observe-only telemetry (default) | `mode: detect` or omit `mode` |
| Block egress not on the allowlist | `mode: defend` + non-empty **`allowed-domains`** / policy files |

If you still have `mode: enforce` or `CI_GUARD_MODE: enforce`, replace with **`defend`**. See **[CHANGELOG — Breaking](CHANGELOG.md)**.

---

## Bare minimum

Smallest workflow that runs Coldstep in **detect** mode: **`checkout` → `phase: start` → your steps → `phase: stop`** (`stop` should run even when earlier steps fail).

```yaml
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: coldstep-io/coldstep@v0.2.0
        with:
          phase: start
      - run: echo "your build/test steps here"
      - uses: coldstep-io/coldstep@v0.2.0
        if: always()
        with:
          phase: stop
```

You get default **detect** telemetry, **`.coldstep-events.jsonl`**, and (with defaults) the digest merged into the **Job Summary** when **`report-job-summary`** is left at **`true`**.

---

## Recommended starter (copy/paste)

Same lifecycle as bare minimum, explicit **`name`/`on`** and pin for a full job you can drop into a repo:

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
      - uses: coldstep-io/coldstep@v0.2.0
        with:
          phase: start
      - run: echo "build/test/deploy steps"
      - uses: coldstep-io/coldstep@v0.2.0
        if: always()
        with:
          phase: stop
```

---

## All composite inputs (summary)

Every `with:` key the action accepts (defaults are what you get if you omit the key). **`phase`** is the only key that must differ between the **start** and **stop** steps.

| Input | Default | Summary |
| :---- | :------ | :------ |
| **`phase`** | `start` | **`start`** — attach agent before workload. **`stop`** — flush digest/telemetry at job end (use **`if: always()`** on this step). |
| **`mode`** | `detect` | **`detect`** — observe only. **`defend`** — block non-allowlisted egress (**`enforce`** is rejected). |
| **`allowed-domains`** | *(empty)* | Comma/whitespace-separated domains for **defend** (trimmed, lowercased). |
| **`allowed-domains-file`** | *(empty)* | Comma-separated workspace paths to UTF-8 files; merged after inline **`allowed-domains`**. |
| **`allowed-hosts`** | *(empty)* | Hostnames; **`*.example.com`** = one-level wildcard. |
| **`allowed-hosts-file`** | *(empty)* | File paths merged after **`allowed-hosts`**. |
| **`allowed-ips`** | *(empty)* | IPv4 literals/CIDRs for policy. |
| **`allowed-ips-file`** | *(empty)* | File paths merged after **`allowed-ips`**. |
| **`ignored-ip-nets`** | *(empty)* | Extra IPv4 CIDRs to treat as ignored (plus implicit RFC1918 unless disabled below). Max **128** merged CIDRs total. |
| **`ignored-ip-nets-file`** | *(empty)* | File paths for more ignored CIDRs. |
| **`no-default-ignored-nets`** | `false` | If **`true`**, do **not** add implicit **`10.0.0.0/8`** and **`172.16.0.0/12`** ignores. |
| **`bootstrap-allowlist`** | `false` | If **`true`**, merge vendored bootstrap domain/IP packs from the action after your lists. |
| **`fail-on-error`** | `false` | If **`true`**, fail the step if the agent never reaches **operational readiness** (BPF/trace/cgroup as required for the mode). Does **not** fail on policy/deny traffic alone. |
| **`ready-timeout-seconds`** | *(see agent)* | Only when **`fail-on-error`** is **`true`**: max seconds to wait for **`.coldstep-ready.json`** (`ok:true`). Clamped **60–2700**; malformed **`ok:false`** fails fast. |
| **`log-level`** | `info` | Agent stderr log level: **`debug`**, **`info`**, **`warn`**, **`error`**. |
| **`feature-gates`** | *(empty)* | Comma-separated **`key=value`** (e.g. **`proc_tree=1,tls_sni=1,fs_events=1`**) passed to the agent. |
| **`report-job-summary`** | `true` | If **`true`**, **stop** merges **`.coldstep-detect.md`** into the Job Summary. |
| **`report-pr-summary`** | `false` | If **`true`**, **stop** posts a PR comment (**`pull_request`** workflows only). |
| **`github-token`** | `${{ github.token }}` | Token for PR comments when **`report-pr-summary`** is **`true`**. |
| **`slack-webhook-endpoint`** | *(empty)* | Slack Incoming Webhook URL only (`https://hooks.slack.com/services/...`). **Stop** posts a short digest. |
| **`smoke-test-egress`** | `false` | If **`true`**, optional IPv4 UDP/HTTP probes after start so JSONL/digest often shows **udp/http** rows. |
| **`io-uring-disable`** | `true` | If **`true`**, disable **io_uring** via sysctl before start (reduces syscall-hook bypass). |
| **`signing-key`** | *(empty)* | Optional base64 **Ed25519** seed/key; when set, JSONL events are signed. |
| **`release-path`** | *(empty)* | Optional path to a prebuilt **`coldstep`** binary; skips build when file exists (advanced/debug). |

**Environment (job-level):** workflows may set **`CI_GUARD_MODE`** to **`detect`** or **`defend`** instead of **`mode:`** in `with:` — same validation rules as **`mode`**.

---

## Validation (what automation proves)

Coldstep’s CI and tests prove **specific scenarios on GitHub-hosted Linux**, not every sentence in the docs. Read **[VALIDATION.md](VALIDATION.md)** for the detect vs defend matrix, job names (`detect-mode`, `defend-mode`, …), and honest limits (self-hosted, adversarial bypass, …).

---

## Versioning

- Prefer **`coldstep-io/coldstep@v0.2.0`** (or a **newer tag** you publish). **`@main`** tracks the default branch and can change without notice.
- **`v0.1.0`** is not usable with `uses: coldstep-io/coldstep@v0.1.0` (that tag lacks repo-root **`action.yml`**); use **`v0.2.0`** or later.

**Example workflows in this repo** (all use `uses: ./` and are triggered with **`workflow_dispatch`** except **`coldstep-detect-demo-dev`** which also runs on **`push` to `dev`**): **[`coldstep-demo-detect.yml`](.github/workflows/coldstep-demo-detect.yml)** (minimal detect), **[`coldstep-demo-enforce.yml`](.github/workflows/coldstep-demo-enforce.yml)** (minimal **defend** — legacy workflow filename), **[`coldstep-demo.yml`](.github/workflows/coldstep-demo.yml)** (full integration / drift), and **[`coldstep-detect-demo-dev.yml`](.github/workflows/coldstep-detect-demo-dev.yml)** — same agent detect setup on **`dev`** with full BLUF + HTML artifact plus an extra **IP classification** Job Summary section.

---

## Add useful controls

```yaml
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: coldstep-io/coldstep@v0.2.0
        with:
          phase: start
          feature-gates: proc_tree=1,tls_sni=1,fs_events=1
          report-job-summary: true
          report-pr-summary: false
          fail-on-error: true
          log-level: info
      - uses: coldstep-io/coldstep@v0.2.0
        if: always()
        with:
          phase: stop
          report-job-summary: true
```

### What these controls do

- `proc_tree=1`: emits `proc_fork` events and a process tree section in the digest.
- `tls_sni=1`: adds TLS ClientHello / SNI rows (`"type":"tls"` in JSONL).
- `fs_events=1`: adds filesystem events (`"type":"fs_event"`).
- `fail-on-error=true`: fails the step if agent **operational** readiness cannot be established (BPF/load), not merely on policy noise.

---

## Defend mode (optional)

Detect mode is default. For defend behavior (block non-allowlisted egress), reuse the same **`env`** / **`checkout`** / **`coldstep-io/coldstep@v0.2.0`** pin as above, then configure `with:` (**`mode: defend`** — **`enforce`** is rejected):

```yaml
- uses: coldstep-io/coldstep@v0.2.0
  with:
    phase: start
    mode: defend
    allowed-domains: google.com,github.com
    # optional:
    # allowed-hosts: api.example.com,*.svc.example.com
    # allowed-ips: 1.1.1.1,8.8.8.8   # IPv4 literals
  # ... workload steps ...
- uses: coldstep-io/coldstep@v0.2.0
  if: always()
  with:
    phase: stop
```

Denied egress appears as `"type":"deny"` in JSONL and in the digest.

### Allowlist files (long lists in the repo)

For large allowlists, keep **UTF-8 text files** in the repository and pass **comma-separated paths** relative to **`GITHUB_WORKSPACE`** (no path escape outside the workspace):

| Input | Merged with |
| ----- | ------------- |
| **`allowed-domains-file`** | Inline **`allowed-domains`** (inline first, then each file in order) |
| **`allowed-hosts-file`** | **`allowed-hosts`** |
| **`allowed-ips-file`** | **`allowed-ips`** |
| **`ignored-ip-nets-file`** | **`ignored-ip-nets`** |

**File format:** optional `#` full-line or end-of-line comments; tokens separated by newlines, commas, and/or spaces (same as editing a long inline list, but reviewable in PRs as a file).

**Bootstrap pack (opt-in, default off):** set **`bootstrap-allowlist: true`** to merge vendored **`public_scripts/coldstep_bootstrap/`** domain and IP packs shipped **inside** the action after your inline and file merges. Default packs may be comment-only; enable only when you accept Coldstep’s bundled policy for your pin — see **`public_scripts/coldstep_bootstrap/README.md`** in the repo.

**Example**

```yaml
- uses: coldstep-io/coldstep@v0.2.0
  with:
    phase: start
    mode: defend
    allowed-domains: api.github.com
    allowed-domains-file: .github/coldstep/egress-domains.txt
    fail-on-error: true
```

---

## Where to look after a run

- **Summary tab:** digest from `.coldstep-detect.md` (when enabled).
- **Workspace:** `.coldstep-events.jsonl`, `.coldstep-telemetry.json`.

Start with default **detect**, then add **`feature-gates`** when you need those streams.

### Report pipelines (maintainers)

| Workflow | Summary surface | Artifact notes |
| -------- | ---------------- | -------------- |
| **`coldstep-demo-detect.yml`** | Tier-1 BLUF (`render_step_summary.py`) | Tier-2 **`coldstep-detect-report.html`** artifact |
| **`coldstep-detect-demo-dev.yml`** | Tier-1 BLUF + IP classification markdown (`render_ip_classification_summary.py`) | JSONL baseline + same Tier-2 **`coldstep-detect-report-html-<runner>`** artifact as **`coldstep-demo-detect`** |

Consumers copying **`QUICK_START`** alone only need the default digest + JSONL unless they opt into maintainer workflows.

### Optional: OTX enrichment (detect reports)

Set repo/org secret **`OTX_API_KEY`** for AlienVault OTX. Enrichment reads indicators from the active report model (full **`report-model`** or **`ip_classification`** rows on the dev pipeline). No secret → skipped, job still succeeds. Details: **`public_scripts/coldstep_detect_report/README.md`**.

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

**Why two `uses: coldstep-io/coldstep` steps?**  
The composite has **`phase: start`** (attach agent before your work) and **`phase: stop`** (flush digest, optional Slack/PR). GitHub does not run a hidden “post” hook for composite actions—you must call **`stop`** explicitly.

**What if I skip `phase: stop`?**  
You lose a clean shutdown path: digest/Summary/Slack/PR comment behavior from the stop step may not run, and you may leave the workspace without the usual final artifacts.

**Can I use `mode: enforce` or `CI_GUARD_MODE=enforce`?**  
No. Use **`defend`** for blocking mode. See **[CHANGELOG](CHANGELOG.md)**.

**Does `fail-on-error: true` fail when someone hits a blocked URL in defend mode?**  
No for **v1** — it fails when the **agent** cannot become operationally ready (BPF/trace/cgroup), not when policy denies traffic.

**Can I pin `coldstep-io/coldstep@main`?**  
You can, but **`main` moves**; prefer a **release tag** per **[README](README.md)** and **[RELEASE_PROCESS.md](RELEASE_PROCESS.md)**.

**Does Coldstep support Windows or macOS runners?**  
**No** for this **v1** quick path — use **`ubuntu-latest`** only.

**How do I get a PR comment with the digest?**  
Set **`report-pr-summary: true`** on the **`stop`** step (and ensure the workflow is a **`pull_request`** event). **`github-token`** defaults to **`github.token`**.

**What Slack URL is allowed?**  
Only **`https://hooks.slack.com/services/...`** incoming webhooks. Pass **`slack-webhook-endpoint`** on the **`stop`** step (`inputs` are read there).

**Where is the full honesty matrix for CI?**  
**[VALIDATION.md](VALIDATION.md)** — what is proven in-repo vs not.
