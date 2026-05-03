# coldstep

**coldstep** is a GitHub Action plus a small Linux **eBPF** agent for **GitHub-hosted Ubuntu** runners. It records egress and process activity to **JSONL** and optional **Markdown** digests (job **Summary** when enabled). **Blocking** uses **`mode: defend`** only — the old **`enforce`** spelling is **not accepted**.

**Pin workflows to** **`coldstep-io/coldstep@v0.2.1`** (or a newer tag on [Releases](https://github.com/coldstep-io/coldstep/releases)). Listing: [**Coldstep eBPF CI Egress** on GitHub Marketplace](https://github.com/marketplace/actions/coldstep-ebpf-ci-egress).

[![coldstep-ci](https://github.com/coldstep-io/coldstep/actions/workflows/coldstep-ci.yml/badge.svg)](https://github.com/coldstep-io/coldstep/actions/workflows/coldstep-ci.yml) [![coldstep-demo](https://github.com/coldstep-io/coldstep/actions/workflows/coldstep-demo.yml/badge.svg)](https://github.com/coldstep-io/coldstep/actions/workflows/coldstep-demo.yml)

**[Quick Start](QUICK_START.md)** · **[`action.yml`](action.yml)** (all inputs) · **[`LICENSE.md`](LICENSE.md)** · **[Contributing](CONTRIBUTING.md)** · **[Security](SECURITY.md)**

### Runtime

Using Coldstep in **your** workflow does **not** require **Python** or **`pip install`** — the composite runs **Go** binaries (`bin/coldstep-action`, `bin/coldstep`, `bin/coldstep-report` after build). Your job may still run **`pip install`**, **`npm ci`**, or any other tooling for **other** steps; Coldstep does **not** restrict that.

---

## At a glance

| Mode | What it does | Allowlist |
| :--- | :------------- | :-------- |
| **`detect`** (default) | Observe and log IPv4-focused egress; no blocking. | Optional (policy labels only). |
| **`defend`** | Block IPv4 egress not on the allowlist (cgroup programs). | **Required** — non-empty effective allowlist. |

**Upgrading from old workflows**

| Before | After |
| :----- | :---- |
| `mode: enforce` | `mode: defend` |
| `CI_GUARD_MODE: enforce` | `CI_GUARD_MODE: defend` |

Older JSONL files may still show `"mode":"enforce"` in archived runs; that is **legacy data**, not a supported input anymore.

Defend setup example: **[QUICK_START → Defend mode](QUICK_START.md#defend-mode-optional)**.

---

## Add it to a workflow

**Recommended:** use **`runs-on: ubuntu-latest`** (see **Requirements**). Pin the published composite action at **`coldstep-io/coldstep@v0.2.1`** (or a newer tag you publish), not **`@main`**.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: coldstep-io/coldstep@v0.2.1
        with:
          phase: start
          fail-on-error: true
          log-level: info
      - run: echo "your build steps"
      - uses: coldstep-io/coldstep@v0.2.1
        if: always()
        with:
          phase: stop
```

**`coldstep-demo`** (`workflow_dispatch`) runs the in-repo action with **`uses: ./`** (same pattern as [`.github/workflows/coldstep-ci-runner.yml`](.github/workflows/coldstep-ci-runner.yml)). Downstream repos should pin **`coldstep-io/coldstep@v0.2.1`** (or a newer tag).

---

## Requirements

| Topic | Detail |
| :---- | :----- |
| **IP versions** | **IPv6 is not supported.** Allowlists, cgroup enforcement, and syscall tracing targets in this repo are **IPv4 only**. |
| **Runner OS** | **Linux only** for the agent. **v1 supports `ubuntu-latest` only** (GitHub-hosted Ubuntu x64). Not supported on macOS, Windows, self-hosted, or other `runs-on` labels until explicitly documented in a later release. |
| **Build on runner** | The action runs [`scripts/build-agent-linux.sh`](scripts/build-agent-linux.sh) (clang, libbpf, **bpftool** against `/sys/kernel/btf/vmlinux` → `bpf/vmlinux.h`, `go generate` / bpf2go, then **`go build`** → **`bin/coldstep`**). |
| **Privileges** | The agent runs under **`sudo`** to load BPF. |
| **Action runtime** | Composite action is shell + Go binaries (`bin/coldstep-action`, `bin/coldstep-report`) and no longer requires Node.js runtime hooks. |

For **GitHub Actions security posture** — threat model for a workflow job, consumer mitigations (pins, permissions), residual risk, and honest telemetry scope — see **[SECURITY.md](SECURITY.md)** (*GitHub Actions: threat model and mitigations*).

---

## GitHub Actions pins in this repository

Consumer copy-paste above uses **`actions/checkout@v6`**. Other first-party pins in **`.github/workflows/`** (check files for edits over time):

| Workflow / area | Notable `uses:` |
| :-------------- | :-------------- |
| **CI / demo / attest** | `actions/checkout@v6`, `actions/setup-go@v6` (`go-version: 1.25.x`), `actions/setup-node@v6` (`node-version: 24`, npm cache where applicable), `actions/upload-artifact@v6` |
| **Supply chain** | `actions/attest@v4` |
| **Pages** | `actions/checkout@v6`, `actions/configure-pages@v6`, `actions/upload-pages-artifact@v4`, `actions/deploy-pages@v5` |

---

## Modes and outputs

Same **`detect`** / **`defend`** meanings as **[At a glance](#at-a-glance)**. This section adds **default artifact paths** and related notes.

| Mode | Behavior |
| :--- | :------- |
| **`detect`** (default) | Observe and record; no egress blocking. |
| **`defend`** | Block TCP/UDP egress that is not on the allowlist; job fails fast on the first deny. Requires configuration (see **`action.yml`** / Quick Start). Uses cgroup **connect4** / **sendmsg4** with IPv4 allowlist entries (from domain **A** records and **`allowed-ips`** IPv4 literals). |

**Artifacts (under `$GITHUB_WORKSPACE` by default)**

| File | Role |
| :--- | :--- |
| **`.coldstep-events.jsonl`** | Append-only event stream (source of truth for investigations). |
| **`.coldstep-detect.md`** | Shutdown digest (triage ribbon, KPI tables, collapsible sections). |
| **`.coldstep-telemetry.json`** | Shutdown totals and BPF health. |

The **post** step can merge **`.coldstep-detect.md`** into the **Actions Summary** tab (`report-job-summary`, default **on**). Full **detect-report** workflows keep that digest **off** so the Summary is not dominated by the long shutdown digest:

- **`coldstep-demo-detect.yml`** (`uses: ./`): builds the full **`report-model.json`** (`coldstep-report build-model`), enriches (rDNS + OTX), writes Tier-1 BLUF and Tier-2 **`coldstep-detect-report.html`** (downloadable artifact).
- **`coldstep-detect-demo-dev.yml`** (runs on **`push` to `dev`** and **`workflow_dispatch`**): same `coldstep-report build-model` pipeline as **`coldstep-demo-detect.yml`** (baseline diff rebuild when available, rDNS + OTX, Tier-1 BLUF, Tier-2 **`coldstep-detect-report.html`** artifact **`coldstep-detect-report-html-<runner>`**), then appends IP/FQDN/rDNS matrix to the Job Summary.

Paths can be overridden with env vars such as `COLDSTEP_EVENTS_LOG`, `COLDSTEP_DETECT_LOG`, `COLDSTEP_TELEMETRY_JSON`. For cgroup BPF attach, **`COLDSTEP_CGROUP_PATH`** overrides the directory passed to **`link.AttachCgroup`** (default: cgroup v2 path from **`/proc/self/cgroup`**, else **`/sys/fs/cgroup`**).

---

## Common inputs

Full list and defaults: **[`action.yml`](action.yml)**. Frequently used:

| Input | Purpose |
| :---- | :------ |
| `mode` | **`detect`** or **`defend`** (blocking). **`enforce`** is rejected. |
| `allowed-domains` | Domain allowlist (**required** for **defend** / blocking). |
| `allowed-hosts` / `allowed-ips` | Optional classification / policy hints; **`allowed-ips`** accepts IPv4 literals only (see **`action.yml`**). |
| `fail-on-error` | Fail if the agent never reaches **operational** readiness (BPF/load), not for policy "violations" alone. |
| `detect-profile` | **`detect` only:** `standard` (default) or **`enhanced`** — enhanced merges default `proc_tree` / `tls_sni` / `fs_events` gates when unset and sets `COLDSTEP_DETECT_PROFILE` for stricter **report-model** integrity (set the same `COLDSTEP_DETECT_PROFILE` on `coldstep-report build-model`). |
| `feature-gates` | Example: `proc_tree=1`, `tls_sni=1`, `fs_events=1` — passed as `COLDSTEP_FEATURE_GATES` (explicit values override enhanced defaults for those keys). |
| `report-job-summary` | Merge digest into Summary when **true**; **false** for workflows that emit a dedicated `coldstep-report render-summary` summary. |
| `report-pr-summary` | Optional PR comment (needs `github-token`). |
| `ignored-ip-nets` / `no-default-ignored-nets` | Optional RFC1918-style ignore merges for policy and defend bypass (see `action.yml`). |
| `smoke-test-egress` | Optional UDP/HTTP probes after startup (default `false`; set `true` for extra digest/JSONL coverage). |

### Optional threat intel (AlienVault OTX)

Detect workflows that build the **report model** can enrich indicators with **AlienVault OTX**. Add a repository or organization secret named **`OTX_API_KEY`**. If the secret is **missing or empty**, enrichment is **skipped** (no outbound calls to OTX; jobs still succeed).

Enrichment walks indicators present in the report model when **`OTX_API_KEY`** is set (`coldstep-report otx-enrich`).

---

## Limits (read before relying on signals)

- **TCP** rows reflect **`connect(2)` at syscall enter**, not guaranteed established sockets.
- **HTTP** events are cleartext **HTTP/1 on port 80**; **HTTPS** is not decrypted. Optional **`tls_sni`** surfaces **ClientHello SNI** from the first **`write(2)`** after **`connect`** (best-effort).
- **Shared runners**: attribution is **PID / `comm`**-class; not a perfect global process tree.
- Prefer **JSONL** over the Summary for forensics; the Summary is **capped** (GitHub limit ~1 MiB per step).
- **Agent env (advanced):** the Go agent enables **verbose BPF verifier logging** for the large `traceconnect` program only when **`COLDSTEP_BPF_VERBOSE_VERIFY`** is set in the job environment. Leave it unset on GitHub-hosted runners (default) so `LoadTraceconnectObjects` stays fast; set it when debugging verifier rejections locally or in a dedicated job.

---

## Supply chain (optional)

On **version tags** matching `v*` (and via **workflow_dispatch**), **[`supply-chain-attest.yml`](.github/workflows/supply-chain-attest.yml)** builds **`bin/coldstep`**, the **esbuild** JS bundle, a tarball, and CycloneDX SBOMs, then creates **artifact attestations** (requires a repository/org configuration that supports attestations). See that file and [`LICENSE.md`](LICENSE.md) for third-party licenses.

---

## Contributing (GitHub Actions only)

Validation and BPF builds run **only on GitHub Actions** (GitHub-hosted **`ubuntu-latest`**). There is no supported local workflow for compiling the agent, reproducing CI, or running the integration suite outside Actions.

**Releases (maintainers):** **`RELEASE_PROCESS.md`** defines the **consumer pin standard** (repo docs vs **`website/`** timing, pin checker, demos, changelog).

- **Merge gates:** PRs and pushes to **`main`** run **[`coldstep-ci.yml`](.github/workflows/coldstep-ci.yml)** → **[`coldstep-ci-runner.yml`](.github/workflows/coldstep-ci-runner.yml)**. Use a PR or **`workflow_dispatch`** on **`coldstep-ci.yml`**, or run **`coldstep-demo.yml`** (full integration), **`coldstep-demo-detect.yml`** / **`coldstep-demo-defend.yml`** (minimal detect / defend demos), to verify changes. **`coldstep-pages.yml`** deploys **`website/`**; **`supply-chain-attest.yml`** runs on **`v*`** tags and manual dispatch.
- **Generated BPF:** `bpf/vmlinux.h` and `internal/bpf/**/*_bpf*.go` stubs are **gitignored**; each CI run executes **`scripts/build-agent-linux.sh`** (host **`bpftool`** + **`go generate`**) before **`go build`**. On a non-Linux workstation, **[`scripts/docker-linux-test.sh`](scripts/docker-linux-test.sh)** runs that pipeline plus **`go test`** inside an **Ubuntu** container (bind-mounts the repo).

### Deep-debug escalation guide

When a normal **`coldstep-ci`** pass is insufficient — flaky failures, BPF verifier/load issues, workflow + agent + report regressions — run **[`coldstep-deep-debug.yml`](.github/workflows/coldstep-deep-debug.yml)** via **`workflow_dispatch`** on your branch.

The workflow executes **`scripts/deep-debug.sh`** on **`ubuntu-latest`** and uploads **`.coldstep-deep-debug/`** as an artifact (staged **`report.md`** + logs). Attach links or snippets from that run to issues or PRs — there is no supported local reproduction path.

Implementation is **clean-room** (no vendored third-party guard code). **Acknowledgments:** prior art that informed product direction is credited in the repo's acknowledgment section where present.

---

## Minimal deploy path

1. Pin **`coldstep-io/coldstep@<tag>`** on **`runs-on: ubuntu-latest`**, with **`phase: start`** before your steps and **`phase: stop`** at the end (`if: always()` as needed) — see **[QUICK_START](QUICK_START.md)**.
2. Start in **`mode: detect`** (default); switch to **`mode: defend`** only when you have a tested allowlist.
3. Prefer **`allowed-*-file`** for long lists; **`bootstrap-allowlist: true`** only if you explicitly want vendored bootstrap packs merged (**default off**).

---

## Repository

Source: **[github.com/coldstep-io/coldstep](https://github.com/coldstep-io/coldstep)**
