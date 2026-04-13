# coldstep

**coldstep** is a GitHub Action plus a small Linux **eBPF** agent for **GitHub-hosted Ubuntu** runners. It observes process and network activity in **detect** mode (default) and can optionally **enforce** an egress allowlist. Telemetry is written to **JSONL** in the workspace and summarized as **Markdown** (merged into the job **Summary** when enabled).

[![coldstep-ci](https://github.com/coldstep-io/coldstep/actions/workflows/coldstep-ci.yml/badge.svg)](https://github.com/coldstep-io/coldstep/actions/workflows/coldstep-ci.yml) [![coldstep-demo](https://github.com/coldstep-io/coldstep/actions/workflows/coldstep-demo.yml/badge.svg)](https://github.com/coldstep-io/coldstep/actions/workflows/coldstep-demo.yml)

**[Quick Start](QUICK_START.md)** · **[`action.yml`](action.yml)** (all inputs) · **[`LICENSE.md`](LICENSE.md)** · **[Contributing](CONTRIBUTING.md)** · **[Security](SECURITY.md)**

---

## Add it to a workflow

**v1:** use **`runs-on: ubuntu-latest`** (see **Requirements**). Pin the published composite action at **`coldstep-io/coldstep@v0.1.0`** (or a newer tag you publish), not **`@main`**.

```yaml
env:
  # Matches this repo's workflows; keeps the composite action on the Node 24 runtime (`node24` in action.yml).
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: coldstep-io/coldstep@v0.1.0
        with:
          fail-on-error: true
          log-level: info
      - run: echo "your build steps"
```

Same-repo testing: `uses: ./` — see [`.github/workflows/coldstep-demo.yml`](.github/workflows/coldstep-demo.yml) (`workflow_dispatch`).

---

## Requirements

| Topic | Detail |
| :---- | :----- |
| **Runner OS** | **Linux only** for the agent. **v1 supports `ubuntu-latest` only** (GitHub-hosted Ubuntu x64). Not supported on macOS, Windows, self-hosted, or other `runs-on` labels until explicitly documented in a later release. |
| **Build on runner** | The action runs [`scripts/build-agent-linux.sh`](scripts/build-agent-linux.sh) (clang, libbpf, **bpftool** against `/sys/kernel/btf/vmlinux` → `bpf/vmlinux.h`, `go generate` / bpf2go, then **`go build`** → **`bin/coldstep`**). |
| **Privileges** | The agent runs under **`sudo`** to load BPF. |
| **Node** | Composite action uses **Node.js 24** (`node24` in `action.yml`). Set workflow env **`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`** to match [`.github/workflows/coldstep-ci-runner.yml`](.github/workflows/coldstep-ci-runner.yml) and [`.github/workflows/coldstep-demo.yml`](.github/workflows/coldstep-demo.yml). |

---

## GitHub Actions pins in this repository

Consumer copy-paste above uses **`actions/checkout@v6`**. Other first-party pins in **`.github/workflows/`** (check files for edits over time):

| Workflow / area | Notable `uses:` |
| :-------------- | :-------------- |
| **CI / demo / attest** | `actions/checkout@v6`, `actions/setup-go@v6` (`go-version: 1.25.x`), `actions/setup-node@v6` (`node-version: 24`, npm cache where applicable), `actions/upload-artifact@v7` |
| **Supply chain** | `actions/attest@v4` |
| **Pages** | `actions/checkout@v6`, `actions/configure-pages@v6`, `actions/upload-pages-artifact@v4`, `actions/deploy-pages@v5` |

---

## Modes and outputs

| Mode | Behavior |
| :--- | :------- |
| **`detect`** (default) | Observe and record; no egress blocking. |
| **`enforce`** | Block TCP/UDP egress that is not on the allowlist; job fails fast on the first deny. Requires configuration (see **`action.yml`** / Quick Start). |

**Artifacts (under `$GITHUB_WORKSPACE` by default)**

| File | Role |
| :--- | :--- |
| **`.coldstep-events.jsonl`** | Append-only event stream (source of truth for investigations). |
| **`.coldstep-detect.md`** | Shutdown digest (KPI tables, collapsible sections). |
| **`.coldstep-telemetry.json`** | Shutdown totals and BPF health. |

The **post** step can merge **`.coldstep-detect.md`** into the **Actions Summary** tab (`report-job-summary`, default on). Paths can be overridden with env vars such as `COLDSTEP_EVENTS_LOG`, `COLDSTEP_DETECT_LOG`, `COLDSTEP_TELEMETRY_JSON`.

---

## Common inputs

Full list and defaults: **[`action.yml`](action.yml)**. Frequently used:

| Input | Purpose |
| :---- | :------ |
| `mode` | `detect` or `enforce`. |
| `allowed-domains` | Enforce-mode domain allowlist (required for enforce). |
| `allowed-hosts` / `allowed-ips` | Optional classification / policy hints (see `action.yml`). |
| `fail-on-error` | Fail if the agent never reaches **operational** readiness (BPF/load), not for policy “violations” alone. |
| `feature-gates` | Example: `proc_tree=1`, `tls_sni=1`, `fs_events=1` — passed as `COLDSTEP_FEATURE_GATES`. |
| `report-job-summary` | Merge digest into the job Summary. |
| `report-pr-summary` | Optional PR comment (needs `github-token`). |
| `ignored-ip-nets` / `no-default-ignored-nets` | Optional RFC1918-style ignore merges for policy and enforce bypass (see `action.yml`). |
| `smoke-test-egress` | Short UDP/HTTP probes in detect (auto by default) to improve digest coverage on hosted runners. |

---

## Limits (read before relying on signals)

- **TCP** rows reflect **`connect(2)` at syscall enter**, not guaranteed established sockets.
- **HTTP** events are cleartext **HTTP/1 on port 80**; **HTTPS** is not decrypted. Optional **`tls_sni`** surfaces **ClientHello SNI** from the first **`write(2)`** after **`connect`** (best-effort).
- **Shared runners**: attribution is **PID / `comm`**-class; not a perfect global process tree.
- Prefer **JSONL** over the Summary for forensics; the Summary is **capped** (GitHub limit ~1 MiB per step).

---

## Supply chain (optional)

On **version tags** matching `v*` (and via **workflow_dispatch**), **[`supply-chain-attest.yml`](.github/workflows/supply-chain-attest.yml)** builds **`bin/coldstep`**, the **esbuild** JS bundle, a tarball, and CycloneDX SBOMs, then creates **artifact attestations** (requires a repository/org configuration that supports attestations). See that file and [`LICENSE.md`](LICENSE.md) for third-party licenses.

---

## Contributing (GitHub Actions only)

Validation and BPF builds run **only on GitHub Actions** (GitHub-hosted **`ubuntu-latest`**). There is no supported local workflow for compiling the agent, reproducing CI, or running the integration suite outside Actions.

- **Merge gates:** PRs and pushes to **`main`** run **[`coldstep-ci.yml`](.github/workflows/coldstep-ci.yml)** → **[`coldstep-ci-runner.yml`](.github/workflows/coldstep-ci-runner.yml)**. Use a PR or **`workflow_dispatch`** on **`coldstep-ci.yml`** (or **`coldstep-demo.yml`** for composite demos) to verify changes. **`coldstep-pages.yml`** deploys **`website/`**; **`supply-chain-attest.yml`** runs on **`v*`** tags and manual dispatch.
- **Generated BPF:** `bpf/vmlinux.h` and `internal/bpf/**/*_bpf*.go` stubs are **gitignored**; each CI run executes **`scripts/build-agent-linux.sh`** (host **`bpftool`** + **`go generate`**) before **`go build`**.

Implementation is **clean-room** (no vendored third-party guard code). **Acknowledgments:** prior art that informed product direction is credited in the repo’s acknowledgment section where present.

---

## Repository

Source: **[github.com/coldstep-io/coldstep](https://github.com/coldstep-io/coldstep)**
