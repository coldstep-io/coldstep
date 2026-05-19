# coldstep

**coldstep** is a GitHub Action plus a small Linux **eBPF** agent for **GitHub-hosted Ubuntu** runners. It records egress and process activity to **JSONL** and optional **Markdown** digests (job **Summary** when enabled). **Blocking** uses **`mode: defend`** only — the old **`enforce`** spelling is **not accepted**.

**Pin workflows to** **`coldstep-io/coldstep@v0.2.5`** (or a newer tag on [Releases](https://github.com/coldstep-io/coldstep/releases)). Listing: [**Coldstep eBPF CI Egress** on GitHub Marketplace](https://github.com/marketplace/actions/coldstep-ebpf-ci-egress).

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

**Recommended:** use **`runs-on: ubuntu-latest`** (see **Requirements**). Pin the published composite action at **`coldstep-io/coldstep@v0.2.5`** (or a newer tag you publish), not **`@main`**.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: coldstep-io/coldstep@v0.2.5
        with:
          fail-on-error: true
          log-level: info
      - run: echo "your build steps"
```

The single `uses:` block is enough — node24 pre/post hooks start the agent before your build steps and flush the digest at job end. **`coldstep-demo`** (`workflow_dispatch`) demonstrates the same pattern. Downstream repos should pin **`coldstep-io/coldstep@v0.2.5`** (or a newer tag).

---

## Requirements

| Topic | Detail |
| :---- | :----- |
| **IP versions** | **Defend is IPv4 + IPv6.** Allowlists resolve both **A** and **AAAA** records and program two LPM tries: `allowed_ipv4` (4-byte keys) and `allowed_ipv6` (16-byte keys). cgroup hooks block on both families — `connect4` / `sendmsg4` for IPv4, `connect6` / `sendmsg6` for IPv6 — denying any destination not on the allowlist with `EPERM`. `::1` (loopback) and `fe80::/10` (link-local) always bypass enforcement. Detect mode observes both families without enforcing. |
| **Runner OS** | **Linux only** for the agent. **v1 supports `ubuntu-latest` only** (GitHub-hosted Ubuntu x64). Not supported on macOS, Windows, self-hosted, or other `runs-on` labels until explicitly documented in a later release. |
| **Build on runner** | The action runs [`scripts/build-agent-linux.sh`](scripts/build-agent-linux.sh) (clang, libbpf, **bpftool** against `/sys/kernel/btf/vmlinux` → `bpf/vmlinux.h`, `go generate` / bpf2go, then **`go build`** → **`bin/coldstep`**). |
| **Privileges** | The agent runs under **`sudo`** to load BPF. |
| **Action runtime** | Composite action is shell + Go binaries (`bin/coldstep-action`, `bin/coldstep-report`) and no longer requires Node.js runtime hooks. |

For **GitHub Actions security posture** — threat model for a workflow job, consumer mitigations (pins, permissions), residual risk, and honest telemetry scope — see **[SECURITY.md](SECURITY.md)** (*GitHub Actions: threat model and mitigations*). For **guaranteed vs best-effort behavior** (telemetry gaps, hook coverage), see **[Guarantees vs best-effort](SECURITY.md#guarantees-vs-best-effort-defend-and-detect)**. Maintainers may keep deeper **egress truthfulness** specs under local **`design/`** (gitignored); consumers should rely on **SECURITY.md** and **README**.

---

## GitHub Actions pins in this repository

Consumer copy-paste above uses **`actions/checkout@v6`**. Other first-party pins in **`.github/workflows/`** (check files for edits over time):

| Workflow / area | Notable `uses:` |
| :-------------- | :-------------- |
| **CI / demo / attest** | `actions/checkout@v6`, `actions/setup-go@v6` (`go-version-file: go.mod`, matches **`go`** directive), `actions/setup-node@v6` (`node-version: 24`, npm cache where applicable), `actions/upload-artifact@v6` |
| **Supply chain** | `actions/attest@v4` |
| **Pages** | `actions/checkout@v6`, `actions/configure-pages@v6`, `actions/upload-pages-artifact@v4`, `actions/deploy-pages@v5` |

---

## Modes and outputs

Same **`detect`** / **`defend`** meanings as **[At a glance](#at-a-glance)**. This section adds **default artifact paths** and related notes.

| Mode | Behavior |
| :--- | :------- |
| **`detect`** (default) | Observe and record; no egress blocking. |
| **`defend`** | Block TCP/UDP egress that is not on the allowlist; job fails fast on the first deny. Requires configuration (see **`action.yml`** / Quick Start). Uses cgroup **connect4** / **sendmsg4** with IPv4 allowlist entries (from domain **A** records and **`allow`** IPv4 literals/CIDRs). |

**Artifacts (under `$GITHUB_WORKSPACE` by default)**

| File | Role |
| :--- | :--- |
| **`.coldstep-events.jsonl`** | Append-only event stream (source of truth for investigations). |
| **`.coldstep-detect.md`** | Shutdown digest (triage ribbon, KPI tables, collapsible sections). |
| **`.coldstep-telemetry.json`** | Shutdown totals and BPF health. |

The **post** step merges **`.coldstep-detect.md`** into the **Actions Summary** tab by default (`report: job-summary`). Full **detect-report** workflows set **`report: none`** so the Summary is not dominated by the long shutdown digest:

- **`coldstep-demo-detect.yml`** (`uses: ./`): builds the full **`report-model.json`** (`coldstep-report build-model`), enriches (rDNS + OTX), writes Tier-1 BLUF and Tier-2 **`coldstep-detect-report.html`** (downloadable artifact).
- **`coldstep-detect-demo-dev.yml`** (runs on **`push` to `dev`** and **`workflow_dispatch`**): same `coldstep-report build-model` pipeline as **`coldstep-demo-detect.yml`** (baseline diff rebuild when available, rDNS + OTX, Tier-1 BLUF, Tier-2 **`coldstep-detect-report.html`** artifact **`coldstep-detect-report-html-<runner>`**), then appends IP/FQDN/rDNS matrix to the Job Summary.

Paths can be overridden with env vars such as `COLDSTEP_EVENTS_LOG`, `COLDSTEP_DETECT_LOG`, `COLDSTEP_TELEMETRY_JSON`. For cgroup BPF attach, **`COLDSTEP_CGROUP_PATH`** overrides the directory passed to **`link.AttachCgroup`** (default: cgroup v2 path from **`/proc/self/cgroup`**, else **`/sys/fs/cgroup`**).

### Suggested allowlist (`suggested-allow` output)

After a **`detect`**-mode run, the post step reads **`.coldstep-events.jsonl`** and emits a ready-to-paste allowlist as both a **Job Summary** section ("**Suggested allowlist**") and an action output named **`suggested-allow`**. Hostnames observed via **DNS / SNI / HTTP Host** take priority over the raw IPs they resolved to, so the output stays stable across DNS rotation. The output is empty in defend mode or when no destinations were observed.

```yaml
- uses: coldstep-io/coldstep@main
  id: coldstep
  with:
    mode: detect
- run: echo "Add to allow: ${{ steps.coldstep.outputs.suggested-allow }}"
```

Typical workflow: run **`detect`** with this snippet across a few representative jobs, paste the union of `suggested-allow` outputs into your `allow:` input, then flip to **`mode: defend`** once the list is stable.

---

## Common inputs

Full list and defaults: **[`action.yml`](action.yml)**. Frequently used:

| Input | Purpose |
| :---- | :------ |
| `mode` | **`detect`** or **`defend`** (blocking). **`enforce`** is rejected. |
| `allow` / `allow-file` | Unified egress allowlist (**required** for **defend** / blocking). Accepts plain domains, `*.example.com` wildcards, IPv4 literals/CIDRs, and `!CIDR` ignore entries. |
| `fail-on-error` | Fail if the agent never reaches **operational** readiness (BPF/load), not for policy "violations" alone. Defaults to **`true`** in defend mode. |
| `detect-profile` | **`detect` only:** `standard` (default) or **`enhanced`** — enhanced enables `proc_tree` / `tls_sni` / `fs_events` and sets `COLDSTEP_DETECT_PROFILE` for stricter **report-model** integrity (set the same `COLDSTEP_DETECT_PROFILE` on `coldstep-report build-model`). |
| `report` | `job-summary` (default), `pr-comment`, `both`, or `none` — where to post the detect digest. |
| `ignored-nets` / `no-default-ignored-nets` | Optional RFC1918-style ignore merges for policy and defend bypass (see `action.yml`). |

### Optional threat intel (AlienVault OTX)

Detect workflows that build the **report model** can enrich indicators with **AlienVault OTX**. Add a repository or organization secret named **`OTX_API_KEY`**. If the secret is **missing or empty**, enrichment is **skipped** (no outbound calls to OTX; jobs still succeed).

Enrichment walks indicators present in the report model when **`OTX_API_KEY`** is set (`coldstep-report otx-enrich`).

---

## Limits (read before relying on signals)

- **TCP** rows reflect **`connect(2)` at syscall enter**, not guaranteed established sockets.
- **HTTP** events are cleartext **HTTP/1 on port 80**; **HTTPS** is not decrypted. Optional **`tls_sni`** surfaces **ClientHello SNI** from the first cleartext handshake buffer seen on **`write(2)`/`writev`/`pwrite(2)`/`pwritev`/`pwritev2`/`sendto`** paths after IPv4 **`connect`** (best-effort); explicit-address TCP **`sendto`** is included when the tuple matches the syscall destination.
- **Shared runners**: attribution is **PID / `comm`**-class; not a perfect global process tree.
- Prefer **JSONL** over the Summary for forensics; the Summary is **capped** (GitHub limit ~1 MiB per step).
- **Agent env (advanced):** the Go agent enables **verbose BPF verifier logging** for the large `traceconnect` program only when **`COLDSTEP_BPF_VERBOSE_VERIFY`** is set in the job environment. Leave it unset on GitHub-hosted runners (default) so `LoadTraceconnectObjects` stays fast; set it when debugging verifier rejections locally or in a dedicated job.

---

## Supply chain (optional)

On **version tags** matching `v*` (and via **workflow_dispatch**), **[`supply-chain-attest.yml`](.github/workflows/supply-chain-attest.yml)** builds **`bin/coldstep`**, the **esbuild** JS bundle, a tarball, and CycloneDX SBOMs, then creates **artifact attestations** (requires a repository/org configuration that supports attestations). See that file and [`LICENSE.md`](LICENSE.md) for third-party licenses.

---

## Contributing (GitHub Actions only)

Validation and BPF builds are **authoritative on GitHub Actions** (GitHub-hosted **`ubuntu-latest`**). Local workstations can approximate parts of the Linux pipeline with Docker (below); kernels and cgroup layout still differ from hosted runners.

**Releases (maintainers):** **`RELEASE_PROCESS.md`** defines the **consumer pin standard** (repo docs vs **`website/`** timing, pin checker, demos, changelog).

- **Merge gates:** PRs and pushes to **`main`** run **[`coldstep-ci.yml`](.github/workflows/coldstep-ci.yml)** → **[`coldstep-ci-runner.yml`](.github/workflows/coldstep-ci-runner.yml)**. Use a PR or **`workflow_dispatch`** on **`coldstep-ci.yml`**, or run **`coldstep-demo.yml`** (full integration), **`coldstep-demo-detect.yml`** / **`coldstep-demo-defend.yml`** (minimal detect / defend demos), to verify changes. **`coldstep-pages.yml`** deploys **`website/`**; **`supply-chain-attest.yml`** runs on **`v*`** tags and manual dispatch.
- **Generated BPF:** `bpf/vmlinux.h` and `internal/bpf/**/*_bpf*.go` stubs are **gitignored**; each CI run executes **`scripts/build-agent-linux.sh`** (host **`bpftool`** + **`go generate`**) before **`go build`**. On a non-Linux workstation, **[`scripts/docker-linux-test.sh`](scripts/docker-linux-test.sh)** runs that pipeline plus **`go test`** inside an **`ubuntu:24.04`** container (bind-mounts the repo). For a **closer match** to **`coldstep-ci-runner`** ( **`go vet`**, **staticcheck**, race on **`internal/agent`**, optional **`integration`** tests in a **`--privileged`** container), use **[`scripts/docker-deep-debug.sh`](scripts/docker-deep-debug.sh)** — by default it also runs **`go test -shuffle`**, **`govulncheck`**, and a **coverage** summary (set **`COLDSTEP_DOCKER_DEEP=0`** to skip). See the script header for **`COLDSTEP_DOCKER_IMAGE`**, **`COLDSTEP_DOCKER_RACE_FULL`**, **`COLDSTEP_DOCKER_INTERACTIVE`**, **`COLDSTEP_DOCKER_NO_INTEGRATION`**, and related env vars (run from the repo root on **Docker Desktop + Git Bash** so bind mounts resolve cleanly).
- **Assistants / iterative fixes:** **[`scripts/agent-linux-verify.sh`](scripts/agent-linux-verify.sh)** wraps the Docker flows, writes **`.coldstep-verify-last.log`**, echoes **`COLDSTEP_AGENT_VERIFY_BUNDLE_*`** markers with a reproducible **`NEXT`** checklist. **`COLDSTEP_VERIFY_MODE=quick`** (**`docker-linux-test`**) for fast fails; **`deep`** (**`docker-deep-debug`**, default); **`fast`** for a shorter **`deep`** pass (**shuffle/govulncheck/coverage** skipped, **integration** skipped). Example: **`COLDSTEP_VERIFY_MODE=fast bash scripts/agent-linux-verify.sh`**. **Windows quickest path:** **`winget install --id Git.Git -e`** once (adds **`bash`**), Docker running; then **`scripts\agent-linux-verify.cmd`**, **`python scripts/agent_linux_verify.py --mode fast`**, or **`powershell -NoProfile -File scripts/agent-linux-verify.ps1 -VerifyMode fast`**.

### Deep-debug escalation guide

When a normal **`coldstep-ci`** pass is insufficient — flaky failures, BPF verifier/load issues, workflow + agent + report regressions — run **[`coldstep-deep-debug.yml`](.github/workflows/coldstep-deep-debug.yml)** via **`workflow_dispatch`** on your branch.

The workflow executes **`scripts/deep-debug.sh`** on **`ubuntu-latest`** and uploads **`.coldstep-deep-debug/`** as an artifact (staged **`report.md`** + logs). Attach links or snippets from that run to issues or PRs. For **local** BPF/agent-focused debugging (without the workflow’s npm/deep-debug stages), run **`scripts/docker-deep-debug.sh`** on a Linux host or Docker Desktop.

Implementation is **clean-room** (no vendored third-party guard code). **Acknowledgments:** prior art that informed product direction is credited in the repo's acknowledgment section where present.

---

## Minimal deploy path

1. Pin **`coldstep-io/coldstep@<tag>`** on **`runs-on: ubuntu-latest`**, with a single **`uses:`** block before your build steps (node24 `pre` starts the agent; `post` flushes the digest at job end) — see **[QUICK_START](QUICK_START.md)**.
2. Start in **`mode: detect`** (default); switch to **`mode: defend`** only when you have a tested allowlist.
3. Prefer **`allowed-*-file`** for long lists; **`bootstrap-allowlist: true`** only if you explicitly want vendored bootstrap packs merged (**default off**).

---

## Repository

Source: **[github.com/coldstep-io/coldstep](https://github.com/coldstep-io/coldstep)**
