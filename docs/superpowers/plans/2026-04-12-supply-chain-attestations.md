# Supply chain attestations + SBOM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedicated GitHub Actions workflow that builds **`bin/ci-runtime-guard`** and the **composite action bundle**, generates **two CycloneDX JSON SBOMs** (Go module surface + npm lockfile surface), uploads those artifacts, and creates **GitHub artifact attestations** (SLSA build provenance for binary + bundle; SBOM attestations for each SBOM tied to the correct subject) without signing OCI images.

**Architecture:** One workflow **`supply-chain-attest.yml`** on **`push` tags `v*`** and **`workflow_dispatch`**, **`runs-on: ubuntu-latest`**, reusing **`scripts/build-agent-linux.sh`** for the Go binary (Docker + BPF parity with existing CI), **`npm ci` + `npm run build`** for the action bundle, **`tar`** to produce **`nightstalker-action-bundle.tar.gz`**, **Syft** CLI to emit **`sbom-go.cdx.json`** and **`sbom-js.cdx.json`**, then **`actions/attest@v4`** in separate steps for provenance-only and SBOM+subject pairs per **`actions/attest`** README (SBOM mode when `sbom-path` is set). Permissions include **`id-token: write`**, **`attestations: write`**, **`contents: read`**, and **`artifact-metadata: write`** as required by the attest action docs.

**Tech stack:** GitHub Actions, `actions/checkout@v5`, `actions/setup-go@v6`, `actions/setup-node@v5` (Node 24 per `package.json`), `actions/attest@v4`, `actions/upload-artifact@v4`, Syft (pinned version via GitHub release `.deb` on amd64), bash, Docker (for `build-agent-linux.sh`).

**Design spec:** `docs/superpowers/specs/2026-04-12-github-attestations-sbom-design.md`

---

## File map

| File | Responsibility |
|------|----------------|
| **Create** `.github/workflows/supply-chain-attest.yml` | Single job: checkout → build Go → build npm → tar bundle → install Syft → SBOMs → attest (4 invocations) → upload artifacts |
| **Modify** `README.md` | New **Supply chain** subsection: when attestations run, how to download artifacts, `gh attestation verify` examples for binary, tarball, and SBOM-backed subjects; note public vs private repo limits |

No changes to `nightstalker-ci.yml`, `action.yml` runtime contract, or Go source in v1 unless Syft/BPF exposes a gap (fix in follow-up).

---

### Task 1: Add `supply-chain-attest` workflow

**Files:**

- Create: `.github/workflows/supply-chain-attest.yml`

- Test: Push branch, run **Actions → supply-chain-attest → Run workflow** (`workflow_dispatch`); confirm job green and **Attestations** tab shows new entries.

- [ ] **Step 1: Create the workflow file**

Create `.github/workflows/supply-chain-attest.yml` with exactly this content (adjust only if `actions/attest` or `checkout` major must change after a future security advisory):

```yaml
# Builds and attests release-grade artifacts: Go agent binary, composite action tarball,
# and CycloneDX SBOMs (Go + npm). Triggers on version tags and manual dispatch.
# Spec: docs/superpowers/specs/2026-04-12-github-attestations-sbom-design.md

name: supply-chain-attest

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

permissions:
  contents: read
  id-token: write
  attestations: write
  artifact-metadata: write

concurrency:
  group: supply-chain-attest-${{ github.ref }}
  cancel-in-progress: true

jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5

      - name: Setup Go
        uses: actions/setup-go@v6
        with:
          go-version: '1.24.x'

      - name: Setup Node
        uses: actions/setup-node@v5
        with:
          node-version: '24'
          cache: npm

      - name: Build Go agent (BPF + binary)
        run: bash scripts/build-agent-linux.sh "$GITHUB_WORKSPACE"

      - name: Build action bundle (ncc)
        run: |
          set -euo pipefail
          npm ci
          npm run typecheck
          npm run build

      - name: Create composite action bundle archive
        run: |
          set -euo pipefail
          test -f action.yml
          test -f dist/main/index.js
          test -f dist/post/index.js
          tar -czf nightstalker-action-bundle.tar.gz action.yml dist/main dist/post

      - name: Install Syft (pinned)
        env:
          SYFT_VERSION: '1.18.0'
        run: |
          set -euo pipefail
          curl -sSfL -o /tmp/syft.deb \
            "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.deb"
          sudo dpkg -i /tmp/syft.deb
          syft version

      - name: Generate SBOMs (CycloneDX JSON)
        run: |
          set -euo pipefail
          # Go-focused SBOM (module + deps); lockfile path keeps catalogers deterministic.
          syft scan "file:${GITHUB_WORKSPACE}/go.mod" \
            -o "cyclonedx-json=${GITHUB_WORKSPACE}/sbom-go.cdx.json"
          # npm dependency SBOM from lockfile (action runtime deps).
          syft scan "file:${GITHUB_WORKSPACE}/package-lock.json" \
            -o "cyclonedx-json=${GITHUB_WORKSPACE}/sbom-js.cdx.json"
          ls -la sbom-go.cdx.json sbom-js.cdx.json

      - name: Attest — build provenance (Go binary)
        uses: actions/attest@v4
        with:
          subject-path: '${{ github.workspace }}/bin/ci-runtime-guard'

      - name: Attest — build provenance (action bundle tarball)
        uses: actions/attest@v4
        with:
          subject-path: '${{ github.workspace }}/nightstalker-action-bundle.tar.gz'

      - name: Attest — SBOM for Go binary subject
        uses: actions/attest@v4
        with:
          subject-path: '${{ github.workspace }}/bin/ci-runtime-guard'
          sbom-path: '${{ github.workspace }}/sbom-go.cdx.json'

      - name: Attest — SBOM for action bundle subject
        uses: actions/attest@v4
        with:
          subject-path: '${{ github.workspace }}/nightstalker-action-bundle.tar.gz'
          sbom-path: '${{ github.workspace }}/sbom-js.cdx.json'

      - name: Upload attestable artifacts
        uses: actions/upload-artifact@v4
        with:
          name: supply-chain-artifacts-${{ github.run_id }}
          path: |
            bin/ci-runtime-guard
            nightstalker-action-bundle.tar.gz
            sbom-go.cdx.json
            sbom-js.cdx.json
          if-no-files-found: error
```

- [ ] **Step 2: Commit the workflow**

```bash
git add .github/workflows/supply-chain-attest.yml
git commit -m "ci: add supply-chain attest workflow for binary, bundle, and SBOMs"
```

- [ ] **Step 3: Validate Syft commands on the runner**

If **Step 1** fails at **Generate SBOMs** with `syft scan file:...` errors (Syft CLI drift), replace that step with the smallest change that works on `ubuntu-latest`, for example:

```bash
syft scan "${GITHUB_WORKSPACE}" \
  --source go-mod \
  -o "cyclonedx-json=${GITHUB_WORKSPACE}/sbom-go.cdx.json"
```

or use `syft packages` instead of `syft scan` per the installed Syft `--help` output. Re-run **`workflow_dispatch`** until green.

**Expected:** Workflow completes; run summary lists attestations from **`actions/attest`**.

---

### Task 2: Document verification in README

**Files:**

- Modify: `README.md` (add a **Supply chain** subsection near the end or after CI / contributing; keep tone factual.)

- Test: Rendered Markdown preview; no code execution.

- [ ] **Step 1: Insert README subsection**

Add the following subsection (adjust heading level `#` vs `##` to match surrounding README structure—use the same level as adjacent major sections):

```markdown
## Supply chain (artifact attestations)

Release-tagged builds (`v*`) and manual runs of the [**supply-chain-attest**](../.github/workflows/supply-chain-attest.yml) workflow produce:

- **`bin/ci-runtime-guard`** — SLSA build provenance + CycloneDX SBOM attestation (Go module / deps).
- **`nightstalker-action-bundle.tar.gz`** — archive of `action.yml`, `dist/main`, `dist/post` with provenance + SBOM attestation (npm lockfile surface).

Download the **`supply-chain-artifacts-<run_id>`** artifact from the workflow run, extract if needed, then verify with the [GitHub CLI](https://cli.github.com/) (v2.49+ recommended for `attestation`):

```bash
gh attestation verify bin/ci-runtime-guard --repo github.com/shermanatoor/nightstalker
gh attestation verify nightstalker-action-bundle.tar.gz --repo github.com/shermanatoor/nightstalker
```

Use the **repository** and **paths** from your checkout. Each path is the **attestation subject** (the binary and the tarball); GitHub stores **separate** attestations for **SLSA provenance** and for **SBOM** predicates that reference the same subject, and `gh attestation verify` resolves attestations for that file. Do not point `gh attestation verify` at the `.cdx.json` files unless your `gh` version documents SBOM-only subjects—here the SBOMs ship as artifacts for SPDX/CDX consumers, not as standalone verification paths.

If `gh` reports a **predicate-type** or **bundle** error, run `gh attestation verify --help` and add the suggested flag for your CLI version.

**Limits:** Artifact attestations require a **public** repo on free/team plans; **private** repos need **GitHub Enterprise Cloud**. There is **no container image signing** in this repo (v1).

Official guide: [Using artifact attestations to establish provenance for builds](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds).
```

- [ ] **Step 2: Commit README**

```bash
git add README.md
git commit -m "docs: supply chain attestation verification for release artifacts"
```

---

### Task 3: End-to-end verification (maintainer checklist)

**Files:** none (manual QA)

- [ ] **Step 1: Run workflow**

On GitHub: **Actions → supply-chain-attest → Run workflow** on branch `feat/supply-chain-attestations` (or default branch after merge). Confirm success.

- [ ] **Step 2: Download artifacts**

Download **`supply-chain-artifacts-*`** from the run; confirm four files present and binary is executable on Linux.

- [ ] **Step 3: Verify attestations locally**

```bash
gh auth login   # if needed
gh attestation verify bin/ci-runtime-guard --repo github.com/shermanatoor/nightstalker
```

**Expected:** `✓ Verification succeeded` (or current success message). Repeat for **`nightstalker-action-bundle.tar.gz`**. (SBOM CycloneDX files are retained for tooling; verification is against **subjects**—binary and tarball—as above.)

If verification fails with **permission** or **not found**, confirm the run is on a **public** repo and that **`gh`** meets minimum version; re-read [gh attestation verify](https://cli.github.com/manual/gh_attestation_verify).

- [ ] **Step 4: Tag dry run (optional)**

```bash
git tag v0.0.0-attest-test
git push origin v0.0.0-attest-test
```

Confirm the workflow triggers on **`v*`** tag. Delete the test tag afterward if policy allows:

```bash
git push origin :refs/tags/v0.0.0-attest-test
```

---

## Spec coverage (self-review)

| Spec requirement | Task |
|------------------|------|
| Go binary provenance (A) | Task 1 — attest `bin/ci-runtime-guard` |
| Bundle archive provenance (B) | Task 1 — `tar` + attest tarball |
| SBOM JSON + SBOM attestation (C) | Task 1 — Syft + two `sbom-path` attest steps |
| No OCI / Cosign images | Out of scope — no tasks |
| Separate from matrix CI | Task 1 — standalone workflow only |
| Verification story | Task 2 README + Task 3 `gh` commands |
| OIDC / permissions | Task 1 YAML `permissions` block |

**Placeholder scan:** None intentional; Syft CLI surface may require Step 3 adjustment in Task 1 (documented as allowed fix path).

**Type consistency:** Artifact paths use `${{ github.workspace }}` consistently; subject paths match attest action contract.

---

## Execution handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-12-supply-chain-attestations.md`. Two execution options:**

**1. Subagent-driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration. **REQUIRED SUB-SKILL:** superpowers:subagent-driven-development.

**2. Inline execution** — Run tasks in this session with checkpoints. **REQUIRED SUB-SKILL:** superpowers:executing-plans.

**Which approach do you want?**
