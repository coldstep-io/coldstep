# GitHub Artifact Attestations + SBOM Design (Action + Go Binary)

**Repository state (2026-04-12):** Composite GitHub Action (`action.yml`, `src/`, `dist/` via ncc), Go agent **`cmd/ci-runtime-guard`** built in CI as **`bin/ci-runtime-guard`**. **No OCI product image**; Docker appears only in local/dev scripts. This spec covers **v1** supply-chain hardening without container signing.

## Goal

Bind **release-grade artifacts** to **this repository and a specific GitHub Actions workflow run** using **GitHub artifact attestations**, and publish **verifiable SBOMs** (SPDX or CycloneDX JSON) with **SBOM attestations**—so consumers and security reviews can answer: *who built this, from what workflow, and what components does it contain?*

## Scope (v1)

1. **Go binary (A)**  
   After a standard Linux build (same toolchain as today’s CI), generate a **build provenance** attestation for the produced **`bin/ci-runtime-guard`** (or the single canonical path chosen in implementation).

2. **Composite action bundle (B)**  
   Produce **one immutable archive** (e.g. `.tar.gz` or `.zip`) containing everything required for **`uses: ./`** at release time: e.g. **`action.yml`**, **`dist/main`**, **`dist/post`**, and any other documented runtime files. Generate **build provenance** for that archive **as one subject** (not per-file, unless policy later requires it).

3. **SBOM (C)**  
   - **Go:** One SBOM for the **Go module** (dependencies + module identity), SPDX or CycloneDX JSON.  
   - **Node:** One SBOM for the **action bundle** dependency surface (lockfile / install tree used to build `dist/`), SPDX or CycloneDX JSON.  
   Attach **SBOM attestations** (GitHub’s SBOM predicate flow) for each file via **`actions/attest`** with **`sbom-path`** (or current documented equivalent—pin action major at implementation time).

4. **Verification story**  
   Document **`gh attestation verify`** for maintainers and advanced consumers (predicate types, subject paths, optional `--repo` / `--owner` flags as needed).

## Out of scope (v1)

- **Signing or attesting OCI / GHCR images** (no product container; Cosign-for-images deferred).  
- **Replacing** existing **`nightstalker-ci`** matrix; attestations run on a **separate, low-frequency** workflow (see below) unless explicitly expanded later.  
- **Windows code signing** (product is Linux-only; AGENTS.md).  
- **Attesting every intermediate PR artifact** by default (optional future toggle if quota and noise are acceptable).

## Architecture

### Trust model

- **OIDC:** Workflows use **`id-token: write`** so GitHub can mint short-lived credentials; **no long-lived signing secrets** for keyless provenance.  
- **GitHub artifact attestations:** Provenance and SBOM bindings are stored and verified through GitHub’s attestation APIs; verification is **`gh`**-centric (acceptable for a GitHub Action product).

### Workflow placement

- **New workflow** (recommended name in implementation: e.g. **`supply-chain-attest.yml`** or **`release-attest.yml`**) triggered by:  
  - **`push` tags** matching a documented pattern (e.g. `v*`), and/or  
  - **`workflow_dispatch`** for manual releases or dry runs.  
- **Rationale:** Keeps **`permissions`** and attestation count predictable; avoids multiplying attestations across the **six-runner** CI matrix.

### Build steps (logical order)

1. **Checkout** at the **release ref** (tag or dispatch ref).  
2. **Build Go binary** (reuse same steps / script patterns as `scripts/build-agent-linux.sh` or documented subset—implementation plan details exact parity).  
3. **Build action bundle** (`npm ci`, `npm run build`, etc.)—parity with existing action bundle job.  
4. **Assemble bundle archive** with a deterministic file list (implementation: document manifest in plan).  
5. **Generate SBOMs**  
   - Go: chosen tool emits **JSON** SPDX or CycloneDX.  
   - Node: chosen tool emits **JSON** SPDX or CycloneDX from **`package-lock.json`** / installed tree.  
6. **Attest**  
   - Provenance: **`actions/attest`** (or pinned **`actions/attest-build-provenance`** if still preferred—unify on **`actions/attest`** per upstream guidance at implementation time) for **binary** and **bundle archive**.  
   - SBOM: **`actions/attest`** with **`sbom-path`** for each SBOM JSON file.  
7. **Upload** release artifacts (binary, bundle archive, SBOMs) as **workflow artifacts** and/or **GitHub Release assets** (implementation plan chooses one or both for discoverability).

### Permissions (initial set; tighten after first green run)

Minimum expected:

- **`contents: read`**  
- **`id-token: write`** (OIDC)  
- **`attestations: write`**  

Add only if GitHub documents or CI proves necessary (e.g. **`artifact-metadata: write`**, registry-related scopes)—**least privilege**.

### Consumer verification

- Document commands such as:  
  `gh attestation verify <path-to-binary> --repo OWNER/REPO`  
  `gh attestation verify <path-to-bundle.tgz> --repo OWNER/REPO`  
  and SBOM attestation verification with the appropriate **predicate type** flags as required by the **`gh`** version in use.  
- Link to GitHub Docs: *Using artifact attestations to establish provenance for builds*.

## Testing / acceptance

- [ ] Tagged (or `workflow_dispatch`) run completes green with attestations visible on the run.  
- [ ] **`gh attestation verify`** succeeds locally against downloaded **binary**, **bundle archive**, and **SBOM** subjects from that run.  
- [ ] README (or security doc) has a short **“Supply chain”** subsection with verification steps and scope (no images in v1).

## Risks and notes

- **Private repositories:** Artifact attestations may require **GitHub Enterprise Cloud**; **public** repos are the primary supported path—confirm org/repo visibility before promising internal-only GHES behavior.  
- **Action versioning:** Consumers pinning **`@sha`** on the action repo still benefit from **provenance on released bundle**; document relationship between **tag**, **commit**, and **attested artifact**.  
- **Tool drift:** Pin **`actions/attest`** (and SBOM generator action or CLI) to **SHA or major** per repo policy; re-read release notes when upgrading.

## References (implementation research)

- GitHub Docs: *Using artifact attestations to establish provenance for builds*  
- GitHub Docs: *Artifact attestations* (concepts)  
- **`actions/attest`** / **`actions/attest-sbom`** repositories (SBOM path consolidation—confirm current recommended inputs at implementation time)

## Next steps

1. **Implementation plan** (`writing-plans` skill): concrete workflow YAML, exact paths, SBOM tool choice, and README edits.  
2. **Feature branch** (e.g. `feat/supply-chain-attestations`) for all workflow and doc changes.
