# Release process (maintainers)

Run these **in order** when cutting a new **tag** so the **Marketplace / `uses: coldstep-io/coldstep@<tag>`** story, the **prebuilt Linux agent** on GitHub Releases, and the **static site** stay aligned.

## Consumer pin standard (normative)

This is the **single standard** for where the recommended **`coldstep-io/coldstep@vX.Y.Z`** pin and **`COLDSTEP_AGENT_VERSION`** appear. Everything else should defer to this file.

| Surface | When to update | Rule |
| :------ | :------------- | :--- |
| `public_scripts/check_workflow_action_pins.py` (`MARKETPLACE_COLDSTEP_TAG`) | Release PR (same train as the tag) | Must equal the tag you are about to publish. |
| `README.md`, `QUICK_START.md`, `CONTRIBUTING.md` | Release PR | Recommended consumer pin = that tag. |
| `.github/workflows/coldstep-demo*.yml` and related (`COLDSTEP_AGENT_VERSION`, comments) | Release PR | Must match the GitHub Release that publishes **`coldstep-linux-amd64`**. |
| `CHANGELOG.md` | Release PR | Add **`## [X.Y.Z]`** (semver without leading **`v`**) and keep footer compare links accurate. |
| **`website/index.html`** | **Follow-up PR to `main` after** the tag exists on **GitHub Releases** | **Never** ship marketing-site YAML examples for a tag that is not published yet. One small PR that only bumps site pins is fine. |
| GitHub Marketplace listing | After release | Human step outside this repo; pin text should match the shipped tag. |

**Two trains (do not mix them up):**

1. **Repository docs + CI pins** — updated in the **release PR** merged before **`git tag`**. They may document the **next** tag while **`CHANGELOG.md` `[Unreleased]`** explains what is not published yet (see that section when applicable).
2. **GitHub Pages (`website/`)** — updated **only after** the tag is live on Releases, so visitors never copy a non-existent **`uses:`** pin.

## 1. Land the release on `main`

- Open a **PR** (for example `release/vX.Y.Z`) with version bumps: **`README`**, **`QUICK_START`**, **`CONTRIBUTING`**, **`public_scripts/check_workflow_action_pins.py`** → **`MARKETPLACE_COLDSTEP_TAG`**, **`coldstep-demo*`** workflows → **`COLDSTEP_AGENT_VERSION`**, and **`CHANGELOG.md`**. **Exclude `website/`** from this PR by default; bump **`website/index.html`** in a **follow-up PR after** the tag is published on Releases (**Consumer pin standard**).
- Wait for **CI green** on the PR (`coldstep-ci`, CodeQL, etc.), then **merge to `main`**.  
- **Do not** tag until the release commit is on `main`.

## 2. Bug readiness gate (before tagging)

Repo-local bug-hunting playbooks (`docs/bug_hunting/*.md`, gitignored with `/docs/`) expand on triage and review; keep them updated as processes change.

Confirm bug-hunting and bug-fix readiness explicitly before creating a release tag:

- **No open release-blocking regressions:** no unresolved P0/P1 bugs for detect mode, defend (blocking) mode, CI entry workflow, or release packaging.
- **Evidence artifacts present:** latest successful CI run has downloadable detect / defend artifacts (`.coldstep-events.jsonl`, `.coldstep-detect.md`, `.coldstep-telemetry.json`) for forensic replay.
- **Critical-path regressions checked:** if release PR touched critical paths (`internal/agent/`, `internal/bpf/`, `bpf/`, `.github/workflows/`, report scripts), ensure critical-path heavy checks passed (`go test -shuffle`, `govulncheck`).
- **Deep-debug policy acknowledged:** if issue history includes flakiness, verifier/load instability, or cross-layer failures, run deep-debug before tagging and attach/report outcome.
- **Known-risk owner assigned:** any accepted non-blocking risk has a documented owner and follow-up issue with target milestone.

## 3. Update local `main` and create the tag

```bash
git checkout main
git pull origin main
git tag -s vX.Y.Z -m "Release vX.Y.Z — <short description>"
git push origin vX.Y.Z
```

Use an **annotated**, **signed** tag (`-s`) if your signing policy expects it.

## 4. Verify `supply-chain-attest`

Pushing **`v*`** triggers [`.github/workflows/supply-chain-attest.yml`](.github/workflows/supply-chain-attest.yml).

- Watch the run: **Actions → supply-chain-attest**, or  
  `gh run list --workflow=supply-chain-attest.yml --limit 3`
- Confirm **success** on: Go build, npm bundle + tarball, SBOMs, **Attest** steps, **Upload Linux agent to GitHub Release**, **Upload attestable artifacts**.

If **Upload Linux agent** hits **immutable Release** / **HTTP 422**, the workflow emits a **`::warning`** and **still succeeds** (see PR **#47**). Then attach **`coldstep-linux-amd64`** from the workflow run’s **`supply-chain-artifacts-*`** artifact to the Release, or temporarily relax immutability.

## 5. Confirm GitHub Release

- **Releases → `vX.Y.Z`** should list **`coldstep-linux-amd64`** (when upload succeeded).
- Optional notes: paste the **`CHANGELOG.md`** section for that version.
- For a **pre-release** (soak / validation first): on the Release, check **Set as pre-release**; clear it when promoting to **Latest**.

## 6. Confirm GitHub Pages

[`coldstep-pages`](.github/workflows/coldstep-pages.yml) runs on **push to `main`**. The **release PR** merge triggers a deploy, but **marketing copy pins** on the site may still show the previous tag until you complete the **post-tag `website/`** bump (**Consumer pin standard**). Confirm the workflow run succeeded; then open the **follow-up** site pin PR if needed.

## 7. Consumer sanity check

- `gh release download vX.Y.Z --repo coldstep-io/coldstep --pattern 'coldstep-linux-amd64' --dir /tmp`
- Demo workflows use **`gh release download "${COLDSTEP_AGENT_VERSION}"`** — version **must match** the tag that has the asset.

---

## Pin bump checklist (next release)

When cutting **`vX.Y.Z`**, bump **`[X.Y.Z]`** in **`CHANGELOG.md`** in the same shape as prior releases.

| Location | What to bump |
| -------- | ------------ |
| `public_scripts/check_workflow_action_pins.py` | `MARKETPLACE_COLDSTEP_TAG` |
| `README.md`, `QUICK_START.md`, `CONTRIBUTING.md` | `coldstep-io/coldstep@vX.Y.Z` |
| `.github/workflows/coldstep-demo*.yml` | `COLDSTEP_AGENT_VERSION` and comment examples |
| `CHANGELOG.md` | New `## [X.Y.Z]` section; fix footer compare links |
| **`website/index.html`** | **After** the tag is on GitHub Releases (**Consumer pin standard**). **`coldstep-pages`** deploys from `main` after merge. |

---

## Reference: v0.1.6 (completed 2026-04-19)

| Step | Result |
| ---- | ------ |
| Merge PR **#48** | **Merged** → `main` @ `c4029fd` |
| Push tag **`v0.1.6`** | Pushed; triggered **supply-chain-attest** run **24635189893** |
| Supply chain | **Success** (~1m19s); binary upload **OK** |
| Release **`v0.1.6`** | Present on GitHub Releases (**Latest**) |
| **coldstep-pages** | **Success** on merge push (**24635184515**) |

## Reference: v0.1.7 (pre-release train; tag after PR merge)

| Step | Result |
| ---- | ------ |
| Branch / PR | **`release/v0.1.7-prerelease`** — open PR to `main` (pin + `CHANGELOG` **pre-release** section) |
| After merge | Tag **`v0.1.7`**, push, confirm **supply-chain-attest**; mark GitHub Release **pre-release** until promoted |
| Second brain | `knowledge/wiki/versioned-releases-and-prerelease.md` + `knowledge/reports/2026-04-20-pre-release-v0.1.7-process.md` |
