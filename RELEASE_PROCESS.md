# Release process (maintainers)

Run these **in order** when cutting a new **tag** so the **Marketplace / `uses: coldstep-io/coldstep@<tag>`** story, the **prebuilt Linux agent** on GitHub Releases, and the **static site** stay aligned.

## 1. Land the release on `main`

- Open a **PR** (e.g. `release/v0.1.x`) with version bumps: `README`, `QUICK_START`, `CONTRIBUTING`, `website/index.html`, `public_scripts/check_workflow_action_pins.py` → `MARKETPLACE_COLDSTEP_TAG`, demo workflows → `COLDSTEP_AGENT_VERSION`, and **`CHANGELOG.md`**.
- Wait for **CI green** on the PR (`coldstep-ci`, CodeQL, etc.), then **merge to `main`**.  
- **Do not** tag until the release commit is on `main`.

## 2. Bug readiness gate (before tagging)

Repo-local bug-hunting playbooks (`docs/bug_hunting/*.md`, gitignored with `/docs/`) expand on triage and review; keep them updated as processes change.

Confirm bug-hunting and bug-fix readiness explicitly before creating a release tag:

- **No open release-blocking regressions:** no unresolved P0/P1 bugs for detect mode, enforce mode, CI entry workflow, or release packaging.
- **Evidence artifacts present:** latest successful CI run has downloadable detect/enforce artifacts (`.coldstep-events.jsonl`, `.coldstep-detect.md`, `.coldstep-telemetry.json`) for forensic replay.
- **Critical-path regressions checked:** if release PR touched critical paths (`internal/agent/`, `internal/bpf/`, `bpf/`, `.github/workflows/`, report scripts), ensure critical-path heavy checks passed (`go test -shuffle`, `govulncheck`).
- **Deep-debug policy acknowledged:** if issue history includes flakiness, verifier/load instability, or cross-layer failures, run deep-debug before tagging and attach/report outcome.
- **Known-risk owner assigned:** any accepted non-blocking risk has a documented owner and follow-up issue with target milestone.

## 3. Update local `main` and create the tag

```bash
git checkout main
git pull origin main
git tag -s v0.1.x -m "Release v0.1.x — <short description>"
git push origin v0.1.x
```

Use an **annotated**, **signed** tag (`-s`) if your signing policy expects it.

## 4. Verify `supply-chain-attest`

Pushing **`v*`** triggers [`.github/workflows/supply-chain-attest.yml`](.github/workflows/supply-chain-attest.yml).

- Watch the run: **Actions → supply-chain-attest**, or  
  `gh run list --workflow=supply-chain-attest.yml --limit 3`
- Confirm **success** on: Go build, npm bundle + tarball, SBOMs, **Attest** steps, **Upload Linux agent to GitHub Release**, **Upload attestable artifacts**.

If **Upload Linux agent** hits **immutable Release** / **HTTP 422**, the workflow emits a **`::warning`** and **still succeeds** (see PR **#47**). Then attach **`coldstep-linux-amd64`** from the workflow run’s **`supply-chain-artifacts-*`** artifact to the Release, or temporarily relax immutability.

## 5. Confirm GitHub Release

- **Releases → `v0.1.x`** should list **`coldstep-linux-amd64`** (when upload succeeded).
- Optional notes: paste the **`CHANGELOG.md`** section for that version.
- For a **pre-release** (soak / validation first): on the Release, check **Set as pre-release**; clear it when promoting to **Latest**.

## 6. Confirm GitHub Pages

[`coldstep-pages`](.github/workflows/coldstep-pages.yml) runs on **push to `main`**. After the **release PR** merged, **`website/`** should already be deploying; confirm the latest run succeeded.

## 7. Consumer sanity check

- `gh release download v0.1.x --repo coldstep-io/coldstep --pattern 'coldstep-linux-amd64' --dir /tmp`
- Demo workflows use **`gh release download "${COLDSTEP_AGENT_VERSION}"`** — version **must match** the tag that has the asset.

---

## Pin bump checklist (next release)

When preparing **v0.1.(x+1)**:

| Location | What to bump |
| -------- | ------------ |
| `public_scripts/check_workflow_action_pins.py` | `MARKETPLACE_COLDSTEP_TAG` |
| `README.md`, `QUICK_START.md`, `CONTRIBUTING.md`, `website/index.html` | `coldstep-io/coldstep@v…` |
| `.github/workflows/coldstep-demo*.yml` | `COLDSTEP_AGENT_VERSION` and comment examples |
| `CHANGELOG.md` | New `## [0.1.(x+1)]` section; fix footer compare links |

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
