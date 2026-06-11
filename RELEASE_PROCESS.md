# Release process (maintainers)

Run these **in order** when cutting a new **tag** so the **Marketplace / `uses: coldstep-io/coldstep@<tag>`** story, the **prebuilt Linux agent** on GitHub Releases, and the **static site** stay aligned.

## Release invariant — the tag ships its own binary (normative, enforced)

**The commit a `vX.Y.Z` tag points to MUST carry `COLDSTEP_BINARY_VERSION = 'vX.Y.Z'` in `src/shared.ts` AND in the compiled `dist/{pre,main,post}/index.js` bundles.** The action downloads the agent binary from the Release named by that constant — if the tagged commit still carries the previous version, everyone who pins the tag (the documented secure practice) silently runs the **previous** agent. This shipped for real: the `v0.5.2` tag pointed at a commit with `COLDSTEP_BINARY_VERSION='v0.5.1'` because the bump lived in a post-tag "Train-2" commit (see *Reference: v0.5.2 incident* below).

**Therefore: the `COLDSTEP_BINARY_VERSION` bump + `npm run build` dist rebuild go in the release PR, BEFORE the tag. There is no post-tag binary-version train. Never tag a commit whose `src/shared.ts` lags the tag.**

This is safe pre-tag because the action fetches the asset SHA-256 from the Releases API at runtime (`src/shared.ts`) — no digest needs to exist when the bump lands. The only cost is a short window between merging the release PR and the tag's `supply-chain-attest` run finishing, during which `@main` consumers fail fast with a clear Releases-API 404. Minimize it: **push the tag immediately after the release PR merges.**

In-repo CI is immune to that window by construction: the `detect-mode` and `defend-mode` jobs build from source and pass `release-path: bin/coldstep` (a release PR pins the next, not-yet-published version, so they must never depend on the consumer download), and `start` seeds the runner-temp binary cache from `release-path` so the stop phase renders the report without touching the Releases API. The published-download path is exercised by consumers and the post-tag demo/red-team workflows.

Enforced in three places — do not remove any of them:

| Gate | Where it runs | What it catches |
| :--- | :------------ | :-------------- |
| `scripts/check_release_version_alignment.py` | `coldstep-ci-runner.yml` `action_bundle` job (every PR/push) | `src/shared.ts` vs `dist/` drift (bumped without rebuild) and `COLDSTEP_BINARY_VERSION` vs `MARKETPLACE_COLDSTEP_TAG` drift (docs pin bumped without the binary version, or vice versa). |
| `scripts/check_release_version_alignment.py --tag "$GITHUB_REF_NAME"` | `supply-chain-attest.yml`, first step on every `v*` tag push | A tag placed on a commit that does not ship its own version — **fails the release before any asset is built, attested, or uploaded.** |
| `internal/releasecheck` (Go test) | `go test ./...` locally + every CI unit job | Same src/dist/marketplace alignment, caught at unit-test time without Python. |

If the tag gate fires: delete the bad tag (or leave it unreleased — the gate ran before any asset upload), land the bump + dist rebuild on `main`, and tag the corrected commit. **Never re-point an already-published tag**; if a bad tag already has a Release, cut the next patch version instead and note the bad tag in `CHANGELOG.md`.

## Consumer pin standard (normative)

This is the **single standard** for where the recommended **`coldstep-io/coldstep@vX.Y.Z`** pin and **`COLDSTEP_AGENT_VERSION`** appear. Everything else should defer to this file.

| Surface | When to update | Rule |
| :------ | :------------- | :--- |
| **`src/shared.ts` (`COLDSTEP_BINARY_VERSION`) + `dist/` rebuild (`npm run build`)** | **Release PR (before the tag — Release invariant)** | Must equal the tag you are about to publish; the tag-time gate in `supply-chain-attest` rejects the release otherwise. |
| `scripts/check_workflow_action_pins.py` (`MARKETPLACE_COLDSTEP_TAG`) | Release PR (same train as the tag) | Must equal the tag you are about to publish. |
| `README.md`, `QUICK_START.md`, `CONTRIBUTING.md` | Release PR | Recommended consumer pin = that tag. |
| `.github/workflows/coldstep-demo*.yml` and related (`COLDSTEP_AGENT_VERSION`, comments) | Release PR | Must match the GitHub Release that publishes **`coldstep-linux-amd64`**. |
| `CHANGELOG.md` | Release PR | Add **`## [X.Y.Z]`** (semver without leading **`v`**) and keep footer compare links accurate. |
| **`website/index.html`** | **Follow-up PR to `main` after** the tag exists on **GitHub Releases** | **Never** ship marketing-site YAML examples for a tag that is not published yet. One small PR that only bumps site pins is fine. |
| GitHub Marketplace listing | After release | Human step outside this repo; pin text should match the shipped tag. |

**Two trains (do not mix them up):**

1. **Repository docs + CI pins + `COLDSTEP_BINARY_VERSION` + `dist/`** — updated in the **release PR** merged before **`git tag`**. They may document the **next** tag while **`CHANGELOG.md` `[Unreleased]`** explains what is not published yet (see that section when applicable). The binary version is **never** bumped post-tag — a post-tag "Train-2" bump is exactly what shipped the v0.5.2 incident (Release invariant above).
2. **GitHub Pages (`website/`)** — updated **only after** the tag is live on Releases, so visitors never copy a non-existent **`uses:`** pin. This is why CI runs `check_workflow_action_pins.py --skip-website`; the no-flag run is the manual post-tag check that the site follow-up landed.

## 1. Land the release on `main`

- Open a **PR** (for example `release/vX.Y.Z`) with version bumps: **`src/shared.ts`** → **`COLDSTEP_BINARY_VERSION`** **plus the matching `npm run build` `dist/` rebuild committed in the same PR** (Release invariant — CI fails the PR if either is missing), **`README`**, **`QUICK_START`**, **`CONTRIBUTING`**, **`scripts/check_workflow_action_pins.py`** → **`MARKETPLACE_COLDSTEP_TAG`**, **`coldstep-demo*`** workflows → **`COLDSTEP_AGENT_VERSION`**, and **`CHANGELOG.md`**. **Exclude `website/`** from this PR by default; bump **`website/index.html`** in a **follow-up PR after** the tag is published on Releases (**Consumer pin standard**).
- Wait for **CI green** on the PR (`coldstep-ci`, CodeQL, etc.), then **merge to `main`**.  
- **Do not** tag until the release commit is on `main`.

## 2. Bug readiness gate (before tagging)

Repo-local bug-hunting playbooks (`docs/bug_hunting/*.md`, gitignored with `/docs/`) expand on triage and review; keep them updated as processes change.

Confirm bug-hunting and bug-fix readiness explicitly before creating a release tag:

- **No open release-blocking regressions:** no unresolved P0/P1 bugs for detect mode, defend (blocking) mode, CI entry workflow, or release packaging.
- **Evidence artifacts present:** latest successful CI run has downloadable detect / defend artifacts (`.coldstep-events.jsonl`, `.coldstep-report.md`, `.coldstep-telemetry.json`) for forensic replay.
- **Critical-path regressions checked:** if release PR touched critical paths (`internal/agent/`, `internal/bpf/`, `bpf/`, `.github/workflows/`, report scripts), ensure critical-path heavy checks passed (`go test -shuffle`, `govulncheck`).
- **Deep-debug policy acknowledged:** if issue history includes flakiness, verifier/load instability, or cross-layer failures, run the **`coldstep-deep-debug`** workflow (**`workflow_dispatch`**) before tagging and attach/report outcome from the uploaded artifact.
- **Known-risk owner assigned:** any accepted non-blocking risk has a documented owner and follow-up issue with target milestone.

## 3. Update local `main` and create the tag

```bash
git checkout main
git pull origin main
# Release invariant pre-flight: the commit you are about to tag must ship its own version.
python3 scripts/check_release_version_alignment.py --tag vX.Y.Z
git tag -s vX.Y.Z -m "Release vX.Y.Z — <short description>"
git push origin vX.Y.Z
```

Use an **annotated**, **signed** tag (`-s`) if your signing policy expects it.

Tag **the release-PR merge commit** (current `main` tip right after the merge) — never an older commit. Push the tag **immediately** after the merge: until `supply-chain-attest` publishes the `vX.Y.Z` asset, `@main` consumers fail fast on the Releases-API 404 (Release invariant section above).

## 4. Verify `supply-chain-attest`

Pushing **`v*`** triggers [`.github/workflows/supply-chain-attest.yml`](.github/workflows/supply-chain-attest.yml). Its **first step** is the Release-invariant gate (`check_release_version_alignment.py --tag`): a tag pointing at a commit that does not ship its own `COLDSTEP_BINARY_VERSION` fails here, before any artifact is built or uploaded. If it fires, follow the remediation in the Release invariant section — do not re-run the job hoping it passes.

- Watch the run: **Actions → supply-chain-attest**, or  
  `gh run list --workflow=supply-chain-attest.yml --limit 3`
- Confirm **success** on: Go build, npm bundle + tarball, SBOMs, **Attest** steps, **Upload Linux agent to GitHub Release**, **Upload attestable artifacts**.

If **Upload Linux agent** hits **immutable Release** / **HTTP 422**, the workflow emits a **`::warning`** and **still succeeds** (see PR **#47**). Then attach **`coldstep-linux-amd64`** from the workflow run’s **`supply-chain-artifacts-*`** artifact to the Release, or temporarily relax immutability.

## 5. Confirm GitHub Release

- **Releases → `vX.Y.Z`** should list **`coldstep-linux-amd64`** (when upload succeeded) — the single published binary asset, now the **combined** `coldstep` binary (agent + `start`/`stop`/`diff`/`assert-integrity` subcommands). The **`coldstep-report-linux-amd64`** asset (issue **#219**) was retired earlier; the separate `coldstep-action` binary was folded into this combined binary, so new tags ship one artifact.
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
| **`src/shared.ts`** | **`COLDSTEP_BINARY_VERSION` → `vX.Y.Z`, then `npm run build` and commit `dist/` (Release invariant — same PR, before the tag)** |
| `scripts/check_workflow_action_pins.py` | `MARKETPLACE_COLDSTEP_TAG` |
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

## Reference: v0.5.2 incident — tag shipped the previous agent (root cause + fix)

**What happened.** Consumers pinning `uses: coldstep-io/coldstep@v0.5.2` (or the commit SHA `3e58f37` the tag resolves to) silently downloaded and ran the **v0.5.1** agent. Found externally by coldstep-labs (runner log: `coldstep: downloading v0.5.1 from …/releases/download/v0.5.1/coldstep-linux-amd64` under the v0.5.2 pin).

**Root cause.** The release flow at the time split the version bump across two trains: the `v0.5.2` tag was placed on the Train-1 release-pins commit (`3e58f37`, PR #301) while `src/shared.ts` / `dist/` still read `COLDSTEP_BINARY_VERSION='v0.5.1'`; the bump landed one commit **after** the tag (`23a3bbe`, Train-2, PR #302). The same pattern existed at v0.5.1 (PR #294) — so **every** tag structurally shipped the previous binary. Not a one-off mistake; a process defect.

**Why it was invisible.** No CI job or release gate compared `COLDSTEP_BINARY_VERSION` to anything: `check_workflow_action_pins.py` was manual-only and never checked `src/shared.ts`, and `supply-chain-attest` built and uploaded whatever the tagged commit contained.

**Fix (this is now the standing rule — see Release invariant at the top):**

1. `COLDSTEP_BINARY_VERSION` bump + `dist/` rebuild moved into the release PR, before the tag. The post-tag Train-2 binary bump is abolished.
2. `scripts/check_release_version_alignment.py` enforces src == dist == `MARKETPLACE_COLDSTEP_TAG` on every PR (`action_bundle` job), and `== tag` as the first step of `supply-chain-attest` on every `v*` push.
3. `internal/releasecheck` repeats the alignment check in `go test ./...`.

**Remediation of the shipped tag.** `v0.5.2` was left as-is (signed tag, immutable Release — never re-point a published tag); the first tag cut under the corrected flow supersedes it and `CHANGELOG.md` notes that `v0.5.2` ran the v0.5.1 agent.

## Reference: v0.2.1

| Step | Maintainer action |
| ---- | ----------------- |
| Release PR | Bump pins (`scripts/check_workflow_action_pins.py` **MARKETPLACE_COLDSTEP_TAG**), **`CHANGELOG.md` [0.2.1]**, demo/red-team **`COLDSTEP_AGENT_VERSION`**, docs, and **`website/index.html`** (allowed in the same train when the tag is about to ship; site should not advertise a tag that will never be published). |
| After merge to `main` | `git tag -s v0.2.1 -m "Release v0.2.1"` → **`git push origin v0.2.1`**. |
| Verify | **`supply-chain-attest`** green; Release **`v0.2.1`** lists **`coldstep-linux-amd64`**; **`gh release download v0.2.1 --pattern coldstep-linux-amd64`**. If the job failed on “immutable + no assets,” fix the empty Release (see workflow log) and re-run **`workflow_dispatch`** on **supply-chain-attest** for the tag, or delete the empty Release and push a new tag. |
| Demo smoke | **`workflow_dispatch`** on **`coldstep-demo`** (env **`COLDSTEP_AGENT_VERSION: v0.2.1`**). |
