# Micro tasks — `v0.2.0` completion track

**Normative pin / release steps:** **`RELEASE_PROCESS.md`** (**Consumer pin standard**).  
**External research (local vault, gitignored):** `knowledge/records/2026-04-29-github-actions-immutable-releases-and-attestations-synthesis.md`

## Micro sprint A — Git / release

- [x] **`git push origin dev`** — ensure **`main`**-bound doc commits (e.g. release process) are on GitHub.
- [ ] **PR `dev` → `main`** — merge when CI green (`coldstep-ci`, CodeQL).
- [ ] **Release PR on `main`** — bump pins per checklist (`MARKETPLACE_COLDSTEP_TAG`, README trio, `COLDSTEP_AGENT_VERSION`, **`CHANGELOG.md` `## [0.2.0]`**); **exclude `website/`**.
- [ ] **`git tag -s v0.2.0`** + push → verify **`supply-chain-attest`**.
- [ ] **Follow-up PR:** **`website/index.html`** pins only (after tag on Releases).

## Micro sprint B — CI truth (re-validate)

- [ ] **`coldstep-detect-demo-dev`** — verify step vs **`.coldstep-detect.md`** lifecycle / Stop phase.
- [ ] **`coldstep-redteam-ebpf`** — anti-blindness canaries present or gate adjusted with **`VALIDATION.md`** honesty.

## Micro sprint C — backlog (non-blocking for tag)

- [ ] GitHub milestone **#73–#77** — close or move leftovers.
- [ ] Detect/defend track plans — next **`D`/`F`** items post-release.

## Done (reference)

- [x] **Consumer pin standard** documented in **`RELEASE_PROCESS.md`** (commit on **`dev`**).
- [x] **Vault synthesis** — immutable releases + attestations ↔ Coldstep (`knowledge/records/2026-04-29-github-actions-immutable-releases-and-attestations-synthesis.md`).
