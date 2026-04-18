# CI hygiene, supply-chain workflow state, workflow dedup, and publish-surface hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align repository documentation and automation with **disabled** supply-chain attestation builds; make the relationship between **`nightstalker-ci.yml`** and **`nightstalker-ci-runner.yml`** obvious and reduce duplicated shell where it is safe; harden **`.gitignore`** against accidental commits of secrets and generated BPF outputs; and **stop tracking internal planning/spec trees** under **`docs/superpowers/`** (optional full **`docs/`** scope) so Git only carries what operators need to build and run the action and agent. **Regarding `scripts/`:** do **not** add `/scripts/` to `.gitignore` unless you complete **Task 4b** first—today’s **GitHub Actions** jobs and the **slim composite** invoke `python3 scripts/...` and `bash scripts/...` after checkout; removing `scripts/` from the repo **breaks CI** with no replacement.

**Architecture:** Keep the **caller / reusable** split (`nightstalker-ci.yml` → `workflow_call` → `nightstalker-ci-runner.yml`); deduplicate repeated **Go + BPF prep** steps by introducing a **local composite Action** (e.g. **`.github/actions/nightstalker-go-bpf-ci`**) invoked from multiple jobs in **`nightstalker-ci-runner.yml`**. Treat **`supply-chain-attest.yml.disabled`** as the canonical “off switch” until re-enabled: update **`README.md`** and any badges/links so users are not sent to a missing workflow. For **docs**, remove **`docs/superpowers/**`** from the Git index and ignore that path (narrowest interpretation of “do not publish `docs/*`” that preserves optional top-level **`docs/`** for future public guides—if you truly want **zero** `docs/` in Git, extend the ignore to **`/docs/`** and delete or relocate every file under `docs/` in the same change). For **`scripts/`**: the **published Node action bundle** (`ncc` → `dist/`) already does **not** ship `scripts/`; if the requirement is “no `scripts/` in **Git**,” relocate CI entrypoints to **`.github/scripts/`** (still tracked) and update all workflow/composite paths in **Task 4b**—**never** bare `.gitignore` on `/scripts/` without that migration.

**Tech Stack:** GitHub Actions (`workflow_call`, composite `uses:`), YAML, bash, Python (`scripts/assert_utf8_text.py`), Go 1.24.x, existing **`scripts/build-agent-linux.sh`** / **`scripts/check-gofmt.sh`**.

---

## File map

| Path | Responsibility |
|------|----------------|
| [`.github/workflows/nightstalker-ci.yml`](../../.github/workflows/nightstalker-ci.yml) | **Entry** workflow: `on`, permissions, concurrency, **matrix** of `runner_label` / `use_slim_action`, single `uses: ./.github/workflows/nightstalker-ci-runner.yml`. |
| [`.github/workflows/nightstalker-ci-runner.yml`](../../.github/workflows/nightstalker-ci-runner.yml) | **Reusable** workflow: jobs `slim`, `action_manifest`, `unit`, `integration`, `action_bundle`, `detect-mode`, `prevent-mode`. Target for composite-based dedup. |
| [`.github/workflows/supply-chain-attest.yml.disabled`](../../.github/workflows/supply-chain-attest.yml.disabled) | Disabled attest workflow (rename blocks `on:`). Source of truth that attestations are **off**. |
| [`README.md`](../../README.md) | Remove or rewrite **Supply chain** section to match disabled workflow; fix any workflow links. |
| [`AGENTS.md`](../../AGENTS.md) | If it promises **`supply-chain-attest.yml`** as active, align wording with disabled state (or “re-enable by renaming”). |
| **Create:** [`.github/actions/nightstalker-go-bpf-ci/action.yml`](../../.github/actions/nightstalker-go-bpf-ci/action.yml) | Composite: checkout is **not** included (each job keeps `actions/checkout` first), then shared Go version, gofmt, `build-agent-linux.sh`, `go vet`, `staticcheck`. |
| [`.gitignore`](../../.gitignore) | Add secret-ish globs; add **`docs/superpowers/`** (or `/docs/`) ignore; add missing **`internal/bpf/tracefs/*_bpfel.go`** / **`*_bpfeb.go`** lines to match other bpf2go packages. |
| [`docs/superpowers/`](../../docs/superpowers/) | **Stop tracking** under Git per product decision (see tasks); maintainers keep a private copy or export if still needed. |
| [`scripts/`](../../scripts/) | **CI-critical** today; not ignored unless **Task 4b** rehomes scripts and updates every caller. |
| **Optional create:** [`.github/scripts/`](../../.github/scripts/) | New home for `assert_utf8_text.py`, `utf8_repo_text.py`, `check-gofmt.sh`, `build-agent-linux.sh`, `ci_nightstalker_jsonl_traffic_diff.py`, Docker test drivers—**only** if Task 4b is approved. |

---

## Clarification (not a task): `nightstalker-ci.yml` vs `nightstalker-ci-runner.yml`

They are **not** the same file and **must not** be merged into one YAML.

| File | Role |
|------|------|
| **`nightstalker-ci.yml`** | **Orchestrator**: triggers (`push` to `main`, `pull_request`, `workflow_dispatch`), repo-level `permissions`, `concurrency`, and the **`strategy.matrix`** that fans out hosted runners. |
| **`nightstalker-ci-runner.yml`** | **Reusable implementation** (`on.workflow_call` + `inputs`): all jobs and steps that actually run Go, BPF, npm, composite `uses: ./`, detect/prevent probes. |

**Dedup target:** repeated step blocks **inside** `nightstalker-ci-runner.yml` (e.g. `unit` vs `integration` both run checkout → gofmt → `build-agent-linux.sh` → vet → staticcheck). The matrix file stays thin.

---

### Task 1: Document supply-chain workflow as disabled

**Files:**

- Modify: [`README.md`](../../README.md)
- Modify: [`AGENTS.md`](../../AGENTS.md) (only if it references an active `supply-chain-attest.yml`)
- Optional modify: [`docs/superpowers/specs/2026-04-12-github-attestations-sbom-design.md`](../../docs/superpowers/specs/2026-04-12-github-attestations-sbom-design.md) — **only if** `docs/superpowers/` remains tracked after Task 4; otherwise skip or delete with Task 4.

- [ ] **Step 1: Replace README “Supply chain” section with disabled-state truth**

In [`README.md`](../../README.md), replace the current section that begins with `## Supply chain (artifact attestations)` through the paragraph ending with the official guide link with:

```markdown
## Supply chain (artifact attestations)

**Status:** The dedicated workflow is **disabled** in this repository. The workflow definition is kept as [`.github/workflows/supply-chain-attest.yml.disabled`](.github/workflows/supply-chain-attest.yml.disabled) so it does not execute on tag pushes or `workflow_dispatch`. **No** release attestations or SBOM uploads are produced from GitHub Actions until maintainers rename it back to `supply-chain-attest.yml` and verify `permissions` / `actions/attest` compatibility.

**Re-enable checklist (maintainers):** rename the file to `supply-chain-attest.yml`, run once via **Actions → Run workflow**, confirm **Attestations** and artifact upload behavior, then restore consumer documentation for `gh attestation verify` with your **actual** `--repo` slug.

**Limits (unchanged when re-enabled):** Public repos: artifact attestations per GitHub’s current product rules. Private repos may require **GitHub Enterprise Cloud**. **GHES** does not support GitHub-hosted artifact attestations. This repo does **not** sign OCI images.
```

- [ ] **Step 2: Grep and fix stale links to `supply-chain-attest.yml`**

Run:

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && rg "supply-chain-attest\\.yml" --glob "*.md"'
```

Expected: only hits inside this plan, inside the disabled workflow file itself, or inside `docs/superpowers/` you are about to untrack—**no** remaining `README.md` / root docs pointing at a **non-disabled** path unless intentional.

- [ ] **Step 3: Commit**

```bash
git add README.md AGENTS.md
git commit -m "docs: align README with disabled supply-chain attest workflow"
```

---

### Task 2: Optional — restore full six-runner matrix on `nightstalker-ci.yml`

**Files:**

- Modify: [`.github/workflows/nightstalker-ci.yml`](../../.github/workflows/nightstalker-ci.yml)

- [ ] **Step 1: Uncomment matrix rows**

Edit [`.github/workflows/nightstalker-ci.yml`](../../.github/workflows/nightstalker-ci.yml) so `matrix.include` lists **all six** rows (matching [`AGENTS.md`](../../AGENTS.md)):

```yaml
        include:
          - runner_label: ubuntu-latest
            use_slim_action: 'false'
          - runner_label: ubuntu-24.04
            use_slim_action: 'false'
          - runner_label: ubuntu-22.04
            use_slim_action: 'false'
          - runner_label: ubuntu-slim
            use_slim_action: 'true'
          - runner_label: ubuntu-24.04-arm
            use_slim_action: 'false'
          - runner_label: ubuntu-22.04-arm
            use_slim_action: 'false'
```

Remove or rewrite the top comment that says matrix is “temporarily ubuntu-latest only” so it matches repo policy.

- [ ] **Step 2: Validate YAML**

Run:

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && python3 scripts/assert_utf8_text.py'
```

Expected: exit code `0`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/nightstalker-ci.yml
git commit -m "ci: restore six-SKU matrix for nightstalker-ci"
```

---

### Task 3: Deduplicate Go + BPF setup in `nightstalker-ci-runner.yml` via composite action

**Files:**

- Create: [`.github/actions/nightstalker-go-bpf-ci/action.yml`](../../.github/actions/nightstalker-go-bpf-ci/action.yml)
- Modify: [`.github/workflows/nightstalker-ci-runner.yml`](../../.github/workflows/nightstalker-ci-runner.yml)

- [ ] **Step 1: Add composite action**

Create [`.github/actions/nightstalker-go-bpf-ci/action.yml`](../../.github/actions/nightstalker-go-bpf-ci/action.yml):

```yaml
name: nightstalker-go-bpf-ci
description: Shared Go toolchain, gofmt, BPF stub generation, vet, and staticcheck for CI jobs

inputs:
  workspace:
    description: Absolute workspace path (use github.workspace)
    required: true
    type: string

runs:
  using: composite
  steps:
    - uses: actions/setup-go@v6
      with:
        go-version: '1.24.x'
    - name: Go format (gofmt)
      shell: bash
      run: bash scripts/check-gofmt.sh
    - name: Prepare BPF and generated Go
      shell: bash
      run: bash scripts/build-agent-linux.sh "${{ inputs.workspace }}"
    - name: Go vet
      shell: bash
      run: go vet ./...
    - name: staticcheck
      shell: bash
      env:
        GOTOOLCHAIN: auto
      run: |
        go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
        echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"
        staticcheck ./...
```

- [ ] **Step 2: Refactor `unit` job**

In [`.github/workflows/nightstalker-ci-runner.yml`](../../.github/workflows/nightstalker-ci-runner.yml), in job `unit`, **replace** the block from `uses: actions/setup-go@v6` through the `staticcheck` step with:

```yaml
      - uses: ./.github/actions/nightstalker-go-bpf-ci
        with:
          workspace: ${{ github.workspace }}
```

Keep the leading `checkout` step unchanged. Keep `Unit tests` as its own final step.

- [ ] **Step 3: Refactor `integration` job**

Same substitution: after `checkout`, call `./.github/actions/nightstalker-go-bpf-ci` with `workspace: ${{ github.workspace }}`, then keep only:

```yaml
      - name: Integration tests (root)
        run: sudo env "PATH=$PATH" go test -tags=integration ./internal/agent/... -count=1
```

- [ ] **Step 4: Refactor detect/prevent jobs (partial)**

In **`detect-mode`**, after UTF-8 assert and **before** `uses: ./` for Nightstalker, insert the composite **once** so detect uses the same built tree as unit/integration:

```yaml
      - uses: ./.github/actions/nightstalker-go-bpf-ci
        with:
          workspace: ${{ github.workspace }}
```

**Remove** the separate `uses: actions/setup-go@v6` block that only set `go-version`, since the composite now includes `setup-go`.

In **`prevent-mode`**, repeat the same pattern after UTF-8 assert and before `uses: ./` for enforce.

**Do not** duplicate `npm` / `uses: ./` composite action testing inside this composite—`action_bundle` job stays separate.

- [ ] **Step 5: YAML sanity**

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && python3 scripts/assert_utf8_text.py'
```

Expected: `0`.

- [ ] **Step 6: Commit**

```bash
git add .github/actions/nightstalker-go-bpf-ci/action.yml .github/workflows/nightstalker-ci-runner.yml
git commit -m "ci: dedupe Go BPF prep via nightstalker-go-bpf-ci composite"
```

---

### Task 4: Stop publishing `docs/superpowers/` via Git (narrow docs ignore)

**Files:**

- Modify: [`.gitignore`](../../.gitignore)

- [ ] **Step 1: Append ignore rules**

Append to [`.gitignore`](../../.gitignore):

```gitignore
# Internal agent specs/plans — not part of the shipped action surface
/docs/superpowers/
```

If the team decision is **stricter** (“no `docs/` at all in Git”), use instead:

```gitignore
/docs/
```

and ensure **no** build or CI step requires files under `docs/` (today CI does not).

- [ ] **Step 2: Remove ignored paths from the Git index (files stay on disk)**

Run (narrow case):

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && git rm -r --cached docs/superpowers 2>/dev/null || true'
```

If you used `/docs/` ignore:

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && git rm -r --cached docs 2>/dev/null || true'
```

Expected: `git status` shows **deleted** entries for those paths under “Changes to be committed” while files remain locally until you delete them manually.

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore: stop tracking internal docs/superpowers; ignore path"
```

If this plan file lives under `docs/superpowers/plans/`, it becomes **untracked** after the commit—copy it to a non-ignored path **before** committing if you need it in Git (e.g. `.github/INTERNAL_CI_PLAN.md`—only if you explicitly want a public plan).

---

### Task 4b (optional): Stop publishing `scripts/` **in Git** — relocate, then ignore or delete old tree

**Hard constraint:** Adding **`/scripts/`** to [`.gitignore`](../../.gitignore) **without** moving the files GitHub runs **will break** [`.github/workflows/nightstalker-ci-runner.yml`](../../.github/workflows/nightstalker-ci-runner.yml), [`.github/actions/nightstalker-ci-slim/action.yml`](../../.github/actions/nightstalker-ci-slim/action.yml), [`.github/workflows/nightstalker-demo.yml`](../../.github/workflows/nightstalker-demo.yml), [`.github/workflows/supply-chain-attest.yml.disabled`](../../.github/workflows/supply-chain-attest.yml.disabled), [`.github/pull_request_template.md`](../../.github/pull_request_template.md), [`README.md`](../../README.md), and [`AGENTS.md`](../../AGENTS.md) (all reference `scripts/`).

**Already true:** The **consumer-facing** action bundle built by **`npm run build`** does **not** include `scripts/`; only checkout-based CI uses that folder.

**Files (if you execute this task):**

- Create directory: [`.github/scripts/`](../../.github/scripts/)
- Move (preserve executable bit on `.sh`): everything under [`scripts/`](../../scripts/) that CI references, at minimum:
  - `assert_utf8_text.py`, `utf8_repo_text.py`, `cursor_hook_fix_utf8.py` (if any workflow/hook references `scripts/` for UTF-8—hooks may stay pointed at `scripts/` or be updated in **`.cursor/hooks.json`** in a separate change)
  - `check-gofmt.sh`, `build-agent-linux.sh`, `docker-ubuntu-test.sh`, `docker-ubuntu-test-inner.sh`, `docker-ubuntu-test-matrix.sh`
  - `ci_nightstalker_jsonl_traffic_diff.py`
  - Any shell/python pair included by the moved scripts (`emit_nightstalker_ci_runner.py`, etc.) — **grep** from moved files for `scripts/` self-references and fix paths.
- Modify: all workflow and composite YAML under [`.github/`](../../.github/) — replace `scripts/` with `.github/scripts/` (or `${{ github.workspace }}/.github/scripts/…` where absolute).
- Modify: [`README.md`](../../README.md), [`AGENTS.md`](../../AGENTS.md), [`.github/pull_request_template.md`](../../.github/pull_request_template.md) — same path replacement for contributor commands.
- Modify: [`.gitignore`](../../.gitignore) — after moves verified green, add **`/scripts/`** and run **`git rm -r --cached scripts`** (or delete tree if nothing left).

- [ ] **Step 1: Inventory and move**

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && ls -la scripts'
```

Copy or `git mv` into `.github/scripts/`, preserving shebangs and `bash`/`python3` usage.

- [ ] **Step 2: Rewrite references**

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && rg -n "scripts/" .github README.md AGENTS.md .cursor 2>/dev/null || true'
```

Update each hit to `.github/scripts/...` (or document intentional exceptions).

- [ ] **Step 3: Fix internal script paths**

Inside moved `.sh` files, update any **`$ROOT/scripts`** or relative includes so **`build-agent-linux.sh`** still finds **`bpf/`**, **`go.mod`**, and Docker helpers (often `${GITHUB_WORKSPACE}` or repo root = `$(git rev-parse --show-toplevel)`). Run:

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && rg -n "scripts/" .github/scripts'
```

Expected: no stale references to the old folder name unless intentional.

- [ ] **Step 4: Run Docker CI from repo root**

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && MSYS_NO_PATHCONV=1 bash .github/scripts/docker-ubuntu-test.sh'
```

(Adjust command to match post-move filename.) Expected: exit `0`.

- [ ] **Step 5: Ignore removed `scripts/` and drop index**

Append to [`.gitignore`](../../.gitignore):

```gitignore
# Legacy path — CI lives under .github/scripts after migration
/scripts/
```

Then:

```bash
git rm -r --cached scripts
```

If the directory is empty on disk, `git add -A` removes it from the tree.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: move CI scripts to .github/scripts and stop tracking scripts/"
```

---

### Task 5: Harden `.gitignore` against secrets and complete BPF generated-file coverage

**Files:**

- Modify: [`.gitignore`](../../.gitignore)

- [ ] **Step 1: Add secret and local-credential globs**

Append:

```gitignore
# Secrets and local credentials (never commit)
.env.*
!.env.example
*.pem
*.p12
*.pfx
id_rsa
id_rsa.pub
id_ed25519
id_ed25519.pub
*.secret
**/credentials.json
**/*service-account*.json
.secrets/

# OS / editor noise
Thumbs.db
Desktop.ini
```

Adjust if the repo later adds a legitimate **`!.env.example`** file; if no example env exists, drop the negated line.

- [ ] **Step 2: Add missing `tracefs` bpf2go outputs**

After the existing `tracedns` lines in [`.gitignore`](../../.gitignore), add:

```gitignore
internal/bpf/tracefs/tracefs_bpfel.go
internal/bpf/tracefs/tracefs_bpfeb.go
```

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore: expand gitignore for secrets and tracefs bpf2go outputs"
```

---

### Task 6: Verification (Linux-class, matches AGENTS)

**Files:** none (commands only)

- [ ] **Step 1: Confirm Git state**

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && git status && git check-ignore -v docs/superpowers/plans/2026-04-12-ci-hygiene-supply-chain-gitignore-dedup.md || true'
```

Expected: ignored path reports a matching `.gitignore` rule after Task 4; working tree clean aside from intentional changes.

- [ ] **Step 2: Docker CI script (authoritative)**

```bash
"C:\Program Files\Git\bin\bash.exe" -lc 'cd /c/dumper_5000 && MSYS_NO_PATHCONV=1 bash scripts/docker-ubuntu-test.sh'
```

Expected: exit `0` (or document skip on Windows if Docker unavailable—then run on Linux CI only).

- [ ] **Step 3: Final commit if any fixups**

Only if Step 2 required small fixes.

---

## Self-review

**1. Spec coverage**

| Requirement | Task |
|-------------|------|
| Supply-chain disabled, docs honest | Task 1 |
| Explain / dedup `nightstalker-ci` vs runner | Intro table + Task 3 |
| `.gitignore` docs internal + secrets | Tasks 4–5 |
| `scripts/` not published in Git | Task 4b (optional; blocked until relocate) |
| BPF `tracefs` generated files not accidentally committed | Task 5 |
| Optional full matrix “ready” for hosted parity | Task 2 |

**2. Placeholder scan**

No `TBD` / `TODO` / vague “add validation” steps; commands are explicit.

**3. Type consistency**

Composite `inputs.workspace` is always passed `${{ github.workspace }}`—matches `build-agent-linux.sh` usage in existing jobs.

---

**Plan complete and saved to `docs/superpowers/plans/2026-04-12-ci-hygiene-supply-chain-gitignore-dedup.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
