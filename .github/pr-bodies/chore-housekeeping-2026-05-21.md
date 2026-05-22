## Summary

Housekeeping batch picked off a local branch that lagged 75 commits behind `origin/main`; rebased onto current main, all five files reviewed against latest. None of these touch agent runtime behavior, BPF C sources, or the published composite path — this is CI hardening, lint-config tightening, and docs only.

- **`.github/workflows/coldstep-ci.yml`** — add a `dist-up-to-date` job that runs `npm ci && npm run build` on every PR and `push`, then fails with a grouped `dist/` diff when committed bundles drift from what current `src/*.ts` produces. Catches the recurring "stale dist after a src change" regression at PR time instead of post-merge.
- **`.golangci.yml`** — narrow the BPF lint exclusion from the whole `internal/bpf/` directory to the regex `internal/bpf/.*_bpf(el|eb)\.go$`, so only the bpf2go-generated stubs bypass `typecheck` / `staticcheck`. Non-generated files under `internal/bpf/` (loaders, `gen.go` directives, abi tests, the `bpfgen` tool) are now linted with the standard rule set. The redundant `internal/bpf/` typecheck override under `rules:` is removed.
- **`CLAUDE.md`** — document the two security-lint suppression syntaxes that coexist in CI: `//nolint:gosec` for `golangci-lint` / `staticcheck`, and `// #nosec GXX` for the standalone `securego/gosec` job. The standalone gosec job does **not** honor the `//nolint` form; future suppressions should put both forms plus a one-line justification on the same line to avoid silent unresolved findings.
- **`CONTRIBUTING.md`** — TypeScript-bundle paragraph now names the new `dist-up-to-date` job as the gate that enforces the `src/`/`dist/` sync invariant, so contributors know what will catch them if they forget `npm run build`.
- **`package.json`** — add a `//overrides` comment key explaining why the `undici ^6.23.1` floor exists (advisories present in 6.23.0 against `@actions/github` / `@actions/http-client`'s transitive `undici`) and the conditions under which the floor should be bumped or widened. No dependency changes, no lockfile change — the key is npm-convention metadata only.

## Why

These edits were drafted during the housekeeping pass on 2026-05-21 but didn't land in any of the merged PRs that day; rather than lose them, this PR brings them onto main as one coherent chore. The `dist-up-to-date` job is the most material item — `dist/` drift has previously slipped past review because there was no PR-time gate, only a hope that whoever touched `src/` remembered to `npm run build`. The other four are smaller follow-ons that complement that gate (lint coverage on the non-generated half of `internal/bpf/`, two docs paragraphs, and a `package.json` comment that explains a non-obvious floor pin).

## Test plan

- [ ] `dist-up-to-date` job passes (i.e. the new gate doesn't fail on its own PR — branch doesn't touch `src/` or `dist/`, so this is mainly checking that `npm ci` accepts the `//overrides` comment key in `package.json`).
- [ ] `lint` (golangci-lint) job passes with the narrowed exclusion — non-generated files under `internal/bpf/` are now in scope; verify nothing previously hidden by the broader exclusion surfaces as a new failure.
- [ ] Full 22-check CI sweep green (`gofmt`, encoding, `unit`, `unit-arm64`, `integration`, `action_bundle`, `detect-mode`, `defend-mode`, CodeQL, gosec, etc.).
- [ ] Spot-check rendered `CLAUDE.md` and `CONTRIBUTING.md` paragraphs read cleanly.
