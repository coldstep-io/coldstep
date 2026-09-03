## Release PR — v0.6.2

Cut under the single-train flow: the `COLDSTEP_BINARY_VERSION` bump and the `dist/` rebuild land **here, before the tag**. There is no post-tag binary bump.

Contents: the nine correctness fixes merged in #366, the version/pin bump, a `CHANGELOG` entry, and the defend-coverage doc update that #366 and #364 both missed.

## Version alignment

The invariant enforced three ways (`check_release_version_alignment.py` in `action_bundle`, the same script with `--tag` as the first step of `supply-chain-attest`, and the `internal/releasecheck` Go test):

| Pin | From | To |
|---|---|---|
| `src/shared.ts` `COLDSTEP_BINARY_VERSION` | `v0.6.1` | `v0.6.2` |
| `dist/{pre,main,post}/index.js` | `v0.6.1` | `v0.6.2` (rebuilt) |
| `scripts/check_workflow_action_pins.py` `MARKETPLACE_COLDSTEP_TAG` | `v0.6.1` | `v0.6.2` |
| `COLDSTEP_AGENT_VERSION` (`coldstep-demo`, `coldstep-redteam-ebpf`) | `v0.6.1` | `v0.6.2` |
| `coldstep-io/coldstep@` pins (README ×4, QUICK_START ×8, CONTRIBUTING ×1) | `v0.6.1` | `v0.6.2` |

The `dist/` diff is **exactly one line per bundle** — the version constant. No platform churn: esbuild emits forward-slash source paths, and `.gitattributes` pins `dist/**/*.js` + `*.map` to LF.

`website/index.html` is **deliberately not bumped here** — its pin lags until the post-tag follow-up PR (the two-train rule for `website/`), which is why `check_workflow_action_pins.py` runs with `--skip-website` in PR CI. Note the website currently pins `v0.5.2`, so the follow-up moves it two releases forward.

## Docs: the unspecified-address bypass was undocumented

#366 added the `::` bypass and #364 added `0.0.0.0` before it. Neither updated the coverage claims, which still listed only loopback and link-local — exactly the "stale `X is not blocked` claims cause doc drift" case CLAUDE.md warns about. Fixed in `action.yml`'s `mode` description, `README.md` (mode table + IP-versions row) and `SECURITY.md` (coverage matrix, H14 paragraph, defend guarantees, cgroup and LSM hook tables).

`SECURITY.md` also gains the rationale: the kernel rewrites an unspecified `connect(2)` / `sendmsg(2)` destination to loopback, but only *after* the cgroup and LSM hooks observe it — so without the bypass they deny a connection the kernel was about to route to loopback.

## What v0.6.2 ships

All nine from #366:

1. **Defend denied `::`** — the IPv6 twin of the `0.0.0.0` bypass, which #364 explicitly deferred. Verified under real BPF: `connect to [::]:38737 succeeded; peer=[::1]:38737`, and reverting only the cgroup call site makes the integration test fail with `operation not permitted`.
2. **One over-long JSONL record suppressed the whole report** — appending a single oversized line to `.coldstep-events.jsonl` was enough to produce no report, no digest, no summary, no PR comment, and the wrong `--strict` error.
3. **`signing-key` rounded integers above 2^53** — `tcp_state`'s `timestamp_ns` was written altered and the signature certified the corrupted value.
4. **A malformed `allow:` entry killed the agent, not `start`** — without `fail-on-error` the job ran to completion with no agent attached and nothing in the log saying so.
5. **TLS `partial` confidence was unreachable** — boundary-length SNIs were labelled `full`.
6. **QUIC counted two different ways** — the two QUIC numbers in the digest disagreed.
7. **PR comment bodies gutted by one invalid UTF-8 byte.**
8. **`allow-file` rejected in-workspace `..`-prefixed filenames.**
9. **`ResolveOwners` burned every retry on an expired parent context.**

Plus: `coldstep-demo`'s `defend-mode` job removed (duplicated the `coldstep-ci-runner` merge gate at ~45 min of Actions minutes per dispatch, and could not publish its own evidence because defend blocks the artifact uploader). The `coldstep-ci-runner` defend gate is unchanged.

`CHANGELOG.md` gains a `[0.6.2]` section. The 0.6.0 / 0.6.1 gap is left as-is rather than reconstructed from `git log` — inferred entries in a published changelog are worse than an honest gap.

## Validation

Green on Linux before opening:

- `scripts/check_release_version_alignment.py` → `OK COLDSTEP_BINARY_VERSION=v0.6.2 (src == dist == marketplace pin)`
- `scripts/check_workflow_action_pins.py --skip-website` → `OK MARKETPLACE_COLDSTEP_TAG=v0.6.2`
- `go test ./internal/releasecheck/`
- `npm run typecheck`, `npm run build`
- `scripts/check-gofmt.sh`, `scripts/check-encoding.sh`, `go vet ./...`, `go test ./...`

## After merge

1. Tag `v0.6.2` on the merge commit and push → `supply-chain-attest` builds and uploads `coldstep-linux-amd64` plus attestations. Its first step re-checks version alignment against the tag, so a misaligned release fails before any asset is built.
2. Separate follow-up PR bumps `website/index.html` to `v0.6.2` once the tag exists on Releases.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
