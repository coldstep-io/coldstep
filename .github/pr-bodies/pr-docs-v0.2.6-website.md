## Summary

Train 2 of the v0.2.6 release: bump `website/index.html` from `v0.2.5` to `v0.2.6` now that the tag is published on GitHub Releases (`coldstep-io/coldstep@v0.2.6`, `45e0268`) and `coldstep-linux-amd64` is uploaded by `supply-chain-attest.yml`.

Per `RELEASE_PROCESS.md`'s Consumer Pin Standard, the marketing site should never advertise a tag that does not exist on Releases — so this bump deliberately lags the repo+CI train (PR #169) by one PR.

### Bumped

| Surface | Before | After |
|:--|:--|:--|
| Quickstart YAML snippet (`<pre><code>` block) | `coldstep-io/coldstep@v0.2.5` | `coldstep-io/coldstep@v0.2.6` |
| Modes section prose (`<code>coldstep-io/coldstep@v0.2.5</code>`) | v0.2.5 | v0.2.6 |

No other website changes; this is pin-only.

### Out of scope

- `src/shared.ts` `COLDSTEP_BINARY_VERSION` is still `v0.2.4`. The v0.2.6 binary now exists on Releases, so a separate PR can bump that to `v0.2.6` and rebuild `dist/` — kept separate from the marketing-site bump so this PR stays trivially reviewable.

## Test plan

- [x] `grep -n "v0.2.5" website/index.html` → no matches.
- [x] `grep -n "v0.2.6" website/index.html` → both expected occurrences (quickstart YAML block + Modes prose).
- [ ] `coldstep-pages.yml` deploys on merge to `main` and the site shows `coldstep-io/coldstep@v0.2.6` in both spots.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
