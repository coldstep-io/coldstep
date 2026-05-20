## Summary

Train 2 of the v0.2.9 release: bump `website/index.html` from `v0.2.8` to `v0.2.9` now that the tag is published on GitHub Releases (`coldstep-io/coldstep@v0.2.9`, `f8fa10d`) and `coldstep-linux-amd64` is uploaded by `supply-chain-attest.yml`.

Pin-only change. No agent / BPF / action / report code touched.

### Files changed

| Surface | Before | After |
| :------ | :----- | :---- |
| Quickstart YAML snippet (`<pre><code>` block) | `coldstep-io/coldstep@v0.2.8` | `coldstep-io/coldstep@v0.2.9` |
| Modes section prose (`<code>coldstep-io/coldstep@v0.2.8</code>`) | v0.2.8 | v0.2.9 |

### Why this is a separate PR

Per `RELEASE_PROCESS.md` Consumer Pin Standard, the marketing site must never advertise a tag that does not exist on GitHub Releases — visitors would copy a broken `uses:` pin. The release-train PR (#197) deliberately left `website/` at v0.2.8 so this follow-up could land *after* the tag is real on Releases.

### Not in this PR

- `src/shared.ts` `COLDSTEP_BINARY_VERSION` is still `v0.2.4`. PR #197 explicitly noted this is intentional ("action's pre-step pull_request CI would 404 otherwise") and every release train since v0.2.4 has left it alone. A separate PR can bump that constant and rebuild `dist/` if/when the team decides — kept out of this marketing-site bump so the diff stays trivially reviewable.

### Test plan

- [x] `grep -n "v0.2.9" website/index.html` → both expected occurrences (quickstart YAML block + Modes prose).
- [x] `grep -n "v0.2.8" website/index.html` → no matches.
- [ ] `coldstep-pages.yml` deploys on merge to `main` and the site shows `coldstep-io/coldstep@v0.2.9` in both spots.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
