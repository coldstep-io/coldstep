## Summary

Train 2 of the v0.2.7 release: bump `website/index.html` from `v0.2.6` to `v0.2.7` now that the tag is published on GitHub Releases (`coldstep-io/coldstep@v0.2.7`, `57e3761`) and `coldstep-linux-amd64` is uploaded by `supply-chain-attest.yml`.

Pin-only change. No agent / BPF / action / report code touched.

### Files changed

| Surface | Before | After |
| :------ | :----- | :---- |
| Quickstart YAML snippet (`<pre><code>` block) | `coldstep-io/coldstep@v0.2.6` | `coldstep-io/coldstep@v0.2.7` |
| Modes section prose (`<code>coldstep-io/coldstep@v0.2.6</code>`) | v0.2.6 | v0.2.7 |

### Why this is a separate PR

Per `RELEASE_PROCESS.md` Consumer Pin Standard, the marketing site must never advertise a tag that does not exist on GitHub Releases — visitors would copy a broken `uses:` pin. The release-train PR (#179) deliberately left `website/` at v0.2.6 so this follow-up could land *after* the tag is real on Releases.

### Not in this PR

- `src/shared.ts` `COLDSTEP_BINARY_VERSION` is still `v0.2.4`. The v0.2.7 binary now exists on Releases, so a separate PR can bump that to `v0.2.7` and rebuild `dist/` — kept separate from the marketing-site bump so this PR stays trivially reviewable.

### Test plan

- [x] `grep -n "v0.2.7" website/index.html` → both expected occurrences (quickstart YAML block + Modes prose).
- [x] `grep -n "v0.2.6" website/index.html` → no matches.
- [ ] `coldstep-pages.yml` deploys on merge to `main` and the site shows `coldstep-io/coldstep@v0.2.7` in both spots.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
