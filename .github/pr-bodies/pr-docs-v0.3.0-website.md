## Summary

Train 2 of the v0.3.0 release: bump `website/index.html` from `v0.2.9` to `v0.3.0` now that the tag is published on GitHub Releases (`coldstep-io/coldstep@v0.3.0`).

Pin-only change. No agent / BPF / action / report code touched.

### Files changed

| Surface | Before | After |
| :------ | :----- | :---- |
| Quickstart YAML snippet (`<pre><code>` block) | `coldstep-io/coldstep@v0.2.9` | `coldstep-io/coldstep@v0.3.0` |
| Modes section prose (`<code>coldstep-io/coldstep@v0.2.9</code>`) | v0.2.9 | v0.3.0 |

### Why this is a separate PR

Per `RELEASE_PROCESS.md` Consumer Pin Standard, the marketing site must never advertise a tag that does not exist on GitHub Releases — visitors would copy a broken `uses:` pin. The release-train PR deliberately left `website/` at v0.2.9 so this follow-up could land *after* the tag is real on Releases.

### Test plan

- [x] `grep -n "v0.3.0" website/index.html` → both expected occurrences (quickstart YAML block + Modes prose).
- [x] `grep -n "v0.2.9" website/index.html` → no matches.
- [ ] `coldstep-pages.yml` deploys on merge to `main` and the site shows `coldstep-io/coldstep@v0.3.0` in both spots.
