## Summary

Train 2 of the v0.4.0 release: bump `website/index.html` from `v0.3.0` to `v0.4.0` and bump `src/shared.ts` `COLDSTEP_BINARY_VERSION` from `v0.2.4` to `v0.4.0` now that the tag is published on GitHub Releases (`coldstep-io/coldstep@v0.4.0`).

Pin-only changes. No agent / BPF / action / report code touched. The TS bundle rebuild only flows through because `COLDSTEP_BINARY_VERSION` is referenced from `src/shared.ts` at runtime (download URL + cache key + Releases API lookup).

### Files changed

| Surface | Before | After |
| :------ | :----- | :---- |
| Quickstart YAML snippet (`<pre><code>` block) | `coldstep-io/coldstep@v0.3.0` | `coldstep-io/coldstep@v0.4.0` |
| Modes section prose (`<code>coldstep-io/coldstep@v0.3.0</code>`) | v0.3.0 | v0.4.0 |
| `src/shared.ts` `COLDSTEP_BINARY_VERSION` | `v0.2.4` | `v0.4.0` |
| `dist/{pre,main,post}/index.js{,.map}` | rebuilt to match `src/shared.ts` | rebuilt to match `src/shared.ts` |

### Why this is a separate PR

Per `RELEASE_PROCESS.md` Consumer Pin Standard, the marketing site must never advertise a tag that does not exist on GitHub Releases — visitors would copy a broken `uses:` pin. Similarly, bumping `COLDSTEP_BINARY_VERSION` before the v0.4.0 GitHub Release asset exists makes the action's pre-step `pull_request` CI fail with `404 fetching .../releases/tags/v0.4.0`. The release-train PR (#217) deliberately left both surfaces at the previous version so this follow-up could land *after* the tag is real on Releases.

### Test plan

- [x] `grep -n "v0.4.0" website/index.html` → both expected occurrences (quickstart YAML block + Modes prose).
- [x] `grep -n "v0.3.0" website/index.html` → no matches.
- [x] `grep -n COLDSTEP_BINARY_VERSION src/shared.ts` → `'v0.4.0'`.
- [x] `npm run typecheck` → clean (no TS errors).
- [x] `npm run build` → `dist/{pre,main,post}/index.js` regenerated; tracked diff matches the `src/shared.ts` version-string change only.
- [ ] All 22 `coldstep-ci` checks pass (this PR exercises the action's pre-step against the now-published `v0.4.0` Releases asset — the gate that the chicken-and-egg deferral was protecting against).
- [ ] `coldstep-pages.yml` deploys on merge to `main` and the site shows `coldstep-io/coldstep@v0.4.0` in both spots.
