## Summary

- Publish `coldstep-report-linux-amd64` as a GitHub Release asset alongside the existing `coldstep-linux-amd64`, with matching build provenance + SBOM attestations.
- Extend `supply-chain-attest.yml`: the `coldstep-report` Go binary (already built by `scripts/build-agent-linux.sh`) is now copied, attested, uploaded to the tag's Release, and included in the `supply-chain-artifacts-*` workflow artifact.
- Update `coldstep-demo.yml` (`detect-mode` job) with a `build-model` + `render-html` + `actions/upload-artifact` block that demos the consumer pattern: download `coldstep-report-linux-amd64` from the matching Release, then ship the rendered HTML as a clickable artifact. The new steps fail-soft (`continue-on-error`) until `COLDSTEP_AGENT_VERSION` points at a tag carrying the asset.
- `RELEASE_PROCESS.md`: note the new asset in the section 5 / section 7 checklists (asset list + consumer sanity check).

Closes #219.

## Why

`coldstep-report` is the post-run report pipeline (`build-model`, `assert-integrity`, `render-summary`, `render-html`, `diff`, `rdns-enrich`, `otx-enrich`, `render-ip-summary`). Before this PR it was only consumable by repos willing to clone the source and rebuild on every run — not viable for external demos. Publishing it as a Release asset turns "telemetry happened" into "open the HTML and see exactly what your CI dialed out to" for consumers like `coldstep-io/coldstep-demo`.

## Notes on the release-upload step

- Agent binary stays the hard requirement under immutable-release rejection (existing `::error` on missing `coldstep-linux-amd64`).
- Report binary is best-effort under the same rejection path (new `::warning` if missing) — a stale report asset must not block the tag if the agent is already present.
- Both binaries are passed in a single `gh release upload --clobber` so they cannot diverge across re-runs of the workflow on the same tag.

## Test plan

- [ ] CI 22-check sweep on this PR (gofmt, encoding, vet, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode, …). `supply-chain-attest` is tag-triggered so it does not fire on PR; YAML diff is reviewed below.
- [ ] Inspect `supply-chain-attest.yml` diff: confirm `bin/coldstep-report` is built, attested (provenance + SBOM), included in the workflow artifact, and uploaded to the Release alongside `coldstep-linux-amd64`.
- [ ] After merge + next `v*` tag: confirm `gh release view <tag>` lists both `coldstep-linux-amd64` and `coldstep-report-linux-amd64`.
- [ ] After the new tag is live, bump `COLDSTEP_AGENT_VERSION` to it in the release PR and run `coldstep-demo` (`workflow_dispatch`) — verify the `coldstep-detect-html-report` artifact appears on the run.
