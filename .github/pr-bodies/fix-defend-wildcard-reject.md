## Summary

- Reject wildcard allow-list entries (`*.example.com`) at action parse time when `mode: defend`. Adds `rejectDefendWildcards` in `cmd/coldstep-action/allowlist_files.go` and wires it into `runStart` after inline + file + bootstrap merge.
- Add `TestRejectDefendWildcards` covering the clean, single-wildcard, and multi-wildcard (dedup) paths.
- Update `action.yml`, `README.md`, and `QUICK_START.md` to document that wildcards are detect-only in lockstep with the input behaviour change.

## Why

Bug #4 from the post-v0.4.0 bug hunt. The BPF `allowed_domains` map uses exact-string lookup, so wildcard entries cannot match in defend mode. Previously the agent emitted a `slog.Warn` from `loadAllowedDomainsMap` and continued; if any other entry resolved, the defend-mode check passed and the agent attached — but the wildcard intent was silently ignored, so subdomains the user expected to be allowed got blocked with no error. Failing loud at action parse time matches the same posture used for rejecting `mode: enforce`.

## Test plan

- [ ] `go test ./cmd/coldstep-action/... -count=1` — including the new `TestRejectDefendWildcards` case
- [ ] `bash scripts/check-gofmt.sh`
- [ ] CI sweep on Linux (gofmt, encoding, vet, staticcheck, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode)
