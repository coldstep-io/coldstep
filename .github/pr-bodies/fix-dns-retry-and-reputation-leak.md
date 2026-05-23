## Summary

- **Bug #7 (`internal/policy/allowlist.go`)**: distinguish parent-cancel from per-attempt timeout in the DNS retry loop. The per-attempt 25s context's `DeadlineExceeded` was indistinguishable from a parent-cancel `Canceled`, so the loop `break`ed and `maxAttempts > 1` was dead code on transient timeouts. Now: after `errors.Is(err, Canceled|DeadlineExceeded)`, check `gctx.Err()` — break only when the parent context fired; otherwise fall through to the next attempt.
- **Bug #12 (`internal/reputation/registry.go`)**: drain `resCh` in a dedicated goroutine so the caller returns immediately on ctx cancellation without holding the closer hostage to a slow enricher. Partial results are preserved via a shared mutex + snapshot pattern (keeps `TestEnrichAll_HungEnricherDoesNotBlockOthers` passing). Enricher ctx contract is now documented in the godoc.
- Add `TestCompileDomainAllowlist_PerAttemptTimeoutRetries` — resolver returns `context.DeadlineExceeded` on attempt 1 and the IP on attempt 2; asserts the second attempt's IP lands in `AllowedIPv4`.
- Add `TestEnrichAll_DoesNotBlockOnCtxIgnoringEnricher` — enricher blocks on a test-controlled channel ignoring ctx; asserts `EnrichAll` returns within 2s of the 50ms ctx deadline.

## Why

Both bugs are silent reliability failures that compound on hosted runners:

- Bug #7 caused defend-mode allowlists to silently shrink on flaky DNS, masking the recoverable case as `UnresolvedDomains`. Workflow authors saw "this domain didn't resolve" when the truth was "this domain timed out once and the retry was dead code."
- Bug #12 pinned memory (goroutines + waitgroup + buffered channel) for the lifetime of any ctx-ignoring enricher backend. The HTTP enrichers we ship today respect ctx, but the contract was undocumented and the registry itself relied on that good behaviour to avoid the leak.

## Test plan

- [ ] `go test ./internal/policy/... ./internal/reputation/... -count=1` (Linux + Windows)
- [ ] `bash scripts/check-gofmt.sh`
- [ ] `staticcheck ./internal/policy/... ./internal/reputation/...`
- [ ] CI sweep: gofmt, encoding, vet, staticcheck, unit, unit-arm64, integration, action_bundle, detect-mode, defend-mode
