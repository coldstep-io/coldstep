## Summary

Implements **H10** (per-domain observation counts, DNS-6e) and **H11** (summary file integrity) from the v0.3.0 hardening roadmap.

- **H10** turns the existing observed-FQDN map into an operator-actionable allowlist cross-reference: every entry compiled into the defend allowlist is rendered with its run-time contact count, and entries with zero contacts are flagged as trim candidates so allowlists shrink between runs.
- **H11** adds two tamper-evidence surfaces — a SHA-256 of `.coldstep-events.jsonl` embedded in the shutdown `MetaEvent`, and a `<!-- coldstep-digest-sha256: <hex> -->` marker appended to `.coldstep-detect.md` after the action writes it. JSONL signing remains the cryptographically strong guarantee; the new hashes are documented as hints in `SECURITY.md`.

## H10 — per-domain observation counts

- **`internal/agent/agent_linux_state.go`** — `runStats.setAllowlistCompileSnapshot` now also captures the full compiled domain list; `allowlistSnapshot` returns it alongside the existing IP count / unresolved / wildcard-risk fields. The per-FQDN counter map (`dstDomainCounts`) was already in place from P1-1 6e — this PR adds the cross-reference rather than re-deriving the data.
- **`internal/agent/agent_linux.go`** — pass `defendCompiled.Domains` into the snapshot.
- **`internal/agent/agent_linux_digest.go`** — unpack the new `domains` value from `allowlistSnapshot` into `DigestInput.AllowlistDomains`.
- **`internal/agent/agent_linux_ring_read.go`** — wire `stats.incDomainCount` on TLS SNI and HTTP Host as well as the existing TCP/UDP FQDN paths so cleartext HTTP and TLS handshakes count toward per-domain totals.
- **`internal/report/digest_types.go`** — add `DigestInput.AllowlistDomains []string`.
- **`internal/report/digest.go`** — `writeAllowlistTrust` gains a fourth render condition (`hasContactSummary`), and a new `writeAllowlistDomainContactSummary` produces a collapsible table that lists each allowlist domain with its observation count and a trim-candidate note for entries at zero. The section is gated on defend mode so it cannot surface in detect (where there is no allowlist to act on).

## H11 — summary file integrity

- **`internal/telemetry/event.go`** — add `MetaEvent.EventsFileSHA256 string \`json:"events_file_sha256,omitempty"\``. Empty on the startup meta; populated on shutdown.
- **`internal/agent/agent_linux.go`** — at shutdown, after the final flush and before appending the shutdown `MetaEvent`, compute SHA-256 of the events file via a new `sha256File` helper and embed the hex digest. Best-effort: a hash failure logs and proceeds with an empty field rather than blocking the shutdown record.
- **`cmd/coldstep-action/main.go`** — extract `digestIntegrityMarker(body)` (pure, testable) and call it from `runStop` after reading `.coldstep-detect.md`. The marker is appended both to the on-disk file and to the in-memory `body` so the same hash travels into `GITHUB_STEP_SUMMARY` and the PR comment.
- **`SECURITY.md`** — new **File integrity** section. Documents JSONL signing (`signing-key`) as the strong guarantee and the two new hashes as tamper-evidence hints, with their limits stated plainly (a step that can rewrite the JSONL can also rewrite the embedded hash — a signing key is the only cryptographic stop).

## Tests

- `TestBuildDetectMarkdown_AllowlistDomainContactSummary` covers a mixed run (two domains with contacts, one without) and pins the "1 unused entry (trim candidates)" headline plus the no-contacts row note.
- `TestBuildDetectMarkdown_AllowlistDomainContactSummary_HiddenInDetect` defends against the renderer surfacing the table outside defend mode.
- `TestDigestIntegrityMarker_RoundTrip` pins the canonical marker format and confirms the SHA matches `sha256.Sum256(body)`.
- `TestDigestIntegrityMarker_EmptyBodyYieldsNothing` defends the no-write path so missing / whitespace digests do not produce a stray comment line.

## Validation

- `bash scripts/check-gofmt.sh` — pass.
- `bash scripts/check-encoding.sh` — pass.
- `go test ./internal/report/... ./internal/telemetry/... ./cmd/coldstep-action/... -count=1` — pass.
- `internal/agent/...` Linux tests + the BPF matrix run on CI (the agent package uses build tags that require generated BPF stubs, so the Windows local environment uses the stub build only).

## Constraints honored

- No new BPF programs, maps, or wire-format changes.
- No schema bump — `telemetry.SchemaVersion` is unchanged. `EventsFileSHA256` is `omitempty`.
- No `enforce` references introduced.
- No new action inputs.
