## Summary

A correctness audit of the agent, the action helper, and the report renderer. Nine defects, each fixed with a regression test that fails without the fix. Plus one CI cost change: the demo's duplicate defend-mode job is removed.

Every fix is independent; the commits are split so they can be reviewed (or reverted) one at a time.

## The defects

### 1. One over-long JSONL record dropped the whole report

`markdown.Parse` ran on a `bufio.Scanner` capped at 4 MiB. A record above the cap stopped `Scan()` permanently — every event after it was silently dropped, and `writeDetailedMarkdownReport` turned the returned error into a `nil` Aggregate. Result: no `.coldstep-report.md`, no mode-named digest, no job summary, no PR comment, a misleading `the agent likely never started` annotation, and under `--strict` the wrong error (`no .coldstep-events.jsonl to evaluate`).

Appending one oversized line to `.coldstep-events.jsonl` was enough to suppress the entire report — against the documented posture that *"a single bad line never aborts the report (defence-in-depth against a build step appending garbage)"*. Also reachable without malice: `MetaEvent` carries `UnresolvedDomains`, so a large allow-file of unresolvable domains can push the shutdown meta record past the cap.

Parse now reads through a `bufio.Reader`, counts an over-long record in `ParseErrors`, consumes it to the next newline, and resumes. The caller renders the partial stream instead of discarding it.

### 2. `signing-key` silently rounded uint64 values above 2^53

`AppendJSONL` canonicalizes key order by round-tripping through `map[string]any`. `json.Unmarshal` decodes every number as `float64`, so large integers were rounded — and the ed25519 signature then certified the rounded value, so verification passed on corrupted data.

```
unsigned: "timestamp_ns":1738368000123456789
signed:   "timestamp_ns":1738368000123456800
```

Fixed with `json.Decoder` + `UseNumber()`. Unsigned runs were always correct.

### 3. `::` was denied in defend mode

The IPv6 analogue of the `0.0.0.0` bypass in #364, which that commit explicitly deferred as a follow-up. It is real.

`tcp_v6_connect()` / `ip6_datagram_connect()` rewrite an all-zero `sin6_addr` to `in6addr_loopback` — but **after** `cgroup/connect6`, `cgroup/sendmsg6` and `lsm/socket_connect` have judged the destination. Those hooks saw the raw `::`, missed the `allowed_ipv6` trie (`::` is neither `::1`, nor `fe80::/10`, nor v4-mapped), and denied a connection the kernel was about to route to loopback.

`lsm/socket_sendmsg` reached the same deny by a second route: with no `msg_name` it falls back to `skc_v6_daddr`, which is all-zero on an unconnected socket. The IPv4 half of that fallback already treats `daddr == 0` as "no destination, do not judge"; the v6 half denied instead.

Adds `coldstep_ipv6_is_unspecified` and wires it into all three v6 paths (cgroup, LSM, skb backstop). Verified under WSL/root with real BPF, mirroring #364's method:

- Before: `connect(("::", port))` under defend failed with `EPERM`.
- After: `connect to [::]:38737 succeeded; peer=[::1]:38737`.
- Reverting only the cgroup call site makes the new integration test fail with `operation not permitted` — the test is not vacuous.
- Enforcement unaffected: `TestRedTeam_DefendBlocksNonAllowlistedTCP` still denies `8.8.8.8:53`; `TestRedTeam_DefendAllowsAllowlistedIP` still passes.
- The verifier accepts the full defend collection including the LSM section.

### 4. A malformed allow entry killed the agent, not `start`

`ipv4LiteralOrCIDR` range-checks neither octets nor prefix length, so `10.0.0.256`, `1.2.3.4/99` and `999.999.999.999` were classified as IP literals. `policy.Parse` rejects them — but only inside the `sudo coldstep run` child, long after `start` returned 0. Without `fail-on-error`, the job then ran to completion with no agent attached, nothing in the log saying so, and in defend mode no enforcement. `start` now runs the classified buckets through `policy.BuildPolicyEx` and fails fast.

### 5. TLS `partial` confidence was unreachable

`readTLSRing` scored confidence on the **sanitized** SNI. `SanitizeField(sni, 253)` caps below `TLSSNIMaxLen` (255), so `ScoreTLSConfidence` could never return `partial` — and an SNI on the capture/RFC boundary, the one case that cannot be proven un-truncated, was labelled `full`. Confidence is now scored on the parsed value, before sanitizing.

### 6. QUIC was scored two different ways

`readUDPRing` used `possibleQUIC := port == 443`, bypassing `IsQUICCandidate` (which also excludes loopback, and which already gates the `quic_candidate` event). Runner-local UDP/443 set `possible_quic` and bumped `Summary.QuicObserved` / `Coverage.QuicObserved` while producing no `quic_candidate` row, so the two QUIC numbers in the digest disagreed — exactly what centralizing the predicate is meant to prevent.

### 7. `truncate()` discarded everything after the first invalid UTF-8 byte

The loop re-validated the **whole prefix** each step (`!utf8.ValidString(s[:end])`), so one bad byte anywhere walked `end` back to it. A 209-byte body with a bad byte at index 7 truncated to 7 bytes of content, at `O(max^2)` byte scans on a 65000-byte PR comment. Only the trailing rune matters; it now decodes backwards at most `UTFMax-1` times.

### 8. `..`-prefixed filenames rejected as traversal

`resolvePathUnderWorkspace` used `HasPrefix(rel, "..")`, which also matches a legitimate in-workspace `..allow.txt`. Only a `..` path *element* escapes; the check now matches `safepath.hasPrefix`.

### 9. `ResolveOwners` spun on an expired parent context

The retry loop broke only on `context.Canceled`. A parent whose own deadline expired surfaces as `DeadlineExceeded`, so the worker burned every remaining attempt on a dead context. Now gates on `gctx.Err()` alone, matching the `CompileDomainAllowlist` worker.

## CI: demo defend-mode job removed

The demo's `defend-mode` job duplicated the egress-block smoke that `coldstep-ci-runner.yml` already runs as a merge gate, and cost ~45 min of Actions minutes per `workflow_dispatch` (BPF verifier load dominates; `run_defend` defaulted to `true`). It also could not publish its own evidence — defend blocks the artifact uploader's egress, which is why the demo's defend digest is hand-authored.

The job and its `run_defend` input are removed. `detect-mode` is unchanged, as is the defend-mode gate in `coldstep-ci-runner.yml`. Nothing outside the workflow file referenced the job.

## Validation

Run on Linux (WSL, kernel 6.6, root for BPF):

- `scripts/run-bpf-c-unit-tests.sh` — host C tests incl. the new `coldstep_ipv6_is_unspecified` cases
- `scripts/check-gofmt.sh`, `scripts/check-encoding.sh`
- `go vet ./...` and `go vet -tags=integration ./...`
- `staticcheck ./...`
- `go test ./... -count=1`
- `go generate ./internal/bpf/defend/...` + real-verifier load of the full defend collection (`wantLSM=true`)
- `go test -tags=integration` for `TestRedTeam_DefendAllowsUnspecifiedIPv6`, `TestRedTeam_DefendBlocksNonAllowlistedTCP`, `TestRedTeam_DefendAllowsAllowlistedIP`

All green. Each fix was also confirmed to fail before the change.

## Notes for the reviewer

- No public inputs, no `action.yml` changes, no schema changes — nothing needs a docs update.
- Generated BPF stubs (`internal/bpf/**/*_bpfel.go`) are regenerated by CI and stay gitignored; none are committed.
- `.gitattributes` pins `*.bpf.c` to LF but not plain `*.c`, so `bpf/host_test/*.c` checks out CRLF on Windows and any edit there flips the whole file in the diff. Not changed here — worth a one-line follow-up (`*.c text eol=lf`).

Co-Authored-By: Claude Opus 5 (1M context) &lt;noreply@anthropic.com&gt;

🤖 Generated with [Claude Code](https://claude.com/claude-code)
