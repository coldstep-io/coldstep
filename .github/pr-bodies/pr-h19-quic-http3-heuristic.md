## Summary

Implements **H19** from the v0.4.0 roadmap: surface UDP/443 egress as a heuristic QUIC/HTTP3 signal so operators can see how much of a run fell into the encrypted-transport visibility gap without inferring it from raw UDP JSONL.

Full QUIC ClientHello parsing is structurally out of scope — it would require QUIC crypto decryption (same architectural limit as ECH). H19 instead flags the underlying `udp` event when `dport == 443`, ticks a per-run counter, and exposes both on the coverage surface that already names every other observation gap.

## What changed

- **`internal/telemetry/event.go`** — new `UDPEvent.PossibleQUIC bool` (json `possible_quic,omitempty`). Rides on the existing udp JSONL line so consumers can triage which UDP rows are likely QUIC/HTTP3 without re-deriving the predicate. Also adds `CoverageReport.QuicObserved uint64` (json `quic_observed,omitempty`) — the per-run total, surfaced on the shutdown `MetaEvent.coverage` block alongside the existing IPv4 / IPv6 / TLS-SNI / io_uring rows.

- **`internal/agent/agent_linux_ring_read.go`** — in `readUDPRing`, set `ev.PossibleQUIC = port == 443` and call `stats.addQUICObserved()` for each true case. Decoupled from the older `IsQUICCandidate` predicate (which keeps the non-loopback-IPv4 gate for the `quic_candidate` JSONL emitter) so the H19 counter mirrors exactly the per-event flag.

- **`internal/agent/agent_linux_state.go`** — new `quicObservedN uint64` field + `addQUICObserved()` / `quicObservedTotal()` helpers under the existing `runStats.mu`. Counts UDP events whose dport is 443; read once at shutdown.

- **`internal/agent/agent_linux_digest.go`** — `buildCoverageReport` gains a `quicObserved uint64` arg so the shutdown `MetaEvent.coverage.quic_observed` field is populated; the startup meta calls it with `0`. `buildDigestInput` propagates `stats.quicObservedTotal()` into the new `DigestInput.QuicObservedCount`.

- **`internal/report/digest_types.go`** — new `DigestInput.QuicObservedCount uint64` (mirrors `CoverageReport.QuicObserved`).

- **`internal/report/digest.go`** — `quicCoverageCell` now renders `⚠️ QUIC/HTTP3 (UDP 443) — N events observed (heuristic, not enforced)` when `QuicObservedCount > 0` (falling back to the older candidate cell when only `QUICCandidateCount` is populated). Technical-details fold gains a `**note: possible-quic**` line explaining that detection is heuristic and that full ClientHello parsing requires QUIC crypto decryption.

- **`SECURITY.md`** — Coverage Boundaries row for QUIC / HTTP3 flips from "UDP event only" to "heuristic observation only (UDP port 443 flagged as `possible-quic`; not enforced)" and references the new JSONL field + `MetaEvent.coverage.quic_observed` so the threat-model doc and the runtime surface speak the same language.

- **`internal/telemetry/event_test.go`** — `TestUDPEventPossibleQUIC_OmitEmpty` (false→omitted, true→`"possible_quic":true`) and `TestCoverageReportQuicObserved_OmitEmpty` (zero→omitted, non-zero→`"quic_observed":N`).

- **`internal/agent/coverage_report_linux_test.go`** — added `quic observed propagates to report (H19)` case to the existing `buildCoverageReport` table test; also asserts `QuicObserved` round-trips through every case.

- **`internal/agent/agent_linux_test.go`** — `TestRunStats_AddQUICObserved` exercises the counter, and `TestUDPEvent_PossibleQUIC_PortPredicate` pins the `dport == 443` rule against 443 / 80 / 53 / 0 / 4433 / 8443 with a JSONL omit-empty check on each.

- **`internal/report/digest_test.go`** — `TestBuildDetectMarkdown_CoverageScopeTable_QUICRowH19` locks the new cell wording and the technical-details note.

## Constraints honored

- **No new BPF programs or maps.** H19 is a pure userspace heuristic on the existing UDP ring; no clang / verifier work required.
- **No new IPv6 promises.** Heuristic fires on the IPv4 udp ring only (consistent with the rest of coldstep's IPv4-only hooks).
- **`PossibleQUIC` is `omitempty`.** Every udp JSONL line that the agent already emits stays byte-identical on `dport != 443` runs — no schema churn for clean runs.
- **`CoverageReport.QuicObserved` is `omitempty`.** A run without UDP/443 egress leaves the field absent rather than serializing `"quic_observed":0`.
- **No `enforce` references introduced.** Agent only emits `mode: detect|defend`.

## Validation

- `bash scripts/check-gofmt.sh` — pass.
- `bash scripts/check-encoding.sh` — pass.
- `go test ./internal/telemetry/... ./internal/report/...  -count=1` — pass on Windows (cross-platform packages).
- `internal/agent` Linux-only tests + BPF compile + verifier load are validated by CI's `coldstep-ci-runner.yml` (`unit`, `unit-arm64`, `integration`, `detect-mode`, `defend-mode`).

## Follow-ups (out of scope)

- **Full QUIC ClientHello parse / Initial-packet header inspection.** Requires QUIC crypto decryption (HKDF over the connection ID) which is structurally outside what an eBPF + userspace correlator can do without a full QUIC stack. Documented as an architectural limit in `SECURITY.md` and in the digest's `possible-quic` note.
- **UDP/443 destination ranking.** A `Top QUIC destinations` slice (analog of the existing `Top destinations` table) is plausible once enough operators ask for it, but H19 keeps the surface to per-event flag + coverage row to avoid prejudging the right aggregation.
