## Summary

Implements **H2** from the v0.2.9 hardening roadmap: make ringbuffer event drops visible in the JSONL output and digest so silent event loss never occurs without a user-visible signal.

The end-to-end path from BPF per-CPU `*_ringbuf_reserve_failures` arrays → `runStats.set*RingbufReserveFailures` → `DigestInput` → digest renderer was already wired (verified during the H2 audit), and `digest.go:98` already includes `totalDetectRingbufReserveFailures(in) > 0` in the `review := …` ⚠️ trigger. This PR adds the missing JSONL surface (a shutdown `MetaEvent` carrying per-channel drop counts) and tightens the digest KPI row label so operators do not have to translate "Ringbuf drops (detect-path total)" → "we lost events".

## What changed

- **`internal/telemetry/event.go`** — new `MetaEvent.DroppedEvents map[string]uint64` (json `dropped_events,omitempty`). Keys are BPF counter names minus the `_ringbuf_reserve_failures` suffix (`connect`, `udp`, `dns`, `http`, `tls`, `exec`, `fork`, `fs`, `ktls`, `bpf_audit`, `tcp_state`, `io_uring`, `deny`). Only emitted on the shutdown `MetaEvent`; the startup `MetaEvent` leaves it nil.

- **`internal/agent/agent_linux_digest.go`** — new `buildDroppedEventsMap(stats, defendState)` helper. Returns `nil` when every counter is zero (so `omitempty` hides the field entirely); otherwise contains only the non-zero entries. Zero keys are dropped at construction time, not at marshal time, so the JSON is genuinely free of `"foo": 0` clutter.

- **`internal/agent/agent_linux.go`** — the existing shutdown defer (the first defer registered in `Run`, therefore LIFO-last) already runs after every BPF per-CPU reader defer has snapshotted into `runStats`. Right after the digest is written, the defer now emits a second `MetaEvent` line into the JSONL with `DroppedEvents` populated, so the *.coldstep-events.jsonl* file always tells the operator what was lost — even if the markdown digest path is suppressed.

- **`internal/report/digest.go`** — rename the Full KPI row from `**⚠️ Ringbuf drops (detect-path total)** | N events dropped` to `**⚠️ Dropped events (ringbuf overflow)** | N`. Matches the H2 spec label and reads cleanly alongside the other KPI rows. Still hidden when `totalDetectRingbufReserveFailures(in) == 0`.

- **`internal/report/digest_test.go`** — updated `TestBuildDetectMarkdown_RingbufDropKPIRow` to match the new label, and added `TestBuildDetectMarkdown_RingbufDropBadge_PerChannel` which walks every detect-path channel (`connect / udp / dns / http / tls / exec / fork / fs / bpf_audit`) and asserts a single non-zero reserve failure flips the headline badge to ⚠️ and renders the KPI row. This is the H2 "silent loss must be visible" guarantee.

- **`internal/agent/agent_linux_test.go`** — `TestBuildDroppedEventsMap_OmitsZerosAndNilWhenClean` (verifies nil when clean, omits zero-valued keys when partial) and `TestBuildDroppedEventsMap_NilDefendState` (detect-only runs that construct no defendState).

## Constraints honored

- No new BPF programs or maps. The shutdown-counter propagation (H2 steps 1–3 + 5–6) was the must-have; the optional real-time `meta_overflow` rate-limit hint (H2 step 4) is intentionally deferred — it requires a new ringbuf map + Go reader and is more invasive than the rest of H2 combined. Filed for a follow-up.
- The shutdown `MetaEvent` is emitted from the existing first-registered (LIFO-last) defer in `Run`, so it lands *after* every per-CPU reserve-failure counter has been snapshotted into `runStats` — no read race on the agent shutdown path.
- `dropped_events,omitempty` + nil-when-empty construction means clean runs see no schema churn in their JSONL.
- No `enforce` references introduced; agent only emits `mode: detect|defend`.

## Validation

- `bash scripts/check-gofmt.sh` — pass.
- `bash scripts/check-encoding.sh` — pass.
- `go test ./... -count=1` (WSL, with BPF stubs generated via `scripts/build-agent-linux.sh`) — pass across all packages.
- BPF compile + verifier load are validated by CI's `coldstep-ci-runner.yml` (`unit`, `unit-arm64`, `integration`, `detect-mode`, `defend-mode`).

## Follow-ups (out of scope)

- **H2 step 4 (BPF real-time overflow hint)** — add a dedicated `overflow_hint_ringbuf` so the Go reader can emit `meta_overflow` JSONL events mid-run when a percpu threshold (e.g. 1000 reserve failures) is crossed. Stretch goal explicitly carved out in the H2 task description because it requires a new BPF ringbuf map + dedicated Go reader.
- Re-label of the `Ringbuf drops` row reference in `website/index.html` lands in the post-tag website-bump PR per `RELEASE_PROCESS.md`; the marketing copy still accurately describes the surface.
