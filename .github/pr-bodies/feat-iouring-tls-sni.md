## io_uring TLS SNI capture (P6 Phase 2.5)

Extract the TLS SNI hostname from io_uring `IORING_OP_SEND` / `IORING_OP_SENDMSG`
ClientHello submissions and surface it as a distinct `io_uring_tls` JSONL event
plus a digest KPI row. Reuses the existing Go ClientHello parser
(`telemetry.ParseClientHelloSNI`) — no in-BPF SNI walk. Enhanced profile only;
the standard-profile fast path is unchanged.

### Telemetry / report layer
- `telemetry.IOUringTLSEvent` + `EventTypeIOUringTLS`, with `Sig` for signature
  round-trip (matches sibling events).
- Digest `io_uring TLS SNI` KPI row + `DigestInput.IoUringTLSSNIs []string`,
  hidden when empty, no headline-badge change (visibility signal, not anomaly).

### BPF + agent wiring
- `io_uring_tls_event` struct + dedicated 64 KiB ringbuf (`io_uring_tls_events`),
  separate from the lean 40-byte `io_uring_events` slot.
- ClientHello-payload capture branch in `trace_io_uring_submit_sqe`, gated by
  `io_uring_peek_cfg` (enhanced profile).
- Agent (`//go:build linux`): `decodeIOUringTLSEvent`, `readIoUringTLSRing`
  (routes the captured payload through `ParseClientHelloSNI`), startup wiring,
  and a `raw_tp/io_uring_submit_sqe` BPF status row.
- IPv4-mapped IPv6 reassembly routing via `tlsReassemblyKeyForEvent` (H21).

### Bug-hunt fixes folded in (7-angle review of this branch)
- **BG-1** — `readIoUringTLSRing` burned a JSONL sequence number before the emit
  decision (and when `EventsLogPath` was empty), and updated `runStats` under
  `jsonlMu` unlike every sibling reader. Restructured to the established pattern.
- **BG-2 (correctness)** — the ClientHello peek read the io_kiocb cmd-union member
  directly. That is the payload pointer for `SEND` but the `struct user_msghdr *`
  for `SENDMSG`, so SENDMSG ClientHellos were **never** detected. SENDMSG now
  resolves `umsg->msg_iov[0].iov_base` before the peek.
- **BG-3** — `io_uring_tls_ringbuf_reserve_failures` was counted in BPF but never
  read; wired through `runStats` → `telemetry.Summary` → `DigestInput` with a
  digest row + H2 dropped-events entry.
- **BG-4 / BG-6** — discard the ringbuf slot in-kernel on a failed payload read
  instead of submitting an empty record; dropped redundant payload/comm memsets.
- **BG-7** — moved the virustotal stub warn-once guard from a package-global
  `sync.Once` to a per-enricher field so `-shuffle` cannot flake the test.

### Tests
Unit + `gofmt` + `vet` + `staticcheck` green. Source-assertion test pins the
SENDMSG iovec walk + discard-on-failure; digest test covers the new
reserve-failure row; decode/round-trip tests cover the wire layout.

### Still deferred (separate follow-ups, tracked in the plan)
- io_uring destination resolution (`fd → socket`): `Dst` stays `"unknown"` this
  phase.
- io_uring `WRITE` / `WRITEV` socket-fd resolution.
- Defend-mode enforcement on io_uring SNI.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
