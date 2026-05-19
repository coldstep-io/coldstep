## Summary

Implements **P3-3**: inter-syscall TLS ClientHello reassembly so the `tls_sni` feature recovers SNI when a stack splits the ClientHello across two write/writev/sendto syscalls (Go `crypto/tls`, rustls, Node.js TLSWrap). Previously the single-buffer parser only saw the 5-byte record header and the event was dropped as `tls_sni_parse`.

## What changed

- **`internal/agent/agent_linux_tls_reassembler.go`** (new) — userspace per-`(pid, dst, dport)` accumulator. Each entry buffers up to 512 bytes, the first byte must be `0x16` (TLS handshake) or the entry is dropped immediately, and the store self-evicts stale keys after 30s or once a parse succeeds. A bounded LRU keeps the map under 1 024 keys.
- **`internal/agent/agent_linux_ring_read.go`** — when the existing single-buffer `ParseClientHelloSNI` fails, the new reassembler is consulted before counting `tls_sni_parse`. On success the emitted `TLSEvent` carries `tls_confidence` and `reassembled_sni`, and the JSONL `note` distinguishes reassembled records from first-buffer hits.
- **`internal/telemetry/event.go`** — `TLSEvent` gains `tls_confidence` (`full` / `partial`) and `reassembled_sni`. Both are `omitempty` so existing fixtures and downstream parsers remain compatible.
- **`internal/agent/agent_linux_tls_reassembler_test.go`** (new) — unit coverage for single-buffer success, header-then-body split, three-write split, TTL eviction (with injected clock), application-data drop, and the 512-byte cap.

## Constraints honored

- **No new `enforce`** introduced anywhere.
- **No BPF / wire format changes.** Option A (per-socket BPF hash map keyed on `(pid, fd)`) is the long-term path because it tracks real connection identity and skips userspace allocation; it requires plumbing `fd` into the wire event and additional verifier work, so this change ships the simpler Option B and notes the migration in the new file's doc comment.
- **Bounded memory**: per-entry 512 B cap, per-process 1 024-key LRU, 30 s TTL.
- **JSONL backwards compatible**: new TLSEvent fields are `omitempty`; older records replay unchanged.

## Validation

- `gofmt -l` — clean on all modified files.
- `go test ./internal/telemetry/... ./internal/report/...` — pass locally on Windows.
- Linux-only agent unit tests (`//go:build linux`) — validated by CI's `coldstep-ci-runner.yml` (`unit`, `unit-arm64`, `integration`).

## Follow-ups (out of scope)

- Option A: BPF-side per-socket hash map keyed on `(pid, fd)` that holds the partial accumulation and frees userspace from any reassembly state. Requires wire-event `fd` plumbing + verifier audit.
- Surface `reassembled_sni` / `tls_confidence` in the report model + markdown digest so reviewers can see how many SNIs needed reassembly. Tracked separately so this PR can land without digest churn.
