## Summary

Implements **BG-02** (`documentation/2026-05-09-bpf-features-implementation-plan.md` Phase C, design choice **C1**): a single bounded `iov[1]` peek for TLS / HTTP fingerprint when `writev`/`pwritev`/`pwritev2` is called with `vlen >= 2`, or `sendmsg`/`sendmmsg` is called with `msg_iovlen >= 2`.

Previously only `iov[0]` was passed to the sniff helpers. The dedicated counters `tls_writev_multi_iovec_observed` and `udp_sendmsg_multi_iovec_observed` fired when fragmentation was observed, but any TLS ClientHello or HTTP request line that landed in `iov[1]` (e.g. length-prefixed framing with a header in `iov[0]`) was silently dropped from `tls_events` / `http_events`.

## What changed

- **`bpf/trace_tls_write.inc`** — in `handle_tls_obs_sys_enter` for `NR_WRITEV` / `NR_PWRITEV` / `NR_PWRITEV2`, after the existing `iov[0]` call to `try_emit_tls_clienthello`, when `dx_ul >= 2` perform one more bounded `bpf_probe_read_user` of `iov[1]` (16 bytes — constant size) and re-invoke `try_emit_tls_clienthello`. The internal TLS prefix fingerprint (`0x16 0x03 0x0? ... 0x01`) gates emission, so a non-matching `iov[1]` is a no-op.

- **`bpf/trace_udp_sendmsg.inc`** — in `handle_udp_obs_sendmsg`, after the existing destination + length extraction from `iov[0]`, when `msg_iovlen >= 2` peek `iov[1]` and feed its buffer through both `try_emit_tls_clienthello` and the cleartext HTTP request fingerprint (`http_prefix_looks_like_request` gated on `dport == 80`). Both helpers gate on their own prefix tests.

- **`bpf/trace_connect.bpf.c`** — reorder includes so `trace_udp_sendmsg.inc` comes after `trace_http_obs.inc` and `trace_tls_write.inc` (the new iov[1] sniff calls helpers defined there). `handle_udp_obs_sendmsg` is only referenced from the .bpf.c dispatcher below the includes, so reordering is safe.

- **`CHANGELOG.md`** — `[Unreleased]` entry describing the change.

## Constraints honored

- **Bounded only** — strictly capped at index 1, no `iov` walk loop.
- **Constant-size reads** — `sizeof(struct coldstep_iovec)` is a compile-time constant, keeping the verifier's scalar range tight.
- **Counters preserved** — `tls_writev_multi_iovec_observed` and `udp_sendmsg_multi_iovec_observed` still increment on `vlen > 1` / `msg_iovlen > 1` so the historical fragmentation-rate metric stays comparable; comments updated to note iov[1] is no longer dropped.
- **No Go / agent / wire changes** — emit goes through existing `tls_events` / `http_events` paths.
- **No `enforce` references** introduced.

## Validation

- `bash scripts/check-gofmt.sh` — pass.
- `bash scripts/check-encoding.sh` — pass.
- `go vet $(go list ./... | grep -v internal/bpf/)` — pass (BPF stub packages require Linux + clang + libbpf to generate `*_bpfel.go`; verified in CI).
- `go test $(go list ./... | grep -v internal/bpf/) -count=1` — pass.
- BPF compile + verifier load are validated by CI's `coldstep-ci-runner.yml` (`unit`, `unit-arm64`, `integration`, `detect-mode`, `defend-mode`).

## Follow-ups (out of scope)

- **BG-03** `sendmmsg` multi-message counter (separate PR per implementation plan Phase D).
- Synthetic `writev` / `sendmsg` 2-iov integration fixture (Phase C step 4 — fixture lives in the demo / red-team workflows; not required for the BPF change itself to merge).
