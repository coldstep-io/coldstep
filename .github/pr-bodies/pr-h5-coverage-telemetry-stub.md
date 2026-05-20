## Summary

H5 from the v0.2.9 hardening roadmap (item 11a): structured **coverage telemetry stub** in the MetaEvent. This is the machine-readable twin of H1's "Coverage scope" table — downstream consumers (report pipeline, dashboards, audit tooling) can now reason about the per-run observation envelope without re-deriving it from individual BPF status rows.

- **New `telemetry.CoverageReport`** in `internal/telemetry/event.go` (six fields, locked JSON shape so consumers can rely on it across releases):
  - `ipv4_tcp`, `ipv4_udp_sendmsg` — always `true`; both classes are gated by always-wired cgroup hooks.
  - `ipv6`, `quic_http3` — always `false` for v0.2.9; the underlying probes are not yet implemented. Shipping the keys now (not `omitempty`) keeps the schema stable as those probes land.
  - `tls_sni_full` — `"full"` when the `tls_sni` feature gate is on **and** the `raw_tp/sys_enter` TLS sniff hook attached cleanly; `"none"` otherwise. The `"partial"` enum value is reserved for future probe variants.
  - `io_uring` — `true` when `raw_tp/io_uring_submit_sqe` attached this run.
- **MetaEvent embeds a `*CoverageReport`** under JSON key `coverage` (`omitempty`). Populated in the same block in `internal/agent/agent_linux.go` that already sets `Capabilities` / `AllowlistIPCount` / `RunnerHasIPv6`. A new `buildCoverageReport` helper in `agent_linux_digest.go` composes the report from the existing BPF status slice + feature gate state + `ioUringRd.R` attach signal.
- **No digest changes** — H1 (PR #193) already renders the human-facing Coverage scope table; H5 adds the structured form alongside, without duplicating the rendering.

## Test plan

- [x] `go test ./internal/telemetry/... ./internal/report/... ./internal/agent/...` clean on Windows
- [x] `gofmt -l .` clean
- [x] `scripts/check-encoding.sh` clean
- [x] New telemetry tests cover the JSON shape (all six keys present), the `omitempty` behaviour of the MetaEvent pointer, and the `buildCoverageReport` state machine (gate off, gate on + probe ok / degraded / missing, io_uring attached)
- [ ] All CI checks pass (Linux integration paths exercise the agent population end-to-end)
