## Summary

H1 from the v0.2.9 hardening roadmap: make the digest honest about what was and wasn't observed.

- **Headline badge text** spells out what each emoji means so operators do not mistake ✅ for "every byte of egress observed":
  - ✅ **No anomalies detected (IPv4 TCP/UDP in scope)**
  - ⚠️ **Partial observation or coverage gaps — review required**
  - 🚨 **BPF failure or canary pipeline issue**
- **Coverage scope table** replaces the one-line "Coverage this run:" with a 7-row table that names each traffic class and its observation status (IPv4 TCP, IPv4 UDP, IPv6, QUIC/HTTP3, io_uring, Unix sockets, payloads beyond iov[0]). The io_uring row reflects the actual BPF probe status — `⚠ partial` when loaded, `✗ not loaded` when absent/failed — and annotates the enhanced-profile TLS ClientHello peek.
- **`runner_has_ipv6` wiring**: new `MetaEvent.RunnerHasIPv6` + `DigestInput.RunnerHasIPv6` + `config.Config.RunnerHasIPv6` (env: `COLDSTEP_RUNNER_HAS_IPV6`). When the runner advertises IPv6 connectivity and no IPv6 hooks are loaded (today: detect mode), the verdict downgrades ✅ → ⚠️ so the headline reflects the partial envelope. The `/proc/net/if_inet6` detection itself lives in the action layer (separate concern).

The visible-line budget for the above-the-fold portion is bumped 30 → 40 — an intentional H1 trade of compactness for honesty.

## Test plan

- [x] `go test ./...` clean on Linux (WSL)
- [x] `go test -race ./internal/report/... ./internal/agent/... ./internal/telemetry/...`
- [x] `gofmt -l internal/ cmd/` clean
- [x] `go vet ./...` clean
- [x] New tests cover the three verdict labels, the io_uring row state machine, the Unix-sockets always-not-observed invariant, the QUIC candidate flip, and the RunnerHasIPv6 ✅→⚠️ downgrade
- [ ] All 22 CI checks pass
