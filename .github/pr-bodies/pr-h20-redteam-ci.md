## Summary

Implements **H20** (v0.4.0 security-review follow-up): integration-level red-team validation for the 12 attack paths catalogued in the review. Adds `internal/agent/redteam_test.go` (gated `//go:build integration && linux && !windows`) and a new `redteam-integration` job in `.github/workflows/coldstep-redteam-ebpf.yml` that runs `sudo go test -tags=integration -run '^TestRedTeam_'` against the agent on `ubuntu-latest`.

## What changed

- **`internal/agent/redteam_test.go`** (new) — 12 `TestRedTeam_*` integration tests, one per attack path. Each stands up the coldstep agent in-process via `Run(ctx, cfg)`, performs a triggering action, and polls `.coldstep-events.jsonl` for the expected event row (or asserts absence in pass-through cases). Shared helpers (`newRedteamHarness`, `applyDetectEnv`, `applyDefendEnv`, `startAgent`, `waitForReady`, `pollJSONLForType`, `stopAgent`) mirror the structure of the existing `TestRun_*` tests in `internal/agent/agent_integration_test.go`.

  | # | Test | Mode | Assertion |
  | - | ---- | ---- | --------- |
  | 1 | `TestRedTeam_TCPConnectNonAllowlistedLogged` | detect | `"type":"tcp"` with `"dst":"1.1.1.1"`, `"dport":443` |
  | 2 | `TestRedTeam_UDPSendtoNonAllowlistedLogged` | detect | `"type":"udp"` to `1.1.1.1:9999` via `python3` `SOCK_DGRAM` `sendto` |
  | 3 | `TestRedTeam_DNSQueryLogged` | detect | `"type":"udp"` with `"dport":53` (DNS surfaces as UDP/53 — no separate `"type":"dns"` JSONL record exists; see SECURITY.md "DNS domain allowlists") |
  | 4 | `TestRedTeam_TLSClientHelloSNICaptured` | detect (`tls_sni=1`) | `"type":"tls"` with `"sni":"example.com"` via `curl --http1.1` |
  | 5 | `TestRedTeam_ExecComm` | detect | `"type":"exec"` with absolute `"exe":"/..."` |
  | 6 | `TestRedTeam_IPv6TCPConnect_RequiresH7` | — | `t.Skip` — IPv6 (`"type":"tcp6"`) is not yet surfaced (SECURITY.md: IPv6 unsupported) |
  | 7 | `TestRedTeam_QUICHeuristic_RequiresH19` | — | `t.Skip` — UDP rows have no `possible_quic` field yet |
  | 8 | `TestRedTeam_IoUringSend_RequiresH8` | — | `t.Skip` — only `io_uring_setup_observed` counter exists; no per-SQE `io_uring_send` JSONL |
  | 9 | `TestRedTeam_DefendBlocksNonAllowlistedTCP` | defend | `"type":"deny"` row for `8.8.8.8:53/tcp` with `127.0.0.1/32` as the only allowlisted IP; classifies `EPERM`/`ECONNREFUSED`/`ENETUNREACH` as expected dial errors |
  | 10 | `TestRedTeam_DefendAllowsAllowlistedIP` | defend | Local `net.Listen("tcp", "127.0.0.1:0")` accept succeeds with `127.0.0.1/32` allowlisted; no `"type":"deny"` row for that dst/port |
  | 11 | `TestRedTeam_DefendLoopbackAllowlistedPasses` | defend | Three consecutive loopback connects pass, no `"type":"deny"` for `127.0.0.1` (loopback is *not* in `DefaultIgnoredIPv4Nets` — see `internal/policy/ignore.go`, so explicit allowlist is required) |
  | 12 | `TestRedTeam_DefendAllowlistedDomainResolvesAndPasses` | defend | `COLDSTEP_ALLOWED_DOMAINS=localhost` resolves to `127.0.0.1`, populates the LPM, loopback connect passes without a deny row |

- **`.github/workflows/coldstep-redteam-ebpf.yml`** — adds the `redteam-integration` job (`runs-on: ubuntu-latest`, `timeout-minutes: 20`). The job runs `scripts/build-agent-linux.sh` first so the BPF probe packages (`internal/bpf/<probe>/*_bpfel.go`) are regenerated, then `sudo env "PATH=$PATH" "HOME=$HOME" go test -tags=integration ./internal/agent/... -run '^TestRedTeam_' -count=1 -parallel 1 -timeout 15m -v`. The existing `audit-validation` job is left untouched.

## Constraints honored

- **CLAUDE.md**: no generated BPF artifacts touched; no `plans/` `docs/` `design/` `knowledge/` `AGENTS.md` files added; no `enforce` references introduced (only `detect` and `defend`).
- **`//go:build integration && linux && !windows`** matches the established pattern in `agent_integration_test.go`; `skipIfUnsupportedSyscallBPFKernel` is reused to keep WSL behaviour consistent with the rest of the integration suite.
- **`go vet ./...` and `go test ./internal/agent/... -count=1`** (non-integration) pass locally; integration tests themselves require root + BPF and are validated by the new CI job.
- **`-parallel 1`**: BPF programs attach to per-runner cgroups; the existing `coldstep-ci-runner.yml` integration matrix uses the same serialization for the same reason.

## Why three tests are `t.Skip`

H7 (IPv6 telemetry → `"type":"tcp6"`), H19 (UDP `possible_quic` heuristic), and H8 (per-SQE `io_uring_send` JSONL emit) are tracked separately and are not on this branch. The skipped tests are stubs ready to drop their `t.Skip` when those land — the `_RequiresH7` / `_RequiresH19` / `_RequiresH8` suffixes are intentionally explicit so a follow-up PR knows what to unskip.

## Validation

- `bash scripts/check-gofmt.sh` — pass.
- `go vet ./...` — pass.
- `go test ./internal/agent/... -count=1` (non-integration) — pass.
- Integration assertions run on `ubuntu-latest` in the new `redteam-integration` workflow job; existing `audit-validation` job (the original red-team workflow) continues to run.

## Follow-ups (out of scope)

- Drop `t.Skip` from `TestRedTeam_IPv6TCPConnect_RequiresH7` when H7 lands.
- Drop `t.Skip` from `TestRedTeam_QUICHeuristic_RequiresH19` when UDP records gain a `possible_quic` field.
- Drop `t.Skip` from `TestRedTeam_IoUringSend_RequiresH8` when io_uring SQEs are surfaced as JSONL events.
