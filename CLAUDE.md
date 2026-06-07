# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo ships

**coldstep** is a GitHub Action (`coldstep-io/coldstep@<tag>`) plus a Linux eBPF agent for GitHub-hosted `ubuntu-latest` runners. It records process / network egress activity to JSONL and optional Markdown digests, and can optionally block IPv4 egress not on an allowlist.

Two runtime modes (the only `mode:` values; `enforce` is rejected at input parsing and in `CI_GUARD_MODE`):

- **`detect`** (default) — observe-only telemetry.
- **`defend`** — block non-allowlisted IPv4 egress via cgroup `connect4`/`sendmsg4` (+ BPF LSM where available). Requires a non-empty effective allowlist.

The config enum (`internal/config/config.go`) uses `ModeDefend` with the underlying string value `"defend"` — public input and internal value match. Older JSONL artifacts may show `"mode":"enforce"`; that is legacy data only, and `isBlockingDigestMode` in `internal/report/digest_aggregation.go` accepts `enforce` / `enforce+<backend>` as an alias for `defend` / `defend+<backend>` so digests replayed from pre-rename artifacts still surface the defend triage row, allowlist-trust section, and IPv6-defend logic.

## Build and dev commands

**Build the agent + action + reporter (Linux only).** `scripts/build-agent-linux.sh` is the single source of truth — it installs clang/llvm/libbpf-dev, dumps BTF to `bpf/vmlinux.h` if missing, runs `go generate` for every `internal/bpf/<probe>` package, and `go build`s three binaries into `bin/`:

```bash
bash scripts/build-agent-linux.sh "$PWD"    # bin/coldstep, bin/coldstep-action, bin/coldstep-report
```

`bpf/vmlinux.h` and `internal/bpf/**/*_bpfel.go` / `*_bpfeb.go` are **gitignored generated artifacts** — never commit them.

**Go checks (run on hosted Linux; mirror CI):**

```bash
bash scripts/check-gofmt.sh           # fail when gofmt -l prints anything
bash scripts/check-encoding.sh        # mojibake + U+FFFD scan across tracked text
go vet ./...
staticcheck ./...                     # honnef.co/go/tools/cmd/staticcheck@v0.7.0
go test ./... -count=1                # unit tests
go test -race -count=1 ./internal/agent/... -timeout 15m
sudo env "PATH=$PATH" go test -tags=integration ./internal/agent/... -count=1 -parallel 1   # needs BPF + root
```

Run a single test: `go test ./internal/agent -run TestRun_BuildsDigestInputWithUDPHTTPSectionState -count=1`.

Integration tests are gated by `//go:build integration && linux && !windows` and require root for BPF load. The `traceconnect` program enables verbose verifier logging only when `COLDSTEP_BPF_VERBOSE_VERIFY` is set — leave it unset on hosted runners.

BPF host-side C unit tests (portable helpers in `bpf/host_test/`) run as part of `build-agent-linux.sh` via `scripts/run-bpf-c-unit-tests.sh`.

**TypeScript composite bundles (`src/` → `dist/`, legacy entrypoint):**

```bash
npm ci
npm run typecheck                     # tsc --noEmit
npm run build                         # esbuild pre/main/post → dist/{pre,main,post}/index.js
```

`action.yml` declares `using: node24` with `pre: dist/pre/index.js`, `main: dist/main/index.js`, `post: dist/post/index.js`. The TS layer is **legacy** — it largely shells out to the Go `coldstep-action` binary. If you edit `src/*.ts`, commit a matching `dist/` rebuild in the same PR (CI/CodeQL verifies it).

**Local Linux oracle when not on Linux:**

```bash
bash scripts/docker-linux-test.sh     # ubuntu:24.04 container; mirrors build-agent-linux + go test ./...
bash scripts/docker-deep-debug.sh     # closer to CI: vet, staticcheck, race, govulncheck, coverage, integration
bash scripts/agent-linux-verify.sh    # wraps both, writes .coldstep-verify-last.log + COLDSTEP_AGENT_VERIFY_BUNDLE_* markers
```

Set `COLDSTEP_VERIFY_MODE=quick|deep|fast` to switch the wrapper (default `deep`). On Windows: `scripts\agent-linux-verify.cmd` or the `.ps1` / `.py` siblings.

**Kernel coupling:** BTF availability is required (kernel 5.5+, `CONFIG_DEBUG_INFO_BTF=y`). `internal/agent.probeBTF` runs at startup and fails Main with a named error if `/sys/kernel/btf/vmlinux` is missing; the synthetic `btf` row in `.coldstep-telemetry.json` carries the positive signal on the happy path. The `coldstep-kernel-matrix.yml` workflow runs weekly to catch regressions across the 5.15 / 6.1 / 6.6 / 6.8 row set. Known kernel-version sensitivities: `lsm/socket_sendpage` was removed in 6.5 and is handled by the BTF pre-check in `internal/bpf/defend/loader.go` (`LoadDefendObjectsForKernel` strips the LSM section when the hook is absent).

## Architecture

### Three Go binaries, one composite action

- **`cmd/coldstep`** (`bin/coldstep run`) — privileged BPF agent. `main` is one line: dispatch to `internal/agent.Main`. Linux-only build (`agent_linux.go`); a non-Linux stub returns an error so the binary still compiles cross-platform.
- **`cmd/coldstep-action`** (`bin/coldstep-action start|stop`) — the action's runtime helper. `start` parses inputs from flags / `INPUT_*` env, sanitizes allowlists, computes effective config, and spawns `bin/coldstep run` as a `sudo` child. `stop` flushes the digest, optionally merges it into `$GITHUB_STEP_SUMMARY`, and optionally posts a PR comment via the GitHub REST API (bounded by `httpNotifyClient`'s 60s timeout — do not remove).
- **`cmd/coldstep-report`** — post-run report pipeline invoked by demo workflows: `build-model`, `assert-integrity`, `render-summary`, `render-html`, `diff`, `render-ip-summary`. Reads `.coldstep-events.jsonl`, produces a normalized model under `internal/report/model`, then renders.

### Composite lifecycle (`action.yml`)

`runs.using: node24` with `pre` / `main` / `post` JS entrypoints in `dist/`. The TS layer (`src/pre.ts`, `src/main.ts`, `src/post.ts`, `src/start.ts`, `src/stop.ts`, `src/shared.ts`) is a thin orchestrator — `pre.ts` starts the agent, `post.ts` stops it. `main.ts` is a status-check stub when no `phase` is set; in-repo CI workflows (`uses: ./`) set `phase: start` / `phase: stop` because local refs do not fire node24 pre/post hooks. Consumer workflows pin a published tag and use a single block.

`action.yml` inputs: `mode`, `allow`, `allow-file`, `detect-profile`, `report`, `fail-on-error`, `signing-key`, `log-level`, `ignored-nets[-file]`, `bootstrap-allowlist`, `no-default-ignored-nets`, `ready-timeout-seconds`, `github-token`. Internal-only: `phase`, `release-path`, `smoke-test-egress`, `io-uring-disable`. The previous deprecated aliases (`allowed-domains*`, `allowed-hosts*`, `allowed-ips*`, `ignored-ip-nets*`, `report-job-summary`, `report-pr-summary`, `feature-gates`) were removed — use the unified inputs.

**Composite manifest rule:** GitHub only loads a repo-root composite from `action.yml` or `action.yaml`. Do not rename it.

### Agent ↔ BPF wiring (`internal/agent/`, `internal/bpf/`, `bpf/`)

Seven BPF probe packages under `internal/bpf/`, each compiled by `go generate`:

| Package | Compiler driver | Why |
| :------ | :------------- | :-- |
| `traceexec`, `tracefork` | direct `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 …` | No syscall-NR dispatch in the C source. |
| `traceconnect`, `tracedns`, `tracefs`, `tracebpfaudit`, `defend` | indirect `//go:generate go run ../bpfgen/main.go` | C sources branch on syscall numbers per arch (`#if defined(bpf_target_arm64)` vs `bpf_target_x86`) so bpf2go must be invoked with `-D__TARGET_ARCH_<runtime.GOARCH>`; the wrapper builds the flags string. `defend` only needs this because its LSM section pulls in `trace_connect_obs.h`. |

Shared C headers live in `bpf/` (notably `coldstep_pure.h`, `deny_event.h`, `defend_policy.inc`, `defend_lpm_key.h`, `trace_connect_obs.h`, `trace_*_obs.inc`, `trace_tls_write.inc`). Defend hooks come from one combined source `trace_defend_all.bpf.c`, which includes `trace_defend_cgroup.inc` (cgroup `connect4`/`sendmsg4` plus `connect6`/`sendmsg6`) and `trace_lsm_defend_lsm.inc` (BPF LSM `socket_connect`/`socket_sendmsg`), plus `trace_lsm_bpf_self_defense.inc` (BPF LSM `bpf` — sub-project B self-defense). The self-defense hook denies `BPF_PROG_GET_FD_BY_ID` / `BPF_MAP_GET_FD_BY_ID` / `BPF_OBJ_GET` that target coldstep's **own** object ids (recorded into `self_prog_ids`/`self_map_ids` by `armBpfSelfDefense` at startup) by a non-agent task, blocking a CAP_BPF attacker from grabbing a handle to detach the monitor; it is armed (`self_defense_cfg.enabled=1`) only after the id sets are populated, the agent's own tgid is exempt, and it emits a `bpf_self_defense` JSONL row + digest KPI on each denial. Like every LSM hook here it only **enforces** where `bpf` is in the kernel boot `lsm=` chain (`/sys/kernel/security/lsm`) — GH hosted runners boot without it, so the hook attaches but stays silent there; the deny integration test gates on that and skips otherwise. The cgroup section enforces **IPv4, IPv4-mapped IPv6, and native IPv6**: the `connect6`/`sendmsg6` hooks (`defend_cgroup_sock_addr_ipv6`, `bpf/trace_defend_cgroup.inc:296-339`, H14, v0.4.0) gate v4-mapped destinations against the IPv4 allowlist and native IPv6 against the `allowed_ipv6` LPM trie, with `::1` (loopback) and `fe80::/10` (link-local) always bypassing. The **LSM section remains IPv4-only** — do not promise IPv6 for the LSM path. The Go-side loader `defend.LoadDefendObjectsForKernel` strips the LSM section from the spec on kernels without CONFIG_BPF_LSM so prog_load doesn't fail.

The agent's Linux entry (`internal/agent/agent_linux.go`) loads each program in a fixed order, captures BPF status into `telemetry.BPFStatus` rows used by the digest, and drains ringbufs through `agent_linux_ring_read.go`. Feature gates `proc_tree`, `tls_sni`, `fs_events` (parsed in `internal/config/featuregates.go`) toggle optional event streams; `COLDSTEP_DETECT_PROFILE=enhanced` flips defaults on if a key is unset. Set the same profile env on the post-run `coldstep-report build-model` step so integrity scoring matches.

**QUIC / HTTP3 visibility note (P2-2).** QUIC payloads are encrypted at the transport layer and cannot be inspected by the BPF probes, so coldstep treats UDP/443 egress to non-loopback IPv4 as a *likely* QUIC/HTTP3 flow and emits a synthetic `quic_candidate` JSONL line alongside the underlying `udp` event (see `IsQUICCandidate` in `internal/agent/quic_candidate.go` and the `QUIC (port-443 UDP)` KPI row in the digest). This is a userspace heuristic — no BPF/clang work involved — and surfaces the visibility gap explicitly rather than letting QUIC traffic look like silent UDP.

### Config + policy compilation

`internal/config.LoadFromEnv` reads `CI_GUARD_MODE` and `COLDSTEP_*` env (set by `coldstep-action` from action inputs):

- `CI_GUARD_MODE=enforce` is **rejected** (returns an error). `defend` maps to `ModeDefend`. Detect is default.
- `defend` mode also requires `COLDSTEP_ALLOWED_DOMAINS` to be non-empty.
- Output paths default under `$GITHUB_WORKSPACE` and are overrideable: `COLDSTEP_EVENTS_LOG`, `COLDSTEP_DETECT_LOG`, `COLDSTEP_TELEMETRY_JSON`, `COLDSTEP_AGENT_STATUS`, `COLDSTEP_CGROUP_PATH`, `COLDSTEP_SIGNING_KEY`.

`internal/policy/allowlist.go` resolves the effective IPv4 set. DNS lookups are bounded (`coldstepDomainLookupConcurrencyLimit = 32`, 25s per lookup) and warn when a single domain resolves to >10 IPv4s — warn-only, do not change effective allowlist on that path without updating the comments.

### Report model + integrity gates

`internal/report/model/` defines the on-disk JSON model that `coldstep-report build-model` produces from JSONL. `internal/report/integrity/` scores it: `RequiredTypesForDetectProfile("enhanced")` expands required event types from `{meta, exec, tcp}` to `{meta, exec, tcp, udp, http, tls, proc_fork, fs_event}`. Detect workflows in CI run `assert-integrity` as an anti-blindness gate.

### Artifacts written to `$GITHUB_WORKSPACE`

- `.coldstep-events.jsonl` — append-only event stream (source of truth).
- `.coldstep-detect.md` — Markdown shutdown digest (post-step merges into Job Summary unless `report: none`/`pr-comment`).
- `.coldstep-telemetry.json` — totals + BPF health.
- `.coldstep-ready.json` — readiness probe; `fail-on-error: true` waits for `ok:true` (clamp 60–2700s, default 1500).
- `.coldstep-agent.stderr.log`, `.coldstep-verify-last.log`, `.coldstep-deep-debug/` — local-only, gitignored.

Note GitHub freezes per-step summary files when a step ends, so the agent writes to `.coldstep-detect.md` during the job; the **stop** step merges into `$GITHUB_STEP_SUMMARY`.

## CI gates (what merges depend on)

- **`coldstep-ci.yml`** (PR / push to main / dispatch) calls reusable **`coldstep-ci-runner.yml`**, which runs: `gofmt`, encoding scan, `unit` (ubuntu-latest + ubuntu-22.04 amd64), `unit-arm64` (ubuntu-24.04-arm + ubuntu-22.04-arm), `integration` (matrix, root, BPF), `action_bundle`, `detect-mode`, `defend-mode`. Concurrency does **not** cancel in-progress runs — defend mode can sit 20+ min in the BPF verifier and a new push must not cancel it.
- **`coldstep-ci-nightly.yml`** — `go test -shuffle`, `govulncheck`, full-module race detector.
- **`coldstep-runner-compat.yml`** (weekly Mon 04:00 UTC + `workflow_dispatch`) — runs detect mode across four runner variants: `vanilla` (plain `ubuntu-latest`), `dind` (`docker:dind` service), `buildkit` (`DOCKER_BUILDKIT=1`), `service-containers` (postgres sidecar). Each variant is its own job with `continue-on-error: true`; an `aggregate` job converts `needs.*.result` into the final pass/fail so one broken variant does not cancel the others. Asserts `.coldstep-events.jsonl` is non-empty, `.coldstep-ready.json` shows `ok:true`, and surfaces (without failing) any BPF `ok=false` entries or `compat_warnings` from the agent's `CheckRunnerCompat()` startup probe (`internal/agent/compat_check_linux.go`). Shared assertion helper: `.github/workflows/scripts/runner-compat-assert.sh`.
- **`coldstep-demo.yml`**, **`coldstep-redteam-ebpf.yml`**, **`coldstep-pages.yml`**, **`supply-chain-attest.yml`** (tag `v*`, attestations + Linux agent upload to the Release).

When CI fails on BPF verifier or generated-stub drift, run `bash scripts/agent-linux-verify.sh` locally (or via Docker) — its emitted `COLDSTEP_AGENT_VERIFY_BUNDLE_*` block is the recommended fix-loop format.

## Conventions

- **Go version:** `go 1.25.10` pinned in `go.mod`; CI uses `setup-go` with `go-version-file: go.mod`. Don't bump the minor in code without updating workflows.
- **`gofmt` is required** on every tracked `.go` file in the working tree.
- **Encoding:** repo is UTF-8 / LF. `.editorconfig` requires tabs for Go, 2-space spaces for YAML/TS/JSON. `scripts/check-encoding.sh` blocks U+FFFD bytes (`EF BF BD`) and a specific mojibake sequence — common cause is shell quoting damage from PowerShell `gh pr edit --body "…"`; use `--body-file` and templates under `.github/pr-bodies/` instead.
- **No vendored guard code.** Implementation is clean-room.
- **Cross-platform builds:** every Linux-specific file uses `//go:build linux` and has a sibling stub for other GOOSes when needed (see `internal/agent/agent_stub.go`, `internal/cgroup/path_other.go`). Integration tests use `//go:build integration && linux && !windows`.
- **Test skips gate on environment, never on unbuilt features.** `t.Skip` is for runtime capability the host lacks — no root/CAP_BPF, missing `python3`/`curl`, unsupported kernel, Windows symlink privilege. A skip that says a feature "is not merged / not implemented yet" is a forbidden stub: it passes green while asserting nothing. If the feature exists, write the real assertion; if it doesn't, don't commit the test. Likewise, do not `t.Skipf` when a required generated artifact is "absent" — the package cannot compile without its generated bindings and CI regenerates them, so a missing map/program is a real regression that must `t.Fatalf`.
- **Local-only / gitignored trees:** `plans/`, `docs/`, `design/`, `knowledge/`, `skills/`, `.cursor/`, `.vscode/`, `specs/`, `AGENTS.md`, `ARCHITECTURE.md`, `KNOWLEDGE_DIRECTOR.md`. `coldstep-ci-runner.yml` actively fails CI if `AGENTS.md` is committed. **Never** `git add -f` any of these paths.
- **Docs alignment:** changes to `action.yml` inputs or workflow pins require updating `README.md`, `QUICK_START.md`, and the input descriptions in lockstep. Release pins (`MARKETPLACE_COLDSTEP_TAG`, `COLDSTEP_AGENT_VERSION`, `website/`) follow the two-train flow in `RELEASE_PROCESS.md` — repo docs + CI pins land in the release PR before `git tag`; `website/` bumps land in a **separate follow-up PR after** the tag exists on Releases.
- **PR descriptions:** prefer the templates under `.github/pr-bodies/` (`gh pr create --body-file`); see `scripts/gh-pr-body.ps1` for the Windows wrapper.
- **Optional pre-commit:** `.pre-commit-config.yaml` runs `scripts/check-encoding.sh` if the user installs pre-commit.
- **Security lint suppressions:** Two separate linters run in CI with different suppression syntax — do not mix them up:
  - `staticcheck` / `golangci-lint`: use `//nolint:staticcheck` or `//nolint:gosec` inline comments.
  - `securego/gosec` (the standalone job in `hosted-linux/gosec`): use `// #nosec GXX` comments (e.g., `// #nosec G115`). The `//nolint:gosec` form is **not** recognized by the standalone gosec job and will leave the violation unresolved.
  - When suppressing a gosec finding, always include both forms on the same line and a brief justification: `// #nosec G115 -- int32 reinterpret of BPF u32 return code; round-trip is intentional //nolint:gosec`.
