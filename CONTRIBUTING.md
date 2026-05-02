# Contributing to coldstep

Thanks for helping improve coldstep. This document is the maintainer-facing counterpart to the user-facing **[README](README.md)** and **[QUICK_START](QUICK_START.md)**.

## What to expect

- **CI is the gate:** meaningful validation (BPF generation, `go test`, integration tests, and **`scripts`** Python guardrails) runs on **GitHub-hosted Linux** via **[`coldstep-ci.yml`](.github/workflows/coldstep-ci.yml)** and **[`coldstep-ci-runner.yml`](.github/workflows/coldstep-ci-runner.yml)**. See **[VALIDATION.md](VALIDATION.md)** for what each layer proves (detect vs defend, workflow jobs, limits). There is no supported path to reproduce the full Linux/eBPF matrix purely on Windows or macOS dev machines.
- **Composite action runtime:** **`action.yml`** is a **composite** action. **`phase: start`** / **`phase: stop`** run **`bin/coldstep-action`** (built by **`scripts/build-agent-linux.sh`** when the binary is missing). Coldstep does **not** use Node **`main`/`post`** entrypoints. Optional **`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`** at the **job** level only affects **other** JavaScript actions in the same job; it is **not** required for Coldstep itself.
- **Composite manifest name:** GitHub only loads a repo-root composite from **`action.yml`** or **`action.yaml`** (`uses: ./`, marketplace). Renaming it (for example to `coldstep-action.yml`) breaks **`uses: ./`** with “Can't find `action.yml`”.
- **Generated artifacts:** `bpf/vmlinux.h` and bpf2go outputs under `internal/bpf/**` are **gitignored**; CI builds them with **`scripts/build-agent-linux.sh`**. Do not commit generated BPF headers or `*_bpfel.go` / `*_bpfeb.go` stubs.

## Before you open a PR

1. **Describe the change** — behavior, risk (especially for **defend** (blocking) mode and BPF), and how you validated it (e.g. link to a fork run or `workflow_dispatch` on **`coldstep-ci`** / **`coldstep-demo`**).
2. **Go** — CI uses **`setup-go`** with **`go-version: 1.25.x`** (see **`.github/workflows/coldstep-ci-runner.yml`**), matching **`go.mod`**. After Linux prep, `gofmt`, `go vet ./...`, and `go test ./...` should pass (see CI for integration tags).
3. **Legacy TypeScript bundles (`src/`, `dist/`)** — the published composite path is Go-only. **`package.json`** labels the esbuild output as **legacy** (CodeQL / maintenance). If you touch **`src/main.ts`** or **`src/post.ts`**, commit **`dist/`** bundles that match those sources — PR **`coldstep-ci`** / CodeQL are the supported verification surfaces (there is no Docker or local Linux matrix you must reproduce).
4. **Allowlist ergonomics** — changing **`allowed-*-file`** / **`bootstrap-allowlist`** behavior or defaults requires updating **QUICK_START**, **`VALIDATION.md`**, and **`action.yml`** input descriptions together.
5. **Docs** — if you change workflow pins or other action inputs, update **README**, **QUICK_START**, and **`action.yml`** descriptions so they stay aligned.
6. **Pinning for consumers** — downstream workflows should use a **release tag** (for example **`coldstep-io/coldstep@v0.2.1`**), not **`@main`**, unless they intentionally track head.

## Security-sensitive areas

Privileged **`sudo`** BPF loading, cgroup egress blocking (**defend**), and parsing of network/process telemetry are high-impact. If your change touches those paths, call that out in the PR and read **[SECURITY.md](SECURITY.md)** for reporting unrelated vulnerabilities.

## License

By contributing, you agree your contributions are under the same terms as the project (**BSD-3-Clause** for in-repo Go/TS/YAML/etc.; eBPF sources follow the dual-license terms described in **[LICENSE.md](LICENSE.md)**). See **LICENSE.md** for the full text and dependency inventory.
