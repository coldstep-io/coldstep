# Contributing to coldstep

Thanks for helping improve coldstep. This document is the maintainer-facing counterpart to the user-facing **[README](README.md)** and **[QUICK_START](QUICK_START.md)**.

## What to expect

- **CI is the gate:** meaningful validation (BPF generation, `go test`, integration tests, TypeScript bundle) runs on **GitHub-hosted `ubuntu-latest`** via **[`coldstep-ci.yml`](.github/workflows/coldstep-ci.yml)** and **[`coldstep-ci-runner.yml`](.github/workflows/coldstep-ci-runner.yml)**. There is no supported path to reproduce the full Linux/eBPF matrix purely on Windows or macOS dev machines.
- **Composite action runtime:** the action declares **`node24`**; workflows in this repo set **`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`** so behavior matches hosted runner defaults. Keep that in mind when copying workflow snippets.
- **Composite manifest name:** GitHub only loads a repo-root composite from **`action.yml`** or **`action.yaml`** (`uses: ./`, marketplace). Renaming it (for example to `coldstep-action.yml`) breaks **`uses: ./`** with “Can't find `action.yml`”.
- **Generated artifacts:** `bpf/vmlinux.h` and bpf2go outputs under `internal/bpf/**` are **gitignored**; CI builds them with **`scripts/build-agent-linux.sh`**. Do not commit generated BPF headers or `*_bpfel.go` / `*_bpfeb.go` stubs.

## Before you open a PR

1. **Describe the change** — behavior, risk (especially for **enforce** mode and BPF), and how you validated it (e.g. link to a fork run or `workflow_dispatch` on **`coldstep-ci`** / **`coldstep-demo`**).
2. **Go** — CI uses **`setup-go`** with **`go-version: 1.24.x`**, matching **`go.mod`**. After Linux prep, `gofmt`, `go vet ./...`, and `go test ./...` should pass (see CI for integration tags).
3. **TypeScript** — if you edit `src/main.ts` or `src/post.ts`, run `npm run typecheck` and **`npm run build`** (**`ncc`** writes **`dist/main`** and **`dist/post`**) so committed **`dist/`** stays in sync with sources.
4. **Docs** — if you change workflow pins or action inputs, update **README**, **QUICK_START**, and **`action.yml`** descriptions so they stay aligned.
5. **Pinning for consumers** — downstream workflows should use a **release tag** (for example **`coldstep-io/coldstep@v0.1.7`**), not **`@main`**, unless they intentionally track head.

## Security-sensitive areas

Privileged **`sudo`** BPF loading, cgroup enforcement, and parsing of network/process telemetry are high-impact. If your change touches those paths, call that out in the PR and read **[SECURITY.md](SECURITY.md)** for reporting unrelated vulnerabilities.

## License

By contributing, you agree your contributions are under the same terms as the project (**BSD-3-Clause** for in-repo Go/TS/YAML/etc.; eBPF sources follow the dual-license terms described in **[LICENSE.md](LICENSE.md)**). See **LICENSE.md** for the full text and dependency inventory.
