# Licensing

## SPDX

The **coldstep** source code in this repository (Go, TypeScript, Python maintenance scripts, YAML, Markdown, and other non-kernel artifacts) is licensed under **BSD-3-Clause**, unless a file header says otherwise.

```text
SPDX-License-Identifier: BSD-3-Clause
```

## BSD-3-Clause (this repository)

Copyright (c) 2026 coldstep-io and contributors.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

---

## Other licenses used in this project

The table below summarizes **third-party and co-licensed material** that appears in dependencies or in code intended to be loaded into the **Linux kernel** as eBPF. It is a human-readable overview; authoritative texts are in each upstream package or kernel tree. Versions refer to **`go.mod`** and **`package-lock.json`** at the time this file was written; run `go list -m all` and `npm ls` when auditing upgrades.

| Component | Where | License(s) |
| :-------- | :---- | :----------- |
| **eBPF programs** (`bpf/*.bpf.c`, included `*.inc`) | In-tree | **`Dual BSD/GPL`** via `char LICENSE[] SEC("license") = "Dual BSD/GPL";` — the usual Linux kernel dual license so programs can be used under **GPL-2.0-only** (kernel context) or **BSD-2-Clause** (see kernel documentation on dual-licensed modules). |
| **[`github.com/cilium/ebpf`](https://github.com/cilium/ebpf)** v0.21.0 | Go module | **MIT** |
| **[`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys)** v0.43.0 | Go module | **BSD-3-Clause** (Go Authors; same style of license as the Go toolchain ecosystem) |
| **GitHub Actions SDK** (`@actions/core`, `@actions/github`, `@actions/http-client`, `@actions/exec`, `@actions/io`) | npm / bundled `dist/` | **MIT** |
| **Octokit** (`@octokit/*`) | npm (transitive) | **MIT** |
| **`undici`**, **`tunnel`**, **`@types/node`**, **`esbuild`**, **`undici-types`** | npm | **MIT** |
| **`before-after-hook`** | npm (transitive) | **Apache-2.0** |
| **`typescript`** | npm (dev) | **Apache-2.0** |
| **`deprecation`**, **`once`**, **`universal-user-agent`**, **`wrappy`** | npm (transitive) | **ISC** |

### Notes

- **Distributed action bundle:** `npm run build` produces `dist/main` and `dist/post` with **esbuild**, which vendors the npm dependency graph above. Treat the bundle as subject to those upstream licenses in addition to this repo’s **BSD-3-Clause** for first-party code.
- **Kernel / BTF at build time:** `scripts/build-agent-linux.sh` may generate **`bpf/vmlinux.h`** from the **running kernel’s BTF**. That header is derived from kernel metadata; building or loading BPF against a given kernel does not re-license this repo’s Go/TS sources, but downstream packaging should respect **kernel COPYING** and **GPL** obligations where they apply to combined or derivative works (consult your counsel for distribution scenarios).

If you believe an entry is missing or a license changed upstream, please open an issue or pull request with a pointer to the upstream `LICENSE` file or SPDX metadata.
