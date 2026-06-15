# coldstep examples

Copy-paste-ready consumer workflows for the
[`coldstep-io/coldstep`](https://github.com/coldstep-io/coldstep) GitHub Action.
All examples pin the published tag **`coldstep-io/coldstep@v0.5.3`** — pin a
release tag, never `@main`.

| File | Mode | What it shows |
| :--- | :--- | :------------ |
| [`detect-basic.yml`](./detect-basic.yml) | `detect` | Observe-only telemetry around a real `npm install express`. Nothing is blocked. |
| [`defend-allowlist.yml`](./defend-allowlist.yml) | `defend` | Block all egress except `registry.npmjs.org` + `nodejs.org`, then run `npm install express`. |
| [`CONSUMER_GUIDE.md`](./CONSUMER_GUIDE.md) | — | How to adopt coldstep in your own repo: inputs, allowlist syntax, rollout from detect → defend, and reading the report. |

## How to use

1. Copy a `.yml` file into `.github/workflows/` in your repository.
2. Keep the pinned tag (`@v0.5.3`) or bump to a newer published release.
3. Use **GitHub-hosted `ubuntu-latest`** — that is the only supported runner
   for v1 (the agent is Linux/eBPF and needs the hosted kernel's BTF).

## Detect first, then defend

Start with `detect-basic.yml`. Let it run on a few builds and read the job
summary / `.coldstep-report.md` to learn which destinations your build
legitimately reaches. Promote those destinations into the `allow` list and
switch to `defend-allowlist.yml` once the allowlist is complete. See
[`CONSUMER_GUIDE.md`](./CONSUMER_GUIDE.md) for the full rollout.

For coverage scope (what is and isn't blocked — QUIC, Unix sockets, io_uring,
detect-mode IPv6) see the repo
[`SECURITY.md → Coverage Boundaries`](../SECURITY.md#coverage-boundaries).
