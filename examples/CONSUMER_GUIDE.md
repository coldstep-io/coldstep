# Consumer guide

How to adopt **coldstep** in your own repository. This is the practical
companion to the runnable workflows in this directory; for the authoritative
input reference see the repo [`README.md`](../README.md) and
[`QUICK_START.md`](../QUICK_START.md).

## 1. Add the action

One `uses:` block is all you need. The action is a node24 JavaScript action
whose `pre` hook starts the agent before your build steps and whose `post` hook
flushes the digest at job end.

```yaml
- uses: coldstep-io/coldstep@v0.5.3
  with:
    mode: detect
    fail-on-error: true
    log-level: info
```

Always pin a published tag (`@v0.5.3` or newer), never `@main`.

## 2. Inputs you will actually use

| Input | Default | Purpose |
| :---- | :------ | :------ |
| `mode` | `detect` | `detect` = observe only. `defend` = block non-allowlisted egress (requires a non-empty allowlist). |
| `allow` | — | Allowlist entries (comma- or newline-separated): domains, wildcards, IPv4/CIDRs, and `!CIDR` ignore entries. |
| `allow-file` | — | Path to a file with the same allowlist syntax, one entry per line. |
| `detect-profile` | base | `enhanced` turns on richer event streams (process tree, TLS SNI, fs events). |
| `report` | on | Controls the rendered job-summary / `.coldstep-report.md` output. |
| `fail-on-error` | `false` | When `true`, the job fails if the agent cannot become operationally ready (not when policy denies traffic). |
| `log-level` | `info` | Agent log verbosity. |
| `no-default-ignored-nets` | `false` | When `true`, disables the implicit RFC1918 (private-range) ignores. |

## 3. Allowlist syntax

The allowlist is one unified model used by both `allow` and `allow-file`:

```text
registry.npmjs.org      # domain — resolved (A/AAAA) at startup
*.githubusercontent.com # wildcard domain
140.82.112.0/20         # IPv4 CIDR
93.184.216.34           # single IPv4
!10.0.0.0/8             # ignore entry — never blocked, never logged as denied
```

- **Domains** are resolved at startup into the effective IP allowlist. If a
  domain resolves to many IPs, all are allowed.
- **Loopback** (`127.0.0.0/8`, `::1`) and the runner's configured DNS resolvers
  always bypass, so DNS itself is never broken by defend mode.
- `defend` mode **requires** a non-empty effective allowlist; it refuses to
  start otherwise.

## 4. Roll out: detect → defend

1. **Observe.** Adopt [`detect-basic.yml`](./detect-basic.yml). Run it on
   several real builds.
2. **Read the report.** The job summary and `.coldstep-report.md` list the
   destinations your build reached. These are your allowlist candidates.
3. **Author the allowlist.** Put the legitimate destinations into `allow` (or a
   committed `allow-file`).
4. **Enforce.** Switch `mode` to `defend` (see
   [`defend-allowlist.yml`](./defend-allowlist.yml)). Watch the next few runs
   for unexpected denials and adjust the allowlist.

## 5. Reading the output

- **Job summary** — a compact report written to the GitHub step summary.
- **`.coldstep-report.md`** — the detailed Markdown report (upload it as an
  artifact if you want to keep it).
- **`.coldstep-events.jsonl`** — the append-only event stream (source of truth).
- **`.coldstep-telemetry.json`** — totals + BPF health.

## 6. Coverage and limits

coldstep is honest about what it does and does not see. Detect-mode IPv6 is not
observed; QUIC/HTTP3 inner framing, Unix sockets, and some io_uring paths are
not blocked. See [`SECURITY.md → Coverage Boundaries`](../SECURITY.md#coverage-boundaries)
for the full matrix and the threat model.
