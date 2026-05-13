## Summary

Adds **tracked** BPF observability gap artifacts under **`documentation/`** (repo **`/specs/`** remains gitignored for local-only drafts):

- **`documentation/2026-05-08-bpf-gaps-backlog.md`** — ranked backlog **#1–#8** (BG-xx items): `pwrite*` sniff parity, unobserved-egress triage, multi-iovec visibility, `sendmmsg` multi-message, tuple LRU hygiene, io_uring research, IPv6 epic, QUIC/TLS research.
- **`documentation/2026-05-08-bpf-gaps-wiki-memo.md`** — theme-first outline for wiki parity.

Vault memo (**`knowledge/`**, local): **`wiki/Memo - BPF observability gaps backlog 2026-05-08`** — updated separately; not part of this PR.

## Validation

- Markdown-only; **no** BPF / Go / CI workflow changes.
- Encoding: UTF-8 ASCII technical prose.

## Merge notes

Safe to squash-merge; optional follow-up: pick **BG-xx** items and **`writing-plans`** per item.
