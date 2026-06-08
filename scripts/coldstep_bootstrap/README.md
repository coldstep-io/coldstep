# Coldstep starter allowlist packs (reference)

These UTF-8 text files are **reference starter lists**. The `bootstrap-allowlist`
input that merged them automatically was **removed** in the allowlist
consolidation — there is now one model: put everything in `allow` / `allow-file`.

To use a pack, **copy the lines you want into your own `allow-file`** (in your
repo / workspace). Same line / `#` comment rules as any `allow-file`.

## Files

| File | Copy entries into |
| ---- | ----------------- |
| **`allowlist-domains-v1.txt`** | your `allow` / `allow-file` (domains) |
| **`allowlist-ips-v1.txt`** | your `allow` / `allow-file` (IPv4 / CIDR) |

## Versioning

**v1** packs are intentionally minimal (may be comment-only). Future tags may add curated rows under semver-style review; see **CHANGELOG** and **VALIDATION.md**.

Trust model: treat bootstrap content like **vendor policy** — review upgrades when bumping the **`coldstep-io/coldstep`** pin.
