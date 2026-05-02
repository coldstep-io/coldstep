# Coldstep bootstrap allowlist packs (optional)

These UTF-8 text files ship **inside the composite action** (`GITHUB_ACTION_PATH/scripts/coldstep_bootstrap/`). They are merged **only** when **`bootstrap-allowlist: true`** on the **`start`** step (`action.yml`). Default is **`false`** — consumers opt in explicitly.

## Files

| File | Merged into |
| ---- | ----------- |
| **`allowlist-domains-v1.txt`** | **`allowed-domains`** (after inline + workspace files) |
| **`allowlist-ips-v1.txt`** | **`allowed-ips`** (after inline + workspace files) |

Same line / `#` comment rules as **`coldstep-action`** workspace allowlist files.

## Versioning

**v1** packs are intentionally minimal (may be comment-only). Future tags may add curated rows under semver-style review; see **CHANGELOG** and **VALIDATION.md**.

Trust model: treat bootstrap content like **vendor policy** — review upgrades when bumping the **`coldstep-io/coldstep`** pin.
