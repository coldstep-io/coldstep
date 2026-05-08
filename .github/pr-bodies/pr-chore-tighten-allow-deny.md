## Summary

Small post-merge cleanup from a skeptical pass: avoid double `To4()` in allowlist merge and use the decoded IPv4 `net.IP` for DNS cache lookup on deny lines (no string round-trip).

## Also

- **`.gitignore`**: `/KNOWLEDGE_DIRECTOR.md` — optional repo-root filename for a local Obsidian Knowledge Director stub; keep it out of Git.
- **`SECURITY.md`**: defend LSM hook table uses **`lsm/socket_connect`** / **`lsm/socket_sendmsg`** to match **`SEC(...)`** in `bpf/trace_lsm_enforce.bpf.c`.

## Verification

- `go test ./internal/policy/... ./internal/agent/...` on Linux
- `scripts/check-encoding.sh`
