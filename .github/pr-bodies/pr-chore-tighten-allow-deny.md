## Summary

Small post-merge cleanup from a skeptical pass: avoid double `To4()` in allowlist merge and use the decoded IPv4 `net.IP` for DNS cache lookup on deny lines (no string round-trip).

## Verification

- `go test ./internal/policy/... ./internal/agent/...` on Linux
- `scripts/check-encoding.sh`
