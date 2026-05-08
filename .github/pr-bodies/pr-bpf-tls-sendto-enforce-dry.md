## Summary

- **TLS / SNI (detect):** TCP `sendto` with an explicit IPv4 `sockaddr` after `connect` now runs the same ClientHello sniff path as connected `sendto(NULL)`, using a stack `connect4_tuple` built from `sin_addr`/`sin_port` (parity with cleartext HTTP `sendto`).
- **Defend BPF:** cgroup and LSM enforce programs share **`bpf/enforce_policy.inc`** + **`bpf/enforce_lpm_key.h`** to dedupe allowlist/deny plumbing without changing behavior.
- **Tests:** `TestRun_TLSClientHelloSendtoSockaddrJSONL` (integration, Linux, root) sends a synthetic ClientHello via `sendto(..., addr)` and asserts `type:tls` + SNI.
- **Docs:** README, digest copy, ring-read note — `tls_sni` describes `write` / `writev` / `sendto` paths.

## Merge / validation

- **`origin/main` merged into `dev`** so this branch matches current main plus this work; merge conflicts in `bpf/trace_connect.bpf.c` and `bpf/trace_tls_write.inc` resolved keeping explicit-sockaddr TLS behavior.
- **Docker (privileged Ubuntu 24.04):** `scripts/build-agent-linux.sh` + `go test -tags=integration ./internal/agent/...` — pass.

## Notes for reviewers

- Generated bpf2go artifacts under `internal/bpf/**` remain gitignored; CI regenerates via `build-agent-linux.sh`.
