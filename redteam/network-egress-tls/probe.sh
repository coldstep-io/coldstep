#!/usr/bin/env bash
# Red-team case: network egress (TLS).
#
# Opens TLS connections to an allowlisted host so coldstep records IPv4 TLS
# egress and (best-effort) extracts the SNI. Two client paths are used because
# they fragment the ClientHello differently: curl, then openssl s_client (which
# tends to emit the ClientHello in a single write, helping the SNI sniff).
#
# The target host is passed as $1 (default: theclouddj.com) so the same script
# works for any allowlisted SNI.
set -euo pipefail

HOST="${1:-theclouddj.com}"

echo "--- NETWORK EGRESS PROBE (TLS) -> ${HOST} ---"
# TLS connect; -4 so agent records IPv4 TLS (JSONL filters non-IPv4).
for _ in 1 2 3; do
	curl -4 --http1.1 -s -I --max-time 8 "https://${HOST}" >/dev/null && break || true
	sleep 1
done
# Second probe: OpenSSL often emits ClientHello in one write (helps when curl path misses SNI sniff).
if command -v openssl >/dev/null 2>&1; then
	timeout 8 openssl s_client -4 -connect "${HOST}:443" -servername "${HOST}" </dev/null >/dev/null 2>&1 || true
fi
