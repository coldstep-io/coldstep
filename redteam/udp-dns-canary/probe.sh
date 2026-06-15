#!/usr/bin/env bash
# Red-team case: UDP / DNS canary.
#
# Sends a DNS query to a public resolver (8.8.8.8) so coldstep records a UDP
# egress / DNS event. Best-effort: the query may be blocked or time out in
# restricted environments, which is fine — the egress attempt is the signal.
set -euo pipefail

echo "--- UDP/DNS CANARY ---"
# Trigger the DNS canary (8.8.8.8).
dig @8.8.8.8 google.com +short >/dev/null || true
