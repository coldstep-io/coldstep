#!/usr/bin/env bash
# Run every red-team probe case in order, then pause so the agent's ring
# readers can drain telemetry before coldstep is stopped.
#
# This is what the coldstep-redteam-ebpf workflow invokes for its
# "Red-team probes" step. Each case is a self-contained probe.sh; see the
# per-case README.md for what it exercises and the expected coldstep behavior.
#
# Usage:
#   bash redteam/run-all.sh [tls-host]
#
# tls-host (optional) is forwarded to the network-egress-tls case
# (default: theclouddj.com).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TLS_HOST="${1:-theclouddj.com}"

bash "${HERE}/exec-canary/probe.sh"
bash "${HERE}/udp-dns-canary/probe.sh"
bash "${HERE}/bpf-audit-probe/probe.sh"
bash "${HERE}/network-egress-tls/probe.sh" "${TLS_HOST}"
bash "${HERE}/fs-event-probe/probe.sh"

# Give ring readers time to drain telemetry before stop.
sleep 5
