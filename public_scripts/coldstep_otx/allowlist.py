"""CIDR-based allowlist for indicators that should bypass OTX lookup.

OTX has no useful data on RFC-reserved address space (loopback, link-local,
RFC1918, etc.) and a 404 for those would render as "unidentified" in the
report - which makes a benign local probe look suspect. The allowlist
short-circuits the API call and tags the indicator with `verdict: "clean"`,
`source: "allowlist"`, `reason: <category>` so the JSON island still records
the action for audit (per the never-silently-drop contract) but doesn't waste
budget or muddy the report.

Schema v2.1 ships IPv4 allowlisting for loopback (127.0.0.0/8, RFC 5735),
RFC1918 private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and
IPv4 link-local (169.254.0.0/16, RFC 3927). Each range uses a stable reason
string (`loopback`, `rfc1918`, `link-local`) for downstream counters and audit.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

ALLOWLIST: tuple[tuple[str, str], ...] = (
    # (CIDR, reason). Order matters only if overlapping networks are ever added.
    ("127.0.0.0/8", "loopback"),
    ("10.0.0.0/8", "rfc1918"),
    ("172.16.0.0/12", "rfc1918"),
    ("192.168.0.0/16", "rfc1918"),
    ("169.254.0.0/16", "link-local"),
)

_PARSED: tuple[tuple[ipaddress.IPv4Network, str], ...] = tuple(
    (ipaddress.ip_network(c, strict=False), r) for c, r in ALLOWLIST  # type: ignore[misc]
)


def is_allowlisted(indicator: str) -> Optional[str]:
    """Return the allowlist reason (e.g. "loopback", "rfc1918", "link-local") if covered, else None.

    Hostnames, garbage, and IPs outside every CIDR all return None - the caller
    must treat None as "fall through to OTX". Never raises.
    """
    if not indicator:
        return None
    try:
        addr = ipaddress.ip_address(indicator)
    except (ValueError, TypeError):
        return None
    for net, reason in _PARSED:
        if addr.version == net.version and addr in net:
            return reason
    return None
