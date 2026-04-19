"""CIDR-based allowlist for indicators that should bypass OTX lookup.

OTX has no useful data on RFC-reserved address space (loopback, link-local,
RFC1918, etc.) and a 404 for those would render as "unidentified" in the
report - which makes a benign local probe look suspect. The allowlist
short-circuits the API call and tags the indicator with `verdict: "clean"`,
`source: "allowlist"`, `reason: <category>` so the JSON island still records
the action for audit (per the never-silently-drop contract) but doesn't waste
budget or muddy the report.

v1 ships only loopback (127.0.0.0/8 per RFC 5735). Adding RFC1918 (10/8,
172.16/12, 192.168/16) or link-local (169.254/16, fe80::/10) is one constant
edit + one new "reason" string - no schema or renderer change needed.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

ALLOWLIST: tuple[tuple[str, str], ...] = (
    # (CIDR, reason). Order matters only for ties; loopback is the most
    # specific case we ship with v1.
    ("127.0.0.0/8", "loopback"),
)

_PARSED: tuple[tuple[ipaddress.IPv4Network, str], ...] = tuple(
    (ipaddress.ip_network(c, strict=False), r) for c, r in ALLOWLIST  # type: ignore[misc]
)


def is_allowlisted(indicator: str) -> Optional[str]:
    """Return the allowlist reason ("loopback") if `indicator` is a covered IP, else None.

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
