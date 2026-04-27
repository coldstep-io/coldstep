"""Best-effort reverse-DNS (PTR) batch resolver for IPv4 indicators.

Used to label egress-flow nodes and the OTX indicator table with friendly
hostnames - e.g. `8.8.8.8` -> `dns.google`. Stdlib only (`socket.gethostbyaddr`
through a thread pool); no network deps, no API key.

Design contract:
- Best-effort: any failure (no PTR, OS-level timeout, unexpected exception)
  silently omits the entry. Callers fall back to displaying the raw IP.
- Wall-clock budget: caps total time so a slow resolver can't stall the
  reporting pipeline. Default 5s for the whole batch, 1s per call.
- IPv4-only: hostnames already have a name, IPv6 is out of v1 scope.
- Stdlib `gethostbyaddr` has no per-call timeout; we approximate by enforcing
  the wall budget at the future-aggregation layer (`as_completed(timeout=...)`).
  This means an in-flight stdlib call may still be running after we return -
  it gets garbage-collected when the daemon thread eventually unblocks.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
from typing import Callable, Iterable, Optional

DEFAULT_WALL_BUDGET_S = 5.0
DEFAULT_PER_CALL_TIMEOUT_S = 1.0
DEFAULT_MAX_WORKERS = 10

Resolver = Callable[[str], Optional[str]]


def _default_resolver(ip: str) -> Optional[str]:
    # gethostbyaddr returns (canonical_name, aliases, addresses); we want the
    # canonical name. Honour socket.setdefaulttimeout if the caller set one.
    name, _aliases, _addrs = socket.gethostbyaddr(ip)
    return name


def _is_ipv4(s: str) -> bool:
    try:
        return ipaddress.ip_address(s).version == 4
    except (ValueError, TypeError):
        return False


def _normalize(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    n = name.strip()
    if n.endswith("."):
        n = n[:-1]
    return n or None


def lookup_batch(
    indicators: Iterable[str],
    *,
    resolver: Resolver = _default_resolver,
    wall_budget_s: float = DEFAULT_WALL_BUDGET_S,
    per_call_timeout_s: float = DEFAULT_PER_CALL_TIMEOUT_S,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> dict[str, str]:
    """Resolve PTR records for every IPv4 in `indicators`. Returns {ip: hostname}.

    Non-IPv4 entries are silently dropped. Failures (no PTR, timeout, unexpected
    exception) are silently dropped. Order of `indicators` does not matter; the
    return dict has whatever subset succeeded within the wall budget.
    """
    ips: list[str] = []
    seen: set[str] = set()
    for entry in indicators:
        if not entry or entry in seen:
            continue
        if not _is_ipv4(entry):
            continue
        seen.add(entry)
        ips.append(entry)
    if not ips:
        return {}

    # Use a per-call timeout via socket.setdefaulttimeout (the stdlib resolver
    # honours it). Save and restore so we don't perturb other code in the same
    # process. Note: this only affects the *default* resolver; injected fakes
    # may not respect it (which is fine - tests pass their own behaviour).
    old_default = socket.getdefaulttimeout()
    socket.setdefaulttimeout(per_call_timeout_s)
    # Note: we deliberately do NOT use `with ThreadPoolExecutor as pool:` here.
    # The context-manager exit calls shutdown(wait=True), which would block
    # until every submitted task finished - defeating the wall budget when the
    # resolver is slow. Instead we shutdown(wait=False, cancel_futures=True);
    # the worker threads are daemon by default (CPython 3.9+) so they won't
    # prevent process exit.
    out: dict[str, str] = {}
    pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=min(max_workers, len(ips)),
        thread_name_prefix="coldstep-rdns",
    )
    try:
        futures = {pool.submit(_safe_resolve, resolver, ip): ip for ip in ips}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=wall_budget_s):
                ip = futures[fut]
                name = _normalize(fut.result())
                if name:
                    out[ip] = name
        except concurrent.futures.TimeoutError:
            # Wall budget exhausted; whatever finished is already in `out`.
            pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        socket.setdefaulttimeout(old_default)
    return out


def _safe_resolve(resolver: Resolver, ip: str) -> Optional[str]:
    try:
        return resolver(ip)
    except Exception:
        # Per the contract: every failure path is silent. Nothing the resolver
        # can throw should ever propagate to the caller.
        return None
