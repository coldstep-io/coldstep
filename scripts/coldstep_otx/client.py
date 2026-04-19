"""Minimal AlienVault OTX HTTP client over urllib.request (stdlib only).

Why stdlib instead of `requests`? Avoids `pip install requests` (~3s) on every
GHA runner and keeps the client surface tiny (no SDK semantics, no on-disk
cache, no pulse CRUD - those live in the official OTXv2.py SDK we model from
but don't depend on).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
DEFAULT_READ_TIMEOUT_S = 15.0
DEFAULT_MAX_ATTEMPTS = 5
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


class OTXError(Exception):
    """Base class for all OTX client errors."""


class InvalidAPIKey(OTXError):
    """OTX returned 403; key is missing/wrong/revoked."""


class RateLimited(OTXError):
    """All retries exhausted on 429 responses."""


class BadRequest(OTXError):
    """OTX returned 4xx other than 403/404."""


class TransportError(OTXError):
    """DNS, TCP, TLS, or other URLError-class failure."""


def _sleep_for_attempt(attempt: int, cap_s: float = 16.0) -> float:
    """Backoff matching the official OTXv2 SDK's `Retry(backoff_factor=1)`.

    SDK formula: backoff_factor * (2 ** (n - 1)) where n is the prior failure
    count. We reproduce it: attempt 1 fails -> sleep 1s, then 2s, 4s, 8s, 16s
    (capped). Caller passes `attempt` starting at 1 (the failing attempt
    just observed).
    """
    return min(cap_s, float(2 ** (attempt - 1)))


class OTXClient:
    def __init__(
        self,
        *,
        api_key: str,
        urlopen: Callable[..., Any] = urllib.request.urlopen,
        sleeper: Optional[Callable[[float], None]] = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        read_timeout_s: float = DEFAULT_READ_TIMEOUT_S,
    ) -> None:
        if not api_key:
            raise InvalidAPIKey("OTXClient requires a non-empty api_key")
        self._api_key = api_key
        self._urlopen = urlopen
        if sleeper is None:
            import time as _time
            sleeper = _time.sleep
        self._sleeper = sleeper
        self._max_attempts = max_attempts
        self._read_timeout_s = read_timeout_s

    def get_general(self, indicator_type: str, indicator: str) -> Optional[dict]:
        """Fetch the `general` section for an indicator. Returns None on 404."""
        url = f"{OTX_BASE_URL}/indicators/{indicator_type}/{indicator}/general"
        req = urllib.request.Request(url, headers={"X-OTX-API-KEY": self._api_key})
        last_429: Optional[urllib.error.HTTPError] = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                with self._urlopen(req, timeout=self._read_timeout_s) as resp:
                    body = resp.read().decode("utf-8")
                    return json.loads(body) if body else {}
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return None
                if e.code == 403:
                    raise InvalidAPIKey(f"OTX rejected api key (HTTP 403) for {url}") from e
                if e.code in RETRY_STATUS:
                    if e.code == 429:
                        last_429 = e
                    if attempt < self._max_attempts:
                        self._sleeper(_sleep_for_attempt(attempt))
                        continue
                    if e.code == 429:
                        raise RateLimited(f"OTX rate-limited after {attempt} attempts") from e
                    raise TransportError(f"OTX returned HTTP {e.code} after {attempt} attempts") from e
                raise BadRequest(f"OTX returned HTTP {e.code} for {url}") from e
            except urllib.error.URLError as e:
                if attempt < self._max_attempts:
                    self._sleeper(_sleep_for_attempt(attempt))
                    continue
                raise TransportError(f"OTX transport error after {attempt} attempts: {e.reason}") from e
            except (TimeoutError, OSError) as e:
                # urllib.request.urlopen raises socket.timeout (== TimeoutError on
                # 3.10+) when the read timeout fires - it is NOT a URLError. Any
                # other low-level OSError (connection reset, etc.) gets the same
                # transient-retry treatment. Observed in CI run 24618444911.
                if attempt < self._max_attempts:
                    self._sleeper(_sleep_for_attempt(attempt))
                    continue
                raise TransportError(f"OTX transport error after {attempt} attempts: {e}") from e
        # Defensive: only reachable if max_attempts == 0 which the constructor forbids by convention.
        if last_429 is not None:
            raise RateLimited("OTX rate-limited (no successful attempt)") from last_429
        raise TransportError("OTX request failed (no attempt produced a response)")
