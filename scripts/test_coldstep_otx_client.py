import io
import json
import secrets
import unittest
import urllib.error
import urllib.request
from unittest.mock import MagicMock

from scripts.coldstep_otx.client import (
    InvalidAPIKey,
    OTXClient,
    RateLimited,
    TransportError,
)


def _resp(status: int, body):
    """Build a fake urlopen response object."""
    payload = json.dumps(body).encode("utf-8") if isinstance(body, dict) else (body or "").encode("utf-8")
    fake = MagicMock()
    fake.status = status
    fake.read = MagicMock(return_value=payload)
    fake.__enter__ = MagicMock(return_value=fake)
    fake.__exit__ = MagicMock(return_value=False)
    return fake


def _http_error(status, body=None):
    payload = json.dumps(body).encode("utf-8") if body else b""
    return urllib.error.HTTPError(
        url="http://test", code=status, msg="x", hdrs=None, fp=io.BytesIO(payload),
    )


class OTXClientRetryTests(unittest.TestCase):
    def test_returns_json_on_200(self):
        fake_open = MagicMock(return_value=_resp(200, {"pulse_info": {"count": 0}}))
        client = OTXClient(api_key="k", urlopen=fake_open, sleeper=lambda s: None)
        result = client.get_general("IPv4", "1.1.1.1")
        self.assertEqual(result, {"pulse_info": {"count": 0}})
        self.assertEqual(fake_open.call_count, 1)

    def test_404_returns_None(self):
        fake_open = MagicMock(side_effect=_http_error(404))
        client = OTXClient(api_key="k", urlopen=fake_open, sleeper=lambda s: None)
        self.assertIsNone(client.get_general("IPv4", "1.1.1.1"))
        self.assertEqual(fake_open.call_count, 1)

    def test_403_raises_invalid_api_key(self):
        fake_open = MagicMock(side_effect=_http_error(403))
        client = OTXClient(api_key="bad", urlopen=fake_open, sleeper=lambda s: None)
        with self.assertRaises(InvalidAPIKey):
            client.get_general("IPv4", "1.1.1.1")

    def test_retries_on_429_then_succeeds(self):
        side = [_http_error(429), _http_error(429), _resp(200, {"ok": True})]
        fake_open = MagicMock(side_effect=side)
        sleeps = []
        client = OTXClient(api_key="k", urlopen=fake_open, sleeper=sleeps.append, max_attempts=5)
        result = client.get_general("IPv4", "1.1.1.1")
        self.assertEqual(result, {"ok": True})
        self.assertEqual(fake_open.call_count, 3)
        self.assertEqual(sleeps, [1.0, 2.0])

    def test_retries_exhausted_raises_rate_limited(self):
        side = [_http_error(429)] * 5
        fake_open = MagicMock(side_effect=side)
        client = OTXClient(api_key="k", urlopen=fake_open, sleeper=lambda s: None, max_attempts=5)
        with self.assertRaises(RateLimited):
            client.get_general("IPv4", "1.1.1.1")
        self.assertEqual(fake_open.call_count, 5)

    def test_retries_on_5xx_then_succeeds(self):
        side = [_http_error(503), _resp(200, {"ok": True})]
        fake_open = MagicMock(side_effect=side)
        client = OTXClient(api_key="k", urlopen=fake_open, sleeper=lambda s: None, max_attempts=5)
        result = client.get_general("IPv4", "1.1.1.1")
        self.assertEqual(result, {"ok": True})
        self.assertEqual(fake_open.call_count, 2)

    def test_url_error_raises_transport_error(self):
        fake_open = MagicMock(side_effect=urllib.error.URLError("boom"))
        client = OTXClient(api_key="k", urlopen=fake_open, sleeper=lambda s: None, max_attempts=2)
        with self.assertRaises(TransportError):
            client.get_general("IPv4", "1.1.1.1")

    def test_sends_api_key_header(self):
        captured = []
        def open_capture(req, timeout=None):
            captured.append(req)
            return _resp(200, {"ok": True})
        # Per-test random fake key. The point of the test is that whatever
        # api_key OTXClient is constructed with round-trips into the
        # X-otx-api-key request header verbatim, so any opaque string works
        # and a freshly generated value keeps Snyk's hardcoded-secret rule
        # (python/HardcodedNonCryptoSecret/test, CWE-547) quiet.
        fake_api_key = "test-" + secrets.token_hex(8)
        client = OTXClient(api_key=fake_api_key, urlopen=open_capture, sleeper=lambda s: None)
        client.get_general("IPv4", "1.1.1.1")
        # urllib normalizes header name to "X-otx-api-key" capitalization on get_header().
        self.assertEqual(captured[0].get_header("X-otx-api-key"), fake_api_key)

    def test_socket_timeout_retries_then_raises_transport_error(self):
        # urlopen raises socket.timeout (== TimeoutError on 3.10+) when the read
        # timeout fires. It is NOT a URLError subclass — observed in CI run
        # 24618444911 where a raw TimeoutError escaped to the workflow step.
        fake_open = MagicMock(side_effect=TimeoutError("read timeout"))
        client = OTXClient(api_key="k", urlopen=fake_open, sleeper=lambda s: None, max_attempts=3)
        with self.assertRaises(TransportError):
            client.get_general("IPv4", "1.1.1.1")
        self.assertEqual(fake_open.call_count, 3)

    def test_socket_timeout_then_success(self):
        side = [TimeoutError("slow"), _resp(200, {"ok": True})]
        fake_open = MagicMock(side_effect=side)
        client = OTXClient(api_key="k", urlopen=fake_open, sleeper=lambda s: None, max_attempts=5)
        self.assertEqual(client.get_general("IPv4", "1.1.1.1"), {"ok": True})
        self.assertEqual(fake_open.call_count, 2)

    def test_url_format_uses_official_endpoint(self):
        captured = []
        def open_capture(req, timeout=None):
            captured.append(req)
            return _resp(200, {"ok": True})
        client = OTXClient(api_key="k", urlopen=open_capture, sleeper=lambda s: None)
        client.get_general("hostname", "evil.example.com")
        self.assertEqual(
            captured[0].full_url,
            "https://otx.alienvault.com/api/v1/indicators/hostname/evil.example.com/general",
        )


if __name__ == "__main__":
    unittest.main()
