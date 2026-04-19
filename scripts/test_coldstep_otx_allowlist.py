import unittest

from scripts.coldstep_otx.allowlist import is_allowlisted


class AllowlistTests(unittest.TestCase):
    def test_loopback_127_0_0_1_is_allowlisted_as_loopback(self):
        self.assertEqual(is_allowlisted("127.0.0.1"), "loopback")

    def test_loopback_127_0_0_255_is_allowlisted(self):
        self.assertEqual(is_allowlisted("127.0.0.255"), "loopback")

    def test_loopback_anywhere_in_127_slash_8_is_allowlisted(self):
        # RFC 5735 reserves the whole 127.0.0.0/8 block for loopback, not just
        # 127.0.0.x. Anything that talks to a 127.x.y.z IP is local by
        # definition and should never burn an OTX call.
        self.assertEqual(is_allowlisted("127.1.2.3"), "loopback")
        self.assertEqual(is_allowlisted("127.255.255.254"), "loopback")

    def test_non_loopback_returns_none(self):
        self.assertIsNone(is_allowlisted("8.8.8.8"))
        self.assertIsNone(is_allowlisted("1.1.1.1"))
        self.assertIsNone(is_allowlisted("128.0.0.1"))
        self.assertIsNone(is_allowlisted("126.255.255.255"))

    def test_hostname_is_not_allowlisted_by_cidr(self):
        # CIDR matching is for IPs only; "localhost" the string is a hostname,
        # so it must fall through to the OTX path (which will then 404).
        self.assertIsNone(is_allowlisted("localhost"))
        self.assertIsNone(is_allowlisted("evil.example.com"))

    def test_garbage_input_returns_none(self):
        self.assertIsNone(is_allowlisted(""))
        self.assertIsNone(is_allowlisted("not-an-ip"))
        self.assertIsNone(is_allowlisted("127.0.0"))
        self.assertIsNone(is_allowlisted("999.999.999.999"))


class ExpandedAllowlistTests(unittest.TestCase):
    def test_rfc1918_10_slash_8(self):
        self.assertEqual(is_allowlisted("10.0.0.1"), "rfc1918")
        self.assertEqual(is_allowlisted("10.255.255.254"), "rfc1918")

    def test_rfc1918_172_16_slash_12(self):
        self.assertEqual(is_allowlisted("172.16.0.1"), "rfc1918")
        self.assertEqual(is_allowlisted("172.31.255.254"), "rfc1918")
        self.assertIsNone(is_allowlisted("172.32.0.1"))  # outside /12

    def test_rfc1918_192_168_slash_16(self):
        self.assertEqual(is_allowlisted("192.168.0.1"), "rfc1918")
        self.assertEqual(is_allowlisted("192.168.255.254"), "rfc1918")

    def test_link_local_169_254(self):
        self.assertEqual(is_allowlisted("169.254.0.1"), "link-local")
        self.assertEqual(is_allowlisted("169.254.169.254"), "link-local")

    def test_loopback_still_works(self):
        self.assertEqual(is_allowlisted("127.0.0.1"), "loopback")

    def test_public_ip_falls_through(self):
        self.assertIsNone(is_allowlisted("8.8.8.8"))
        self.assertIsNone(is_allowlisted("142.251.111.136"))


if __name__ == "__main__":
    unittest.main()
