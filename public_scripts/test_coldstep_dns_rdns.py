import socket
import unittest

from public_scripts.coldstep_dns.rdns import lookup_batch


def _resolver_table(table: dict, *, raise_for=None):
    """Build a fake resolver from {ip: name} (or {ip: Exception})."""
    raise_for = raise_for or {}

    def _resolve(ip: str):
        if ip in raise_for:
            raise raise_for[ip]
        return table.get(ip)

    return _resolve


class LookupBatchTests(unittest.TestCase):
    def test_resolves_known_ipv4_to_hostname(self):
        out = lookup_batch(
            ["8.8.8.8", "1.1.1.1"],
            resolver=_resolver_table({"8.8.8.8": "dns.google", "1.1.1.1": "one.one.one.one"}),
        )
        self.assertEqual(out, {"8.8.8.8": "dns.google", "1.1.1.1": "one.one.one.one"})

    def test_missing_ptr_omits_entry(self):
        # NXDOMAIN / no PTR -> no map entry (caller falls back to raw IP).
        out = lookup_batch(
            ["8.8.8.8", "203.0.113.99"],
            resolver=_resolver_table({"8.8.8.8": "dns.google"},
                                     raise_for={"203.0.113.99": socket.herror("no PTR")}),
        )
        self.assertIn("8.8.8.8", out)
        self.assertNotIn("203.0.113.99", out)

    def test_socket_timeout_is_swallowed(self):
        out = lookup_batch(
            ["1.2.3.4"],
            resolver=_resolver_table({}, raise_for={"1.2.3.4": socket.timeout("slow")}),
        )
        self.assertEqual(out, {})

    def test_unexpected_exception_is_swallowed(self):
        # Defense in depth: anything escaping the resolver must not crash the batch.
        out = lookup_batch(
            ["1.2.3.4", "8.8.8.8"],
            resolver=_resolver_table({"8.8.8.8": "dns.google"},
                                     raise_for={"1.2.3.4": RuntimeError("kapow")}),
        )
        self.assertEqual(out, {"8.8.8.8": "dns.google"})

    def test_skips_non_ipv4_inputs(self):
        # Hostnames already have a name; IPv6 isn't in v1 scope; garbage is garbage.
        called = []

        def watching_resolver(ip):
            called.append(ip)
            return "should-not-reach"

        out = lookup_batch(
            ["evil.example.com", "::1", "not-an-ip", "", "8.8.8.8"],
            resolver=watching_resolver,
        )
        self.assertEqual(called, ["8.8.8.8"])
        self.assertEqual(out, {"8.8.8.8": "should-not-reach"})

    def test_dedupes_inputs(self):
        called = []

        def watching_resolver(ip):
            called.append(ip)
            return "dns.google"

        lookup_batch(["8.8.8.8", "8.8.8.8", "8.8.8.8"], resolver=watching_resolver)
        self.assertEqual(called, ["8.8.8.8"])

    def test_wall_budget_caps_total_work(self):
        # Resolver that never returns: enforce that the batch exits within
        # roughly the wall budget instead of blocking indefinitely.
        import threading
        import time

        block = threading.Event()

        def slow_resolver(ip):
            block.wait(timeout=10)
            return None

        try:
            t0 = time.monotonic()
            out = lookup_batch(
                [f"10.0.0.{i}" for i in range(1, 6)],
                resolver=slow_resolver,
                wall_budget_s=0.3,
                max_workers=5,
            )
            elapsed = time.monotonic() - t0
        finally:
            block.set()

        self.assertEqual(out, {})
        self.assertLess(elapsed, 1.5, f"batch should respect wall budget; took {elapsed:.2f}s")

    def test_strips_trailing_dot_from_fqdn(self):
        # gethostbyaddr returns the canonical name with a trailing dot in some
        # configurations - normalize it so renderers don't display "dns.google."
        out = lookup_batch(["8.8.8.8"], resolver=_resolver_table({"8.8.8.8": "dns.google."}))
        self.assertEqual(out, {"8.8.8.8": "dns.google"})

    def test_empty_input_returns_empty_dict_without_calling_resolver(self):
        called = []

        def watching_resolver(ip):
            called.append(ip)
            return "boom"

        out = lookup_batch([], resolver=watching_resolver)
        self.assertEqual(out, {})
        self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
