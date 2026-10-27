"""DNS checks against a mocked resolver — no network needed.

Run:  python3 -m unittest discover tests
"""

import socket
import threading
import time
import unittest
from unittest import mock

from src import dnscheck
from src.reporting import Report

ADDRINFO = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))]


class TestSystemResolve(unittest.TestCase):

    def test_returns_ips(self):
        with mock.patch("socket.getaddrinfo", return_value=ADDRINFO):
            self.assertEqual(dnscheck.system_resolve("example.com"),
                             ["93.184.215.14"])

    def test_resolution_failure_is_none(self):
        with mock.patch("socket.getaddrinfo",
                        side_effect=socket.gaierror("nodename nor servname")):
            self.assertIsNone(dnscheck.system_resolve("example.com"))

    def test_hung_resolver_times_out(self):
        # getaddrinfo ignores socket timeouts; a dead DNS must still not
        # stall the check past the requested timeout.
        release = threading.Event()

        def hang(*args, **kwargs):
            release.wait(10)
            return ADDRINFO

        with mock.patch("socket.getaddrinfo", side_effect=hang):
            start = time.monotonic()
            result = dnscheck.system_resolve("example.com", timeout=0.2)
            elapsed = time.monotonic() - start
        release.set()
        self.assertIsNone(result)
        self.assertLess(elapsed, 1.0)

    def test_does_not_touch_global_socket_timeout(self):
        before = socket.getdefaulttimeout()
        with mock.patch("socket.getaddrinfo", return_value=ADDRINFO):
            dnscheck.system_resolve("example.com", timeout=1.5)
        self.assertEqual(socket.getdefaulttimeout(), before)


class TestHijackCheck(unittest.TestCase):

    def _collect(self, resolve):
        report = Report(quiet=True)
        with mock.patch.object(dnscheck, "system_resolve", side_effect=resolve), \
                mock.patch.object(dnscheck, "query", return_value=["1.2.3.4"]), \
                mock.patch.object(dnscheck, "doh_query", return_value=["1.2.3.4"]):
            findings = dnscheck.collect(report)
        hijack = next(r for r in report.results if r.name == "DNS hijack check")
        return findings, hijack

    def test_dead_dns_skips_hijack_check(self):
        findings, hijack = self._collect(lambda name: None)
        self.assertEqual(hijack.status, "info")
        self.assertIn("skipped", hijack.detail)
        self.assertIsNone(findings["nxdomain_hijack"])

    def test_clean_dns_passes(self):
        findings, hijack = self._collect(
            lambda name: ["93.184.215.14"] if name == dnscheck.TEST_DOMAIN else None)
        self.assertEqual(hijack.status, "ok")
        self.assertFalse(findings["nxdomain_hijack"])

    def test_hijacking_dns_fails(self):
        findings, hijack = self._collect(lambda name: ["10.10.10.10"])
        self.assertEqual(hijack.status, "fail")
        self.assertTrue(findings["nxdomain_hijack"])


if __name__ == "__main__":
    unittest.main()
