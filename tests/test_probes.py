"""Probe classification against mocked network calls — no network needed.

Each case is a way a probe can be fooled into blaming the wrong thing:
a DNS failure posing as a blocked port, one filtered endpoint posing as a
captive portal, a ping-shy router posing as a dead one.

Run:  python3 -m unittest discover tests
"""

import io
import socket
import unittest
from unittest import mock

from network_manager import captive, connectivity, services
from network_manager.reporting import Report


def _result(report, name):
    return next(r for r in report.results if r.name == name)


class TestServices(unittest.TestCase):

    def _collect(self, connect, ntp):
        report = Report(quiet=True)
        with mock.patch.object(services, "_connect_v4", side_effect=connect), \
                mock.patch.object(services, "check_udp_dns", return_value=True), \
                mock.patch.object(services, "check_ntp", side_effect=ntp):
            findings = services.collect(report)
        return report, findings

    def test_dns_failure_is_not_a_blocked_port(self):
        def connect(host, port):
            raise socket.gaierror("nodename nor servname provided")
        report, findings = self._collect(connect, lambda: None)
        self.assertEqual(findings["blocked"], [])
        self.assertEqual(len(findings["unresolved"]),
                         len(services.TCP_SERVICES) + 1)  # + NTP
        r = _result(report, "SSH — port 22 (github.com)")
        self.assertEqual(r.status, "info")
        self.assertIn("didn't resolve", r.detail)

    def test_refused_port_is_blocked(self):
        def connect(host, port):
            if port == 22:
                raise ConnectionRefusedError()
        report, findings = self._collect(connect, lambda: True)
        self.assertEqual(findings["blocked"], ["SSH — port 22 (github.com)"])
        self.assertEqual(findings["unresolved"], [])

    def test_ntp_retries_only_a_lost_reply(self):
        calls = iter([False, True])
        ntp = mock.Mock(side_effect=lambda: next(calls))
        report, findings = self._collect(lambda h, p: None, ntp)
        self.assertEqual(ntp.call_count, 2)
        self.assertIn("UDP — NTP time sync (123)", findings["open"])

    def test_check_ntp_unresolvable_host_is_none(self):
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror()):
            self.assertIsNone(services.check_ntp())


class TestCaptivePortal(unittest.TestCase):

    def _collect(self, *probe_results):
        report = Report(quiet=True)
        with mock.patch.object(captive, "_probe", side_effect=probe_results), \
                mock.patch.object(captive, "check_tls_interception",
                                  return_value=("ok", "issued by X")):
            findings = captive.collect(report)
        return findings, _result(report, "Captive portal")

    def test_one_filtered_endpoint_is_not_a_portal(self):
        findings, r = self._collect(
            ("clean", "a"), ("clean", "b"), ("portal", "HTTP 403 from c"))
        self.assertFalse(findings["captive_portal"])
        self.assertEqual(r.status, "info")
        self.assertIn("1 of 3", r.detail)

    def test_all_clean_is_ok(self):
        findings, r = self._collect(("clean", "a"), ("clean", "b"), ("clean", "c"))
        self.assertFalse(findings["captive_portal"])
        self.assertEqual(r.status, "ok")

    def test_redirects_are_a_portal_with_login_url(self):
        findings, r = self._collect(
            ("redirect", "http://login.hotel/"), ("redirect", "http://login.hotel/"),
            ("portal", "unexpected content"))
        self.assertTrue(findings["captive_portal"])
        self.assertEqual(findings["portal_url"], "http://login.hotel/")
        self.assertEqual(r.status, "fail")

    def test_majority_of_wrong_answers_is_a_portal(self):
        findings, _ = self._collect(
            ("portal", "x"), ("portal", "y"), ("clean", "c"))
        self.assertTrue(findings["captive_portal"])

    def test_tie_goes_to_portal_only_with_a_redirect(self):
        findings, _ = self._collect(
            ("redirect", "http://login.x/"), ("clean", "b"), ("unreachable", "c"))
        self.assertTrue(findings["captive_portal"])
        findings, _ = self._collect(
            ("portal", "HTTP 500"), ("clean", "b"), ("unreachable", "c"))
        self.assertFalse(findings["captive_portal"])

    def test_relative_redirect_becomes_absolute_url(self):
        err = captive.urllib.error.HTTPError(
            "http://captive.apple.com/hotspot-detect.html", 302, "Found",
            {"Location": "/login?x=1"}, io.BytesIO())
        with mock.patch("urllib.request.OpenerDirector.open", side_effect=err):
            verdict, url = captive._probe(captive.PROBES[0])
        self.assertEqual((verdict, url),
                         ("redirect", "http://captive.apple.com/login?x=1"))


class TestGatewayReachability(unittest.TestCase):

    def test_refused_tcp_proves_router_is_alive(self):
        with mock.patch("socket.create_connection",
                        side_effect=ConnectionRefusedError()):
            self.assertTrue(connectivity.gateway_answers_tcp("10.0.0.1"))

    def test_silent_router_is_not_alive(self):
        with mock.patch("socket.create_connection",
                        side_effect=socket.timeout()):
            self.assertFalse(connectivity.gateway_answers_tcp("10.0.0.1"))

    def test_ping_shy_router_counts_as_reachable(self):
        report = Report(quiet=True)
        with mock.patch.object(connectivity, "ping", return_value=None), \
                mock.patch.object(connectivity, "gateway_answers_tcp",
                                  return_value=True), \
                mock.patch.object(connectivity, "tcp_connect_ms",
                                  return_value=None):  # offline: stop early
            findings = connectivity.collect(report, gateway="10.0.0.1")
        self.assertTrue(findings["gateway_reachable"])
        self.assertEqual(_result(report, "Gateway (router)").status, "ok")


if __name__ == "__main__":
    unittest.main()
