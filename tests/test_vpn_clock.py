"""VPN awareness and the wrong-clock vs. HTTPS-interception distinction.

Both are cases where every individual check "works" but the conclusion
would be wrong: a VPN makes the report describe the tunnel, and a wrong
clock fails certificates exactly like a MITM does. No network needed.

Run:  python3 -m unittest discover tests
"""

import os
import tempfile
import unittest
from email.utils import formatdate
from unittest import mock

from network_manager import captive, history, netinfo
from network_manager.reporting import Report
from network_manager.verdict import diagnose

DAY = 86400


def _result(report, name):
    return next(r for r in report.results if r.name == name)


class TestClockSkew(unittest.TestCase):

    def _skew(self, *server_times, now=1_000_000_000.0):
        """Run clock_skew() with each source answering the given time."""
        answers = iter(server_times)

        def open_(req, timeout):
            t = next(answers)
            if isinstance(t, Exception):
                raise t
            resp = mock.MagicMock()
            resp.__enter__.return_value.headers = {"Date": formatdate(t, usegmt=True)}
            return resp

        with mock.patch("urllib.request.OpenerDirector.open", side_effect=open_), \
                mock.patch.object(captive.time, "time", return_value=now):
            return captive.clock_skew()

    def test_clock_behind_is_negative(self):
        now = 1_000_000_000.0
        self.assertAlmostEqual(self._skew(now + 3 * DAY, now + 3 * DAY, now=now),
                               -3 * DAY, delta=1)

    def test_stale_cached_date_never_blames_a_good_clock(self):
        # One source serves a months-old cached Date (seen live on
        # captive.apple.com); the live one agrees with us → no skew.
        now = 1_000_000_000.0
        self.assertAlmostEqual(self._skew(now - 150 * DAY, now, now=now), 0, delta=1)

    def test_unreachable_sources_give_none(self):
        self.assertIsNone(self._skew(OSError(), OSError()))

    def test_describe_skew(self):
        self.assertEqual(captive.describe_skew(-3 * DAY), "your clock is 3 days behind")
        self.assertEqual(captive.describe_skew(3600), "your clock is 1 hour ahead")


class TestClockVsInterception(unittest.TestCase):

    def _collect(self, skew):
        report = Report(quiet=True)
        with mock.patch.object(captive, "_probe", return_value=("clean", "x")), \
                mock.patch.object(captive, "check_tls_interception",
                                  return_value=("intercepted", "certificate has expired")), \
                mock.patch.object(captive, "clock_skew", return_value=skew):
            findings = captive.collect(report)
        return findings, report

    def test_wrong_clock_is_not_reported_as_mitm(self):
        findings, report = self._collect(-3 * DAY)
        self.assertFalse(findings["tls_interception"])
        self.assertEqual(_result(report, "System clock").status, "fail")
        self.assertEqual(_result(report, "TLS inspection (HTTPS MITM)").status, "info")

    def test_correct_clock_keeps_the_mitm_alarm(self):
        for skew in (2.0, None):  # in sync, or time unknown
            with self.subTest(skew=skew):
                findings, report = self._collect(skew)
                self.assertTrue(findings["tls_interception"])
                self.assertEqual(
                    _result(report, "TLS inspection (HTTPS MITM)").status, "fail")

    def test_clock_is_only_checked_when_tls_fails(self):
        with mock.patch.object(captive, "_probe", return_value=("clean", "x")), \
                mock.patch.object(captive, "check_tls_interception",
                                  return_value=("ok", "issued by X")), \
                mock.patch.object(captive, "clock_skew") as skew:
            captive.collect(Report(quiet=True))
        skew.assert_not_called()

    def test_verdict_blames_the_clock_not_the_network(self):
        status, headline, action = diagnose(_base(
            portal={"tls_interception": False, "clock_skew_s": -3 * DAY}))
        self.assertEqual(status, "fail")
        self.assertIn("3 days behind", headline)
        self.assertIn("Date & Time", action)


def _base(**overrides):
    findings = {
        "network": {"local_ip": "10.0.0.2", "gateway": "10.0.0.1"},
        "connectivity": {"internet": True, "latency_ms": 30},
        "portal": {},
        "dns": {"system_resolves": True},
        "services": {"blocked": [], "open": []},
    }
    findings.update(overrides)
    return findings


class TestVpn(unittest.TestCase):

    def test_tunnel_without_gateway_is_not_a_routing_failure(self):
        status, headline, action = diagnose(_base(
            network={"local_ip": "10.8.0.2", "gateway": None,
                     "vpn_interface": "utun4"}))
        self.assertEqual(status, "ok")
        self.assertIn("VPN on utun4", headline)
        self.assertIn("Disconnect the VPN", action)

    def test_vpn_note_keeps_the_real_action(self):
        status, headline, action = diagnose(_base(
            network={"local_ip": "10.8.0.2", "gateway": None,
                     "vpn_interface": "wg0"},
            portal={"tls_interception": True}))
        self.assertEqual(status, "fail")
        self.assertIn("VPN on wg0", headline)
        self.assertIn("VPN or mobile data", action)

    def test_no_vpn_no_note(self):
        _, headline, _ = diagnose(_base())
        self.assertNotIn("VPN", headline)

    def test_report_flags_vpn_and_softens_missing_gateway(self):
        report = Report(quiet=True)
        with mock.patch.object(netinfo, "get_default_route", return_value=(None, "utun4")), \
                mock.patch.object(netinfo, "get_local_ip", return_value="10.8.0.2"), \
                mock.patch.object(netinfo, "get_ssid", return_value=None), \
                mock.patch.object(netinfo, "get_dns_servers", return_value=["10.8.0.1"]):
            findings = netinfo.collect(report)
        self.assertEqual(findings["vpn_interface"], "utun4")
        self.assertEqual(_result(report, "VPN").status, "warn")
        self.assertEqual(_result(report, "Gateway").status, "info")

    def test_linux_tunnel_route_without_via_is_parsed(self):
        with mock.patch.object(netinfo.sys, "platform", "linux"), \
                mock.patch.object(netinfo, "_run",
                                  return_value="default dev wg0 scope link\n"):
            self.assertEqual(netinfo.get_default_route(), (None, "wg0"))
        with mock.patch.object(netinfo.sys, "platform", "linux"), \
                mock.patch.object(netinfo, "_run",
                                  return_value="default via 192.168.1.1 dev wlan0 proto dhcp\n"):
            self.assertEqual(netinfo.get_default_route(), ("192.168.1.1", "wlan0"))

    def test_vpn_runs_are_not_saved_to_history(self):
        tmp = tempfile.mkdtemp()
        report = Report(quiet=True)
        with mock.patch.object(history, "HISTORY_DIR", tmp):
            for gateway in ("10.8.0.1", None):  # usually no gateway at all
                with self.subTest(gateway=gateway):
                    report = Report(quiet=True)
                    history.compare(report, _base(
                        network={"gateway": gateway, "vpn_interface": "utun4"}))
                    self.assertEqual(os.listdir(tmp), [])
                    self.assertIn("VPN is active",
                                  _result(report, "History").detail)


if __name__ == "__main__":
    unittest.main()
