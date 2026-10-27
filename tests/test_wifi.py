"""Wi-Fi link parsing and the open-network warning — no radio needed.

Run:  python3 -m unittest discover tests
"""

import unittest
from unittest import mock

from network_manager import wifi
from network_manager.reporting import Report
from network_manager.verdict import diagnose

# Trimmed `system_profiler SPAirPortDataType` output. The nearby network
# listed after ours is open — it must never be mistaken for ours.
PROFILER = """\
Wi-Fi:
      Interfaces:
        en0:
          Supported PHY Modes: 802.11 a/b/g/n/ac/ax
          Current Network Information:
            Hotel-Guest:
              PHY Mode: 802.11ac
              Channel: 36 (5GHz, 80MHz)
              Security: {security}
              Signal / Noise: -58 dBm / -94 dBm
              Transmit Rate: 433
          Other Local Wi-Fi Networks:
            FreeAirportWiFi:
              Security: None
"""


def _link(security):
    out = mock.Mock(stdout=PROFILER.format(security=security))
    with mock.patch.object(wifi.sys, "platform", "darwin"), \
            mock.patch.object(wifi.subprocess, "run", return_value=out):
        return wifi.get_link_info()


def _result(report, name):
    return next((r for r in report.results if r.name == name), None)


class TestParsing(unittest.TestCase):

    def test_reads_our_network_not_a_nearby_open_one(self):
        link = _link("WPA2 Personal")
        self.assertEqual(link["security"], "WPA2 Personal")
        self.assertEqual(link["security_level"], "ok")
        self.assertEqual((link["rssi_dbm"], link["snr_db"]), (-58, 36))

    def test_open_network(self):
        self.assertEqual(_link("None")["security_level"], "open")

    def test_levels(self):
        for security, level in [("None", "open"), ("WEP", "open"),
                                ("WPA Personal", "weak"),
                                ("WPA2 Personal", "ok"),
                                ("WPA2/WPA3 Personal", "ok"),
                                ("WPA3 Enterprise", "ok"), ("OWE", "ok"),
                                ("Something new", None), (None, None)]:
            with self.subTest(security=security):
                self.assertEqual(wifi.security_level(security), level)


class TestReport(unittest.TestCase):

    def _row(self, security):
        report = Report(quiet=True)
        wifi.collect(report, _link(security))
        return _result(report, "Wi-Fi security")

    def test_open_network_warns_with_advice(self):
        row = self._row("None")
        self.assertEqual(row.status, "warn")
        self.assertEqual(row.detail,
                         "Open (no password) — this network is not encrypted")
        self.assertIn("VPN", row.advice)

    def test_weak_and_secure(self):
        self.assertEqual(self._row("WPA Personal").status, "warn")
        self.assertEqual(self._row("WPA3 Personal").status, "ok")
        self.assertEqual(self._row("Something new").status, "info")


class TestVerdict(unittest.TestCase):

    def _diagnose(self, level, vpn=None):
        return diagnose({
            "network": {"local_ip": "10.0.0.2", "gateway": "10.0.0.1",
                        "vpn_interface": vpn},
            "connectivity": {"internet": True, "latency_ms": 30},
            "portal": {}, "dns": {"system_resolves": True},
            "services": {"blocked": [], "open": []},
            "wifi": {"security_level": level},
        })

    def test_open_wifi_downgrades_healthy_to_warn(self):
        status, headline, action = self._diagnose("open")
        self.assertEqual(status, "warn")
        self.assertIn("unencrypted", headline)
        self.assertIn("VPN", action)

    def test_vpn_covers_open_wifi(self):
        status, headline, _ = self._diagnose("open", vpn="utun4")
        self.assertEqual(status, "ok")
        self.assertIn("your VPN covers that", headline)

    def test_secure_wifi_is_unchanged(self):
        status, headline, action = self._diagnose("ok")
        self.assertEqual(status, "ok")
        self.assertNotIn("unencrypted", headline)
        self.assertIsNone(action)


if __name__ == "__main__":
    unittest.main()
