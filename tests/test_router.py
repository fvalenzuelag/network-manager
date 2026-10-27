"""Router identity: ARP impersonation and router changes between visits.

Run:  python3 -m unittest discover tests
"""

import tempfile
import unittest
from unittest import mock

from network_manager import history, netinfo
from network_manager.reporting import Report
from network_manager.verdict import diagnose

GW, GW_MAC = "192.168.0.1", "18:35:d1:f7:72:a8"

MAC_ARP = """\
? (192.168.0.1) at 18:35:d1:f7:72:a8 on en0 ifscope [ethernet]
? (192.168.0.7) at 2:1a:b:c:d:e on en0 ifscope [ethernet]
? (192.168.0.9) at (incomplete) on en0 ifscope [ethernet]
? (192.168.0.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""

LINUX_NEIGH = """\
192.168.0.1 dev wlan0 lladdr 18:35:d1:f7:72:a8 REACHABLE
192.168.0.7 dev wlan0 lladdr 02:1a:0b:0c:0d:0e STALE
192.168.0.9 dev wlan0 FAILED
"""


class TestArpTable(unittest.TestCase):

    def _table(self, platform, output):
        with mock.patch.object(netinfo.sys, "platform", platform), \
                mock.patch.object(netinfo, "_run", return_value=output):
            return netinfo.arp_table()

    def test_macos_normalizes_and_skips_broadcast_multicast_incomplete(self):
        self.assertEqual(self._table("darwin", MAC_ARP), {
            GW: GW_MAC, "192.168.0.7": "02:1a:0b:0c:0d:0e"})

    def test_linux_ip_neigh(self):
        self.assertEqual(self._table("linux", LINUX_NEIGH), {
            GW: GW_MAC, "192.168.0.7": "02:1a:0b:0c:0d:0e"})


class TestImpersonation(unittest.TestCase):

    def _check(self, arp):
        report = Report(quiet=True)
        result = netinfo.check_router_impersonation(report, GW, GW_MAC, arp)
        return result, (report.results[0] if report.results else None)

    def test_unique_router_mac_is_clean(self):
        result, row = self._check({GW: GW_MAC, "192.168.0.7": "02:00:00:00:00:07"})
        self.assertEqual((result, row.status), ("clean", "ok"))

    def test_another_ip_with_router_mac_is_suspicious(self):
        result, row = self._check({GW: GW_MAC, "192.168.0.66": GW_MAC})
        self.assertEqual((result, row.status), ("suspicious", "warn"))
        self.assertIn("192.168.0.66", row.detail)

    def test_proxy_arp_is_not_an_alarm(self):
        arp = {GW: GW_MAC, **{f"192.168.0.{i}": GW_MAC for i in range(10, 15)}}
        result, row = self._check(arp)
        self.assertEqual((result, row.status), ("proxy_arp", "info"))
        self.assertIn("proxy ARP", row.detail)

    def test_unknown_router_mac_is_skipped(self):
        report = Report(quiet=True)
        self.assertIsNone(netinfo.check_router_impersonation(report, GW, None, {}))
        self.assertEqual(report.results, [])

    def test_verdict_warns_on_suspected_spoofing(self):
        status, headline, action = diagnose({
            "network": {"local_ip": "192.168.0.39", "gateway": GW,
                        "router_impersonation": "suspicious"},
            "connectivity": {"internet": True}, "portal": {},
        })
        self.assertEqual(status, "warn")
        self.assertIn("ARP spoofing", headline)
        self.assertIn("VPN", action)


class TestRouterChange(unittest.TestCase):

    def _second_visit(self, network_first, network_second):
        tmp = tempfile.mkdtemp()
        with mock.patch.object(history, "HISTORY_DIR", tmp):
            history.compare(Report(quiet=True), {"network": network_first})
            report = Report(quiet=True)
            history.compare(report, {"network": network_second})
        return next((r for r in report.results if r.name == "Router"), None)

    def test_same_ssid_new_router_warns(self):
        row = self._second_visit(
            {"ssid": "Hotel-Guest", "gateway_mac": GW_MAC},
            {"ssid": "Hotel-Guest", "gateway_mac": "aa:bb:cc:dd:ee:ff"})
        self.assertEqual(row.status, "warn")
        self.assertIn(f"{GW_MAC} → aa:bb:cc:dd:ee:ff", row.detail)

    def test_same_router_is_quiet(self):
        self.assertIsNone(self._second_visit(
            {"ssid": "Hotel-Guest", "gateway_mac": GW_MAC},
            {"ssid": "Hotel-Guest", "gateway_mac": GW_MAC}))

    def test_keyed_by_mac_a_new_router_is_just_a_new_network(self):
        # With the SSID hidden, a different router lands in a different
        # history file — no false "router changed" on unrelated networks.
        self.assertIsNone(self._second_visit(
            {"gateway": GW, "gateway_mac": GW_MAC},
            {"gateway": GW, "gateway_mac": "aa:bb:cc:dd:ee:ff"}))


if __name__ == "__main__":
    unittest.main()
