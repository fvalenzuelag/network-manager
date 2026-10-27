"""The verdict engine is pure logic over a findings dict — ideal to pin down.

Each case is a network condition travelers actually hit; the assertion is
the layer the verdict must blame, not the exact wording.

Run:  python3 -m unittest discover tests
(stdlib unittest, like everything else in this project — no pip installs)
"""

import unittest

from src.verdict import diagnose


def base(**overrides):
    findings = {
        "network": {"local_ip": "10.0.0.2", "gateway": "10.0.0.1"},
        "connectivity": {"internet": True, "gateway_reachable": True,
                         "latency_ms": 30},
        "portal": {},
        "dns": {"system_resolves": True},
        "services": {"blocked": [], "open": []},
        "wifi": {},
    }
    findings.update(overrides)
    return findings


class TestVerdict(unittest.TestCase):

    def test_healthy_network_is_ok(self):
        status, headline, action = diagnose(base())
        self.assertEqual(status, "ok")
        self.assertIsNone(action)

    def test_no_network_at_all(self):
        status, headline, _ = diagnose({})
        self.assertEqual(status, "fail")
        self.assertIn("not connected", headline)

    def test_self_assigned_ip_blames_dhcp(self):
        status, headline, _ = diagnose(base(network={"local_ip": "169.254.1.5"}))
        self.assertEqual(status, "fail")
        self.assertIn("DHCP", headline)

    def test_gateway_ok_but_no_internet_blames_uplink(self):
        status, headline, action = diagnose(base(
            connectivity={"internet": False, "gateway_reachable": True}))
        self.assertEqual(status, "fail")
        self.assertIn("upstream", headline)
        # It must tell the user local fixes won't help.
        self.assertIn("locally", action)

    def test_gateway_dead_blames_access_point(self):
        status, headline, _ = diagnose(base(
            connectivity={"internet": False, "gateway_reachable": False}))
        self.assertEqual(status, "fail")
        self.assertIn("access point", headline)

    def test_captive_portal_includes_login_url(self):
        status, headline, action = diagnose(base(
            portal={"captive_portal": True, "portal_url": "http://login.x"}))
        self.assertEqual(status, "warn")
        self.assertIn("portal", headline)
        self.assertIn("http://login.x", action)

    def test_portal_blocking_direct_ip_still_says_log_in(self):
        # Portals commonly drop all traffic until login; that must not be
        # blamed on the venue's uplink.
        status, headline, action = diagnose(base(
            connectivity={"internet": False, "gateway_reachable": True},
            portal={"captive_portal": True, "portal_url": "http://login.x"}))
        self.assertEqual(status, "warn")
        self.assertIn("portal", headline)
        self.assertIn("http://login.x", action)

    def test_tls_interception_is_a_hard_fail(self):
        status, headline, _ = diagnose(base(portal={"tls_interception": True}))
        self.assertEqual(status, "fail")
        self.assertIn("HTTPS", headline)

    def test_dead_dns_with_public_resolvers_suggests_switching(self):
        status, _, action = diagnose(base(
            dns={"system_resolves": False, "public_dns_reachable": True}))
        self.assertEqual(status, "fail")
        self.assertIn("1.1.1.1", action)

    def test_link_loss_blames_wifi_and_reports_signal(self):
        status, headline, action = diagnose(base(
            connectivity={"internet": True, "loss_gateway_pct": 20.0,
                          "latency_ms": 80},
            wifi={"rssi_dbm": -82}))
        self.assertEqual(status, "warn")
        self.assertIn("-82", headline)
        self.assertIn("access point", action)

    def test_upstream_loss_says_moving_wont_help(self):
        status, headline, action = diagnose(base(
            connectivity={"internet": True, "loss_gateway_pct": 0.0,
                          "loss_internet_pct": 12.0, "latency_ms": 40}))
        self.assertEqual(status, "warn")
        self.assertIn("uplink", headline)
        self.assertIn("won't help", action)

    def test_blocked_services_are_summarized(self):
        status, headline, _ = diagnose(base(
            services={"blocked": ["SSH — port 22 (github.com)",
                                  "Email — IMAP 993 (Gmail)"], "open": []}))
        self.assertEqual(status, "warn")
        self.assertIn("2 service(s)", headline)
        self.assertIn("SSH", headline)

    def test_weak_signal_alone_degrades_verdict(self):
        for rssi, expected in [(-50, "ok"), (-85, "warn")]:
            with self.subTest(rssi=rssi):
                status, _, _ = diagnose(base(wifi={"rssi_dbm": rssi}))
                self.assertEqual(status, expected)


if __name__ == "__main__":
    unittest.main()
