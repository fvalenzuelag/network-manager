"""DNS-over-HTTPS: the check itself, and the advice that depends on it.

The point of the check is that "use DNS-over-HTTPS" becomes a verified fix
(or is replaced by "use a VPN") instead of a guess. No network needed.

Run:  python3 -m unittest discover tests
"""

import json
import socket
import unittest
from unittest import mock

from network_manager import dnscheck
from network_manager.reporting import Report
from network_manager.verdict import diagnose


def _response(payload):
    resp = mock.MagicMock()
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    resp.__enter__.return_value.read.return_value = body
    return resp


class TestDohQuery(unittest.TestCase):

    def _query(self, outcome):
        kwargs = ({"side_effect": outcome} if isinstance(outcome, Exception)
                  else {"return_value": _response(outcome)})
        with mock.patch("urllib.request.urlopen", **kwargs) as urlopen:
            ips = dnscheck.doh_query("example.com", "https://1.1.1.1/dns-query")
        return ips, urlopen

    def test_answer_is_parsed_and_request_is_json_api(self):
        ips, urlopen = self._query({"Status": 0, "Answer": [
            {"type": 5, "data": "alias.example."},  # CNAME, skipped
            {"type": 1, "data": "93.184.215.14"}]})
        self.assertEqual(ips, ["93.184.215.14"])
        req = urlopen.call_args[0][0]
        self.assertEqual(req.full_url,
                         "https://1.1.1.1/dns-query?name=example.com&type=A")
        self.assertEqual(req.get_header("Accept"), "application/dns-json")

    def test_failures_are_none(self):
        for outcome in ({"Status": 2},                # SERVFAIL
                        {"Status": 0, "Answer": []},  # no A record
                        b"<html>portal</html>",       # not JSON
                        ["not", "a", "dict"],
                        socket.timeout()):            # blocked
            with self.subTest(outcome=outcome):
                self.assertIsNone(self._query(outcome)[0])


class TestCollectAdvice(unittest.TestCase):

    def _collect(self, system=True, public=True, doh=True, hijack=False):
        def resolve(name):
            if name == dnscheck.TEST_DOMAIN:
                return ["93.184.215.14"] if system else None
            return ["10.10.10.10"] if hijack else None
        report = Report(quiet=True)
        with mock.patch.object(dnscheck, "system_resolve", side_effect=resolve), \
                mock.patch.object(dnscheck, "query",
                                  return_value=["1.2.3.4"] if public else None), \
                mock.patch.object(dnscheck, "doh_query",
                                  return_value=["1.2.3.4"] if doh else None):
            findings = dnscheck.collect(report)
        return findings, {r.name: r for r in report.results}

    def test_working_doh(self):
        findings, rows = self._collect()
        self.assertTrue(findings["doh_works"])
        self.assertEqual(rows["DNS-over-HTTPS"].status, "ok")
        self.assertIn("Cloudflare, Google", rows["DNS-over-HTTPS"].detail)

    def test_blocked_doh_is_only_info_when_dns_is_fine(self):
        findings, rows = self._collect(doh=False)
        self.assertFalse(findings["doh_works"])
        self.assertEqual(rows["DNS-over-HTTPS"].status, "info")

    def test_blocked_doh_warns_when_it_was_the_way_out(self):
        _, rows = self._collect(public=False, doh=False)
        self.assertEqual(rows["DNS-over-HTTPS"].status, "warn")
        self.assertIn("only a VPN", rows["Direct access to public DNS"].advice)

    def test_hijack_advice_follows_doh(self):
        _, rows = self._collect(hijack=True, doh=True)
        self.assertIn("works here", rows["DNS hijack check"].advice)
        _, rows = self._collect(hijack=True, doh=False)
        self.assertIn("only a VPN", rows["DNS hijack check"].advice)


class TestVerdictAdvice(unittest.TestCase):

    def _verdict(self, **dns):
        return diagnose({
            "network": {"local_ip": "10.0.0.2", "gateway": "10.0.0.1"},
            "connectivity": {"internet": True, "latency_ms": 20},
            "portal": {}, "dns": dns,
        })

    def test_dead_dns_with_working_doh_is_a_confirmed_fix(self):
        status, _, action = self._verdict(system_resolves=False,
                                          public_dns_reachable=False,
                                          doh_works=True)
        self.assertEqual(status, "fail")
        self.assertIn("it works on this network", action)

    def test_dead_dns_with_blocked_doh_says_vpn(self):
        _, headline, action = self._verdict(system_resolves=False,
                                            public_dns_reachable=False,
                                            doh_works=False)
        self.assertIn("DNS-over-HTTPS are blocked", headline)
        self.assertIn("VPN or mobile data", action)
        self.assertNotIn("Enable DNS-over-HTTPS", action)

    def test_unknown_doh_keeps_the_generic_advice(self):
        _, _, action = self._verdict(system_resolves=False,
                                     public_dns_reachable=False)
        self.assertIn("Enable DNS-over-HTTPS", action)

    def test_hijack_action_follows_doh(self):
        _, _, action = self._verdict(system_resolves=True, nxdomain_hijack=True,
                                     doh_works=False)
        self.assertIn("DNS-over-HTTPS is blocked here", action)


if __name__ == "__main__":
    unittest.main()
