"""Path MTU / blackhole detection against an emulated `ping`.

The fake reproduces real macOS and Linux output for each way a path can
treat an oversized don't-fragment packet: deliver it, refuse it with a
signal (local interface or a router's "frag needed"), or drop it silently.

Run:  python3 -m unittest discover tests
"""

import subprocess
import unittest
from unittest import mock

from network_manager import connectivity
from network_manager.reporting import Report
from network_manager.verdict import diagnose

OVERHEAD = connectivity.ICMP_OVERHEAD


def fake_ping(mtu, mode, platform):
    """subprocess.run stand-in for a path whose MTU is `mtu`.

    mode: 'silent' (oversize dropped), 'router' (router signals frag
    needed), 'local' (local interface refuses), 'blocked' (no ICMP at all).
    """
    calls = []

    def run(cmd, **kwargs):
        size = int(cmd[cmd.index("-s") + 1])
        calls.append(size)
        if mode == "blocked":
            return subprocess.CompletedProcess(cmd, 2, "", "")
        if size + OVERHEAD <= mtu:
            return subprocess.CompletedProcess(
                cmd, 0, f"{size + 8} bytes from 1.1.1.1: icmp_seq=0 ttl=58\n", "")
        if mode == "silent":
            return subprocess.CompletedProcess(cmd, 2, "Request timeout\n", "")
        if mode == "local":
            err = ("ping: sendto: Message too long\n" if platform == "darwin"
                   else f"ping: local error: message too long, mtu={mtu}\n")
            return subprocess.CompletedProcess(cmd, 2, "", err)
        out = (f"556 bytes from 10.0.0.1: frag needed and DF set (MTU {mtu})\n"
               if platform == "darwin" else
               f"From 10.0.0.1 icmp_seq=1 Frag needed and DF set (mtu = {mtu})\n")
        return subprocess.CompletedProcess(cmd, 1, out, "")

    return run, calls


class TestPathMtu(unittest.TestCase):

    def _measure(self, mtu, mode, platform="darwin"):
        run, calls = fake_ping(mtu, mode, platform)
        with mock.patch.object(connectivity.sys, "platform", platform), \
                mock.patch.object(connectivity.subprocess, "run", side_effect=run) as m:
            result = connectivity.path_mtu()
        return result, calls, m

    def test_full_size_path_costs_two_probes(self):
        result, calls, _ = self._measure(1500, "silent")
        self.assertEqual(result, {"mtu": 1500, "blackhole": False})
        self.assertEqual(calls, [56, 1472])

    def test_silent_drop_is_a_blackhole_and_mtu_is_found(self):
        for platform in ("darwin", "linux"):
            for true_mtu in (1492, 1420, 1400, 1280):
                with self.subTest(platform=platform, mtu=true_mtu):
                    result, calls, _ = self._measure(true_mtu, "silent", platform)
                    self.assertTrue(result["blackhole"])
                    self.assertLessEqual(true_mtu - result["mtu"], 4)
                    self.assertLessEqual(result["mtu"], true_mtu)
                    self.assertLessEqual(len(calls), 12)  # bounded search

    def test_signaled_limits_are_not_blackholes(self):
        for platform in ("darwin", "linux"):
            for mode in ("router", "local"):
                with self.subTest(platform=platform, mode=mode):
                    result, _, _ = self._measure(1400, mode, platform)
                    self.assertFalse(result["blackhole"])
                    self.assertLessEqual(1400 - result["mtu"], 4)

    def test_icmp_blocked_measures_nothing(self):
        result, calls, _ = self._measure(1500, "blocked")
        self.assertIsNone(result)
        self.assertEqual(calls, [56])

    def test_dont_fragment_flag_per_platform(self):
        _, _, m = self._measure(1500, "silent", "darwin")
        self.assertIn("-D", m.call_args_list[0][0][0])
        _, _, m = self._measure(1500, "silent", "linux")
        cmd = m.call_args_list[0][0][0]
        self.assertEqual(cmd[cmd.index("-M") + 1], "do")


class TestReporting(unittest.TestCase):

    def _collect(self, mtu):
        report = Report(quiet=True)
        with mock.patch.object(connectivity, "tcp_connect_ms", return_value=20.0), \
                mock.patch.object(connectivity, "check_ipv6", return_value="none"), \
                mock.patch.object(connectivity, "internet_latency", return_value=20.0), \
                mock.patch.object(connectivity, "packet_loss", return_value=0.0), \
                mock.patch.object(connectivity, "path_mtu", return_value=mtu):
            findings = connectivity.collect(report)
        row = next((r for r in report.results if r.name == "Packet size (MTU)"), None)
        return findings, row

    def test_rows(self):
        cases = [({"mtu": 1500, "blackhole": False}, "ok"),
                 ({"mtu": 1400, "blackhole": False}, "info"),
                 ({"mtu": 1400, "blackhole": True}, "warn")]
        for mtu, status in cases:
            with self.subTest(mtu=mtu):
                findings, row = self._collect(mtu)
                self.assertEqual(row.status, status)
                self.assertEqual(findings["path_mtu"], mtu["mtu"])
        _, row = self._collect({"mtu": 1400, "blackhole": True})
        self.assertIn("MTU to 1400", row.advice)

    def test_icmp_blocked_reports_nothing(self):
        findings, row = self._collect(None)
        self.assertIsNone(row)
        self.assertFalse(findings["mtu_blackhole"])

    def test_verdict_names_the_blackhole(self):
        status, headline, action = diagnose({
            "network": {"local_ip": "10.0.0.2", "gateway": "10.0.0.1"},
            "connectivity": {"internet": True, "latency_ms": 20,
                             "path_mtu": 1400, "mtu_blackhole": True},
            "portal": {}, "dns": {"system_resolves": True},
        })
        self.assertEqual(status, "warn")
        self.assertIn("over 1400 bytes", headline)
        self.assertEqual(action, "Set your MTU to 1400.")


if __name__ == "__main__":
    unittest.main()
