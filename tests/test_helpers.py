"""Managed-network helpers, history storage and scan output — no network.

The helpers' optional dependencies (netmiko, requests) are stubbed when
they aren't installed, so the suite stays stdlib-only like the tool.

Run:  python3 -m unittest discover tests
"""

import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

for _dep in ("netmiko", "requests"):
    if importlib.util.find_spec(_dep) is None:
        stub = types.ModuleType(_dep)
        stub.ConnectHandler = stub.Session = mock.MagicMock()
        sys.modules[_dep] = stub

from src import history, monitoring_cisco, monitoring_unifi, network_discovery  # noqa: E402


class TestCisco(unittest.TestCase):

    def test_parses_cpu_line(self):
        out = ("CPU utilization for five seconds: 5%/0%; one minute: 3%; "
               "five minutes: 2%")
        self.assertEqual(monitoring_cisco.parse_cpu(out),
                         "5% (5 s), 3% (1 min), 2% (5 min)")

    def test_parses_processor_memory(self):
        out = "Processor Pool Total:  800000000 Used:  240000000 Free:  560000000"
        self.assertEqual(monitoring_cisco.parse_memory(out),
                         "30% of processor memory used")

    def test_unparseable_output_is_none(self):
        self.assertIsNone(monitoring_cisco.parse_cpu("% Invalid input"))
        self.assertIsNone(monitoring_cisco.parse_memory(""))

    def test_full_status_and_always_disconnects(self):
        conn = mock.Mock()
        conn.send_command.side_effect = lambda cmd: {
            "show run | include ^hostname": "hostname core-sw1",
            "show version | include uptime":
                "core-sw1 uptime is 3 weeks, 2 days, 4 hours",
            "show processes cpu | include CPU utilization":
                "CPU utilization for five seconds: 9%/1%; one minute: 7%; "
                "five minutes: 6%",
            "show processes memory | include Processor":
                "Processor Pool Total: 1000 Used: 250 Free: 750",
        }[cmd]
        with mock.patch.object(monitoring_cisco, "ConnectHandler",
                               return_value=conn):
            status = monitoring_cisco.get_device_status({"host": "10.0.0.1"})
        self.assertEqual(status, {
            "hostname": "core-sw1", "uptime": "3 weeks, 2 days, 4 hours",
            "cpu_util": "9% (5 s), 7% (1 min), 6% (5 min)",
            "mem_util": "25% of processor memory used"})
        conn.disconnect.assert_called_once()

    def test_failure_mid_session_still_disconnects(self):
        conn = mock.Mock()
        conn.send_command.side_effect = OSError("session dropped")
        with mock.patch.object(monitoring_cisco, "ConnectHandler",
                               return_value=conn), \
                mock.patch("builtins.print"):
            self.assertIsNone(
                monitoring_cisco.get_device_status({"host": "10.0.0.1"}))
        conn.disconnect.assert_called_once()

    def test_does_not_need_requests(self):
        self.assertNotIn("requests", vars(monitoring_cisco))
        self.assertIs(monitoring_cisco.load_env, monitoring_unifi.load_env)


class TestUnifi(unittest.TestCase):

    def test_only_state_1_is_connected(self):
        self.assertEqual(monitoring_unifi.device_status(1), "CONNECTED")
        self.assertEqual(monitoring_unifi.device_status(0), "DISCONNECTED")
        self.assertEqual(monitoring_unifi.device_status(6), "HEARTBEAT MISSED")
        self.assertIn("UNKNOWN", monitoring_unifi.device_status(99))

    def _run(self, login_codes):
        session = mock.Mock()
        posts = iter(login_codes)

        def post(url, **kwargs):
            resp = mock.Mock(headers={"X-CSRF-Token": "tok"})
            resp.status_code = next(posts) if "login" in url else 200
            return resp
        session.post.side_effect = post
        session.get.return_value.json.return_value = {
            "data": [{"name": "AP", "model": "U6", "state": 6}]}
        with mock.patch.object(monitoring_unifi.requests, "Session",
                               return_value=session), \
                mock.patch("builtins.print") as printed:
            code = monitoring_unifi.monitor("https://c", "u", "p")
        return code, session, printed

    def test_classic_controller(self):
        code, session, printed = self._run([200])
        self.assertEqual(code, 0)
        session.get.assert_any_call("https://c/api/s/default/stat/device",
                                    timeout=10)
        session.get.assert_any_call("https://c/api/logout", timeout=10)
        self.assertIn("HEARTBEAT MISSED", printed.call_args[0][0])

    def test_unifi_os_console(self):
        code, session, _ = self._run([404, 200])
        self.assertEqual(code, 0)
        session.get.assert_any_call(
            "https://c/proxy/network/api/s/default/stat/device", timeout=10)
        session.post.assert_any_call("https://c/api/auth/logout",
                                     headers={"X-CSRF-Token": "tok"},
                                     timeout=10)

    def test_bad_credentials(self):
        code, session, _ = self._run([400])
        self.assertEqual(code, 1)
        session.get.assert_not_called()


class TestHistoryStorage(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        patcher = mock.patch.object(history, "HISTORY_DIR", self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_save_is_atomic_and_leaves_no_temp_files(self):
        history.save_run("net", {"timestamp": "t1"})
        history.save_run("net", {"timestamp": "t2"})
        self.assertEqual([r["timestamp"] for r in history.load_runs("net")],
                         ["t1", "t2"])
        self.assertEqual(os.listdir(self.dir), ["net.json"])

    def test_failed_write_keeps_previous_file(self):
        history.save_run("net", {"timestamp": "t1"})
        with mock.patch.object(history.json, "dump",
                               side_effect=RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                history.save_run("net", {"timestamp": "t2"})
        self.assertEqual(history.load_runs("net"), [{"timestamp": "t1"}])
        self.assertEqual(os.listdir(self.dir), ["net.json"])

    def test_corrupt_file_is_set_aside_not_overwritten(self):
        for content in ("{not json", json.dumps({"a": 1})):
            with self.subTest(content=content):
                path = os.path.join(self.dir, "net.json")
                with open(path, "w") as f:
                    f.write(content)
                self.assertEqual(history.load_runs("net"), [])
                with open(path + ".corrupt") as f:
                    self.assertEqual(f.read(), content)

    def test_when_tolerates_missing_or_naive_timestamps(self):
        self.assertEqual(history._when(None), "previously")
        self.assertIsInstance(history._when("2026-01-02T03:04:05"), str)


class TestScanOutput(unittest.TestCase):

    def test_unwritable_output_does_not_crash_scan(self):
        with mock.patch.object(network_discovery, "get_local_ip",
                               return_value="10.0.0.5"), \
                mock.patch.object(network_discovery, "_probe_host",
                                  side_effect=lambda ip: ip if ip.endswith(".1") else None), \
                mock.patch.object(network_discovery, "arp_table", return_value={}), \
                mock.patch.object(network_discovery, "_hostname", return_value=None), \
                mock.patch.object(network_discovery, "OUTPUT_FILE",
                                  "/dev/null/not-a-dir/devices.txt"):
            devices = network_discovery.discover_network()
        self.assertIn("10.0.0.1", [d["ip"] for d in devices])

    def test_this_machine_is_listed(self):
        # The local host doesn't answer its own probes or appear in ARP.
        with mock.patch.object(network_discovery, "get_local_ip",
                               return_value="10.0.0.5"), \
                mock.patch.object(network_discovery, "_probe_host",
                                  side_effect=lambda ip: ip if ip.endswith(".1") else None), \
                mock.patch.object(network_discovery, "arp_table", return_value={}), \
                mock.patch.object(network_discovery, "_hostname", return_value=None), \
                mock.patch.object(network_discovery, "OUTPUT_FILE",
                                  "/dev/null/not-a-dir/devices.txt"):
            devices = network_discovery.discover_network()
        self.assertEqual([(d["ip"], d["is_you"]) for d in devices],
                         [("10.0.0.1", False), ("10.0.0.5", True)])

    def test_output_is_not_relative_to_cwd(self):
        self.assertTrue(os.path.isabs(network_discovery.OUTPUT_FILE))


if __name__ == "__main__":
    unittest.main()
