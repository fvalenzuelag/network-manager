"""Speed test: upload limits, bufferbloat grading, and how results surface.

No network: transfers and latency probes are mocked.

Run:  python3 -m unittest discover tests
"""

import http.client
import tempfile
import unittest
from unittest import mock

from network_manager import history, speed
from network_manager.reporting import Report
from network_manager.verdict import diagnose


class Probes:
    """Stand-in for LoadLatency with fixed results."""

    def __init__(self, samples=(), failures=0):
        self.samples, self.failures = list(samples), failures

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass


class TestGrading(unittest.TestCase):

    def test_scale(self):
        # idle is 20 ms, so the increase is loaded - 20; 60 starts grade C.
        for loaded, grade in [(30, "ok"), (70, "ok"), (80, "moderate"),
                              (219, "moderate"), (220, "severe")]:
            with self.subTest(loaded=loaded):
                g, inc = speed.grade_bufferbloat(20, Probes([loaded] * 5))
                self.assertEqual((g, inc), (grade, loaded - 20))

    def test_one_spike_does_not_cry_wolf(self):
        g, _ = speed.grade_bufferbloat(20, Probes([25, 900, 27, 24]))
        self.assertEqual(g, "ok")

    def test_timeouts_under_load_are_severe(self):
        g, inc = speed.grade_bufferbloat(20, Probes([25, 30], failures=2))
        self.assertEqual((g, inc), ("severe", None))

    def test_too_little_data_says_nothing(self):
        self.assertEqual(speed.grade_bufferbloat(20, Probes([25, 30])), (None, None))
        self.assertEqual(speed.grade_bufferbloat(None, Probes([25] * 9)), (None, None))


class TestUpload(unittest.TestCase):

    def _upload(self, **kwargs):
        def urlopen(req, timeout):
            for _ in req.data:  # the server reads the whole body
                pass
            resp = mock.MagicMock()
            resp.__enter__.return_value.read.return_value = b"ok"
            return resp
        with mock.patch("urllib.request.urlopen", side_effect=urlopen):
            return speed.measure_upload(**kwargs)

    def test_stops_at_byte_budget(self):
        _, _, sent = self._upload(max_bytes=5 * speed.CHUNK)
        self.assertEqual(sent, 5 * speed.CHUNK)

    def test_stops_at_time_budget(self):
        self.assertIsNone(self._upload(max_seconds=0))  # nothing sent

    def test_dropped_connection_is_none(self):
        with mock.patch("urllib.request.urlopen",
                        side_effect=http.client.RemoteDisconnected("bye")):
            self.assertIsNone(speed.measure_upload())


class TestCollect(unittest.TestCase):

    def _collect(self, down_probes, up_probes, up=(17.0, 8.0, 17_000_000)):
        report = Report(quiet=True)
        with mock.patch.object(speed, "idle_latency", return_value=20.0), \
                mock.patch.object(speed, "measure", return_value=(150.0, 1.0, 25_000_000)), \
                mock.patch.object(speed, "measure_upload", return_value=up), \
                mock.patch.object(speed, "LoadLatency",
                                  side_effect=[down_probes, up_probes]):
            findings = speed.collect(report)
        rows = {r.name: r for r in report.results}
        return findings, rows

    def test_worse_direction_decides_and_is_named(self):
        findings, rows = self._collect(Probes([25] * 5), Probes([260] * 50))
        self.assertEqual(findings["bufferbloat"], "severe")
        self.assertEqual(findings["bufferbloat_ms"], 240)
        row = rows["Latency under load"]
        self.assertEqual(row.status, "warn")
        self.assertIn("while uploading", row.detail)

    def test_healthy_link(self):
        findings, rows = self._collect(Probes([40] * 5), Probes([35] * 50))
        self.assertEqual(findings["bufferbloat"], "ok")
        self.assertEqual(rows["Latency under load"].status, "ok")
        self.assertEqual(findings["upload_mbps"], 17.0)

    def test_no_honest_answer_no_row(self):
        findings, rows = self._collect(Probes([25]), Probes([]))
        self.assertIsNone(findings["bufferbloat"])
        self.assertNotIn("Latency under load", rows)

    def test_slow_upload_warns(self):
        _, rows = self._collect(Probes([25] * 5), Probes([25] * 5),
                                up=(0.8, 8.0, 800_000))
        self.assertEqual(rows["Upload speed"].status, "warn")
        self.assertIn("camera", rows["Upload speed"].advice)


class TestSurfacing(unittest.TestCase):

    def _verdict(self, **speed_findings):
        return diagnose({
            "network": {"local_ip": "10.0.0.2", "gateway": "10.0.0.1"},
            "connectivity": {"internet": True, "latency_ms": 20},
            "portal": {}, "dns": {"system_resolves": True},
            "speed": speed_findings,
        })

    def test_bufferbloat_and_low_upload_degrade_the_verdict(self):
        status, headline, action = self._verdict(
            bufferbloat="severe", bufferbloat_ms=240, upload_mbps=0.8)
        self.assertEqual(status, "warn")
        self.assertIn("240 ms", headline)
        self.assertIn("upload is only 0.8 Mbps", headline)
        self.assertIn("calls", action)

    def test_mild_bloat_keeps_it_healthy(self):
        status, _, _ = self._verdict(bufferbloat="ok", bufferbloat_ms=30,
                                     upload_mbps=17.0)
        self.assertEqual(status, "ok")

    def test_history_flags_upload_drop(self):
        tmp = tempfile.mkdtemp()
        net = {"ssid": "Cafe", "gateway_mac": "aa:bb:cc:dd:ee:ff"}
        with mock.patch.object(history, "HISTORY_DIR", tmp):
            history.compare(Report(quiet=True),
                            {"network": net, "speed": {"upload_mbps": 20.0}})
            report = Report(quiet=True)
            history.compare(report, {"network": net, "speed": {"upload_mbps": 4.0}})
        row = next(r for r in report.results if r.name == "Upload speed")
        self.assertIn("20 Mbps", row.detail)
        self.assertIn("4 Mbps now", row.detail)


if __name__ == "__main__":
    unittest.main()
