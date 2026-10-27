"""The GUI server must only obey its own page — not other websites.

Spins up the real handler on a free localhost port; the functions that
would touch the network are mocked.

Run:  python3 -m unittest discover tests
"""

import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

from network_manager import gui

API = {gui.API_HEADER: "1"}


class TestGuiSecurity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), gui.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        patches = [
            mock.patch.object(gui, "start_run", return_value=True),
            mock.patch.object(gui, "probe", return_value={"internet_ms": 5}),
        ]
        self.start_run, _ = [p.start() for p in patches]
        for p in patches:
            self.addCleanup(p.stop)

    def request(self, method, path, headers=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = dict(headers or {})
        headers["Host"] = host or f"127.0.0.1:{self.port}"
        conn.request(method, path, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    # ── Our own page works ──────────────────────────────────────────
    def test_page_and_api_work_for_own_origin(self):
        self.assertEqual(self.request("GET", "/")[0], 200)
        self.assertEqual(self.request("GET", "/api/state", API)[0], 200)
        self.assertEqual(self.request("GET", "/api/probe", API)[0], 200)
        status, body = self.request("POST", "/api/run?speed=1", API)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"started": True})
        self.start_run.assert_called_once_with(include_speed=True)

    def test_localhost_name_is_accepted(self):
        status, _ = self.request("GET", "/api/state", API,
                                 host=f"localhost:{self.port}")
        self.assertEqual(status, 200)

    # ── DNS rebinding: a foreign Host is refused everywhere ─────────
    def test_foreign_host_is_rejected(self):
        for method, path in [("GET", "/"), ("GET", "/api/state"),
                             ("POST", "/api/run")]:
            with self.subTest(path=path):
                status, _ = self.request(method, path, API,
                                         host=f"evil.example:{self.port}")
                self.assertEqual(status, 403)
        self.start_run.assert_not_called()

    # ── CSRF: requests without the API header do nothing ────────────
    def test_api_without_header_is_rejected(self):
        for method, path in [("GET", "/api/state"), ("GET", "/api/probe"),
                             ("POST", "/api/run?speed=1")]:
            with self.subTest(path=path):
                self.assertEqual(self.request(method, path)[0], 403)
        self.start_run.assert_not_called()

    def test_portal_endpoint_and_state(self):
        with mock.patch.object(gui.captive, "portal_cleared", return_value=True):
            self.assertEqual(self.request("GET", "/api/portal")[0], 403)  # no header
            status, body = self.request("GET", "/api/portal", API)
        self.assertEqual((status, json.loads(body)), (200, {"cleared": True}))
        status, body = self.request("GET", "/api/state", API)
        self.assertIn("portal_url", json.loads(body))

    def test_run_via_get_is_refused(self):
        # An <img src=".../api/run?speed=1"> must not start a speed test.
        status, _ = self.request("GET", "/api/run?speed=1", API)
        self.assertEqual(status, 405)
        self.start_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
