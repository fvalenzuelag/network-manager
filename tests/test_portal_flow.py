"""Captive portal login flow: open the page, wait for login, run again.

Also pins that a network-supplied login URL can only ever be a web page —
it gets opened in the browser. No network needed.

Run:  python3 -m unittest discover tests
"""

import contextlib
import io
import json
import sys
import unittest
from unittest import mock

import main
from src import captive

PORTAL = {"captive_portal": True, "portal_url": "http://login.hotel/",
          "tls_interception": False}
CLEAN = {"captive_portal": False, "portal_url": None, "tls_interception": False}


class TestLoginUrlSafety(unittest.TestCase):

    def _probe_redirect(self, location):
        err = captive.urllib.error.HTTPError(
            "http://captive.apple.com/hotspot-detect.html", 302, "Found",
            {"Location": location}, io.BytesIO())
        with mock.patch("urllib.request.OpenerDirector.open", side_effect=err):
            return captive._probe(captive.PROBES[0])

    def test_web_redirects_are_login_pages(self):
        self.assertEqual(self._probe_redirect("https://login.hotel/x"),
                         ("redirect", "https://login.hotel/x"))

    def test_non_web_redirects_are_never_offered(self):
        for location in ("javascript:alert(document.cookie)",
                         "file:///etc/passwd",
                         "data:text/html,<script>alert(1)</script>"):
            with self.subTest(location=location):
                verdict, detail = self._probe_redirect(location)
                self.assertEqual(verdict, "portal")  # still a portal sign
                self.assertNotIn(location, detail)

    def test_login_url(self):
        self.assertIsNone(captive.login_url(CLEAN))
        self.assertIsNone(captive.login_url(None))
        self.assertEqual(captive.login_url(PORTAL), "http://login.hotel/")
        self.assertEqual(captive.login_url({"captive_portal": True}),
                         "http://captive.apple.com")


class TestWaitForLogin(unittest.TestCase):

    def test_cleared_uses_the_same_vote_as_detection(self):
        cases = [([("clean", "a")] * 3, True),
                 ([("redirect", "http://x/")] * 3, False),
                 ([("clean", "a"), ("clean", "b"), ("portal", "403")], True),
                 ([("unreachable", "a")] * 3, False)]  # offline ≠ logged in
        for results, cleared in cases:
            with self.subTest(results=results):
                with mock.patch.object(captive, "_run_probes", return_value=results):
                    self.assertEqual(captive.portal_cleared(), cleared)

    def test_returns_once_cleared(self):
        sleeps = []
        with mock.patch.object(captive, "portal_cleared",
                               side_effect=[False, False, True]):
            self.assertTrue(captive.wait_for_login(sleep=sleeps.append))
        self.assertEqual(sleeps, [3.0, 3.0])

    def test_times_out(self):
        with mock.patch.object(captive, "portal_cleared", return_value=False):
            self.assertFalse(captive.wait_for_login(timeout=0, sleep=lambda s: None))


class TestCli(unittest.TestCase):

    def _main(self, argv, portal_results, wait=True):
        """Run main.py's `portal` command with scripted probe outcomes."""
        out, err = io.StringIO(), io.StringIO()
        wait_mock = mock.Mock(side_effect=wait if isinstance(wait, BaseException)
                              else None, return_value=wait)
        with mock.patch.object(sys, "argv", ["main.py", "portal", *argv]), \
                mock.patch.object(captive, "collect", side_effect=portal_results), \
                mock.patch.object(captive, "wait_for_login", wait_mock), \
                mock.patch.object(main.webbrowser, "open") as opened, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main.main()
        return code, out.getvalue(), err.getvalue(), opened, wait_mock

    def test_open_waits_then_runs_again(self):
        code, out, _, opened, wait = self._main(["--open"], [PORTAL, CLEAN])
        opened.assert_called_once_with("http://login.hotel/")
        wait.assert_called_once()
        self.assertIn("Logged in — running the check again", out)
        self.assertEqual(code, 0)

    def test_json_stays_parseable_and_reports_the_post_login_run(self):
        code, out, err, _, _ = self._main(["--open", "--json"], [PORTAL, CLEAN])
        payload = json.loads(out)  # nothing but JSON on stdout
        self.assertFalse(payload["findings"]["captive_portal"])
        self.assertIn("Waiting for you to log in", err)

    def test_no_wait_keeps_the_old_behaviour(self):
        _, _, _, opened, wait = self._main(["--open", "--no-wait"], [PORTAL])
        opened.assert_called_once()
        wait.assert_not_called()

    def test_ctrl_c_while_waiting_keeps_the_first_results(self):
        code, out, _, _, _ = self._main(["--open"], [PORTAL],
                                        wait=KeyboardInterrupt())
        self.assertIn("Stopped waiting", out)
        self.assertIn("Summary", out)

    def test_no_portal_no_browser(self):
        _, _, _, opened, wait = self._main(["--open"], [CLEAN])
        opened.assert_not_called()
        wait.assert_not_called()


if __name__ == "__main__":
    unittest.main()
