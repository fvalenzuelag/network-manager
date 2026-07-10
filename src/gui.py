"""Local web GUI — a stdlib http.server serving web/index.html.

`python main.py gui` starts a localhost-only server and opens the browser.
The page runs the same full check as the CLI, streaming results live via
polling, plus a live stability monitor. Everything is served from disk with
no external assets, so it works on a network with no internet at all.
"""

import json
import mimetypes
import os
import threading
import time
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import dnscheck, history, netinfo, verdict
from .connectivity import ping, tcp_connect_ms
from .fullcheck import run_full
from .reporting import Report

WEB_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

_lock = threading.Lock()
_state = {
    "running": False,
    "report": None,
    "verdict": None,
    "started": None,
    "elapsed": None,
    "error": None,
}


def _run_check(include_speed):
    report = _state["report"]
    try:
        findings = run_full(report, include_speed=include_speed)
        history.compare(report, findings)
        _state["verdict"] = verdict.diagnose(findings)
    except Exception as e:  # surfaced in the UI instead of a dead spinner
        _state["error"] = f"{type(e).__name__}: {e}"
    finally:
        _state["elapsed"] = time.monotonic() - _state["started"]
        _state["running"] = False


def start_run(include_speed=False):
    with _lock:
        if _state["running"]:
            return False
        _state.update(running=True, report=Report(quiet=True), verdict=None,
                      started=time.monotonic(), elapsed=None, error=None)
    threading.Thread(target=_run_check, args=(include_speed,),
                     daemon=True).start()
    return True


def probe():
    """One live-monitor tick: gateway ping, internet TCP, DNS query."""
    gateway, _ = netinfo.get_default_route()
    dns_server = next((s for s in netinfo.get_dns_servers() if "." in s), None)
    gw_ms = ping(gateway, count=1, timeout_s=2) if gateway else None
    net_ms = tcp_connect_ms("1.1.1.1", 443, timeout=2)
    dns_ms = None
    if dns_server:
        t0 = time.monotonic()
        if dnscheck.query("example.com", dns_server, timeout=2) is not None:
            dns_ms = (time.monotonic() - t0) * 1000
    return {"gateway_ms": gw_ms, "internet_ms": net_ms, "dns_ms": dns_ms}


class Handler(BaseHTTPRequestHandler):

    def log_message(self, *args):  # keep the terminal clean
        pass

    def _send(self, body, content_type, code=200):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(json.dumps(obj, default=str).encode(),
                   "application/json", code)

    def _serve_static(self, path):
        """Serve a file from WEB_ROOT, refusing anything that escapes it."""
        rel = "index.html" if path == "/" else path.lstrip("/")
        full = os.path.realpath(os.path.join(WEB_ROOT, rel))
        if not full.startswith(os.path.realpath(WEB_ROOT) + os.sep) \
                and full != os.path.realpath(WEB_ROOT):
            self._json({"error": "forbidden"}, 403)
            return
        try:
            with open(full, "rb") as f:
                ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
                if ctype.startswith("text/") or ctype == "application/javascript":
                    ctype += "; charset=utf-8"
                self._send(f.read(), ctype)
        except OSError:
            self._json({"error": "not found"}, 404)

    def do_GET(self):
        url = urlparse(self.path)

        if url.path == "/api/state":
            report = _state["report"]
            v = _state["verdict"]
            elapsed = _state["elapsed"]
            if elapsed is None and _state["started"] is not None:
                elapsed = time.monotonic() - _state["started"]
            self._json({
                "running": _state["running"],
                "results": [asdict(r) for r in list(report.results)] if report else [],
                "verdict": {"status": v[0], "headline": v[1], "action": v[2]} if v else None,
                "elapsed": round(elapsed, 1) if elapsed is not None else None,
                "error": _state["error"],
            })

        elif url.path == "/api/run":
            query = parse_qs(url.query)
            speed = query.get("speed", ["0"])[0] == "1"
            self._json({"started": start_run(include_speed=speed)})

        elif url.path == "/api/probe":
            self._json(probe())

        elif url.path.startswith("/api/"):
            self._json({"error": "not found"}, 404)

        else:
            self._serve_static(url.path)


def serve(port=8765, open_browser=True):
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError:  # port taken — let the OS pick one
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"network-manager GUI: {url}  (Ctrl-C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
