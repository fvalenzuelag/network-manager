"""Captive portal detection.

Probes the same endpoints operating systems use to detect portals. A clean
network returns the exact expected response; a captive portal intercepts the
request and answers with a redirect or a login page instead.
"""

import http.client
import ssl
import socket
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

# (url, expected_status, expected_body_substring)
PROBES = [
    ("http://captive.apple.com/hotspot-detect.html", 200, "Success"),
    ("http://connectivitycheck.gstatic.com/generate_204", 204, ""),
    ("http://detectportal.firefox.com/success.txt", 200, "success"),
]

TIMEOUT = 6


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _probe(args):
    """Returns ('clean'|'portal'|'unreachable', detail)."""
    url, expected_status, expected_body = args
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "network-manager-diag/1.0"})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            body = resp.read(2048).decode("utf-8", "replace")
            if resp.status == expected_status and expected_body in body:
                return ("clean", url)
            return ("portal", f"unexpected content from {url}")
    except urllib.error.HTTPError as e:
        location = e.headers.get("Location", "")
        if 300 <= e.code < 400 and location:
            return ("portal", location)
        return ("portal", f"HTTP {e.code} from {url}")
    except (urllib.error.URLError, socket.timeout, OSError,
            http.client.HTTPException):
        return ("unreachable", url)


def check_tls_interception(host="www.google.com", timeout=6):
    """Verify a TLS handshake with a well-known site and return the cert issuer.

    Returns ('ok'|'intercepted'|'unreachable', detail).
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        org = issuer.get("organizationName", issuer.get("commonName", "unknown"))
        return ("ok", f"certificate issued by {org}")
    except ssl.SSLCertVerificationError as e:
        return ("intercepted", e.reason or str(e))
    except OSError:
        return ("unreachable", f"cannot reach {host}:443")


def collect(report):
    """Run captive portal + TLS interception checks. Returns findings dict."""
    findings = {"captive_portal": False, "portal_url": None}

    with ThreadPoolExecutor(max_workers=len(PROBES)) as pool:
        results = list(pool.map(_probe, PROBES))

    portals = [detail for verdict, detail in results if verdict == "portal"]
    clean = [1 for verdict, _ in results if verdict == "clean"]
    unreachable = [1 for verdict, _ in results if verdict == "unreachable"]

    if portals:
        findings["captive_portal"] = True
        redirect = next((d for d in portals if d.startswith("http")), None)
        findings["portal_url"] = redirect
        detail = f"login page: {redirect}" if redirect else portals[0]
        report.add(
            "Captive portal", "fail", detail,
            "This network requires a login before you can use it. Open "
            + (redirect or "http://captive.apple.com")
            + " in your browser to sign in.",
        )
    elif clean:
        report.add("Captive portal", "ok", "no portal — direct internet access")
    elif len(unreachable) == len(PROBES):
        report.add(
            "Captive portal", "fail", "all portal-check endpoints unreachable",
            "HTTP traffic isn't going through at all — see connectivity results.",
        )

    verdict, detail = check_tls_interception()
    findings["tls_interception"] = verdict == "intercepted"
    if verdict == "ok":
        report.add("TLS inspection (HTTPS MITM)", "ok", detail)
    elif verdict == "intercepted":
        report.add(
            "TLS inspection (HTTPS MITM)", "fail", detail,
            "HTTPS certificate verification failed: this network may be "
            "intercepting encrypted traffic. Do NOT log in to sensitive "
            "accounts; use a VPN or mobile data.",
        )
    else:
        report.add("TLS inspection (HTTPS MITM)", "warn", detail)

    return findings
