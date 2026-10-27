"""Captive portal detection.

Probes the same endpoints operating systems use to detect portals. A clean
network returns the exact expected response; a captive portal intercepts the
request and answers with a redirect or a login page instead.
"""

import email.utils
import http.client
import ssl
import socket
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

# (url, expected_status, expected_body_substring)
PROBES = [
    ("http://captive.apple.com/hotspot-detect.html", 200, "Success"),
    ("http://connectivitycheck.gstatic.com/generate_204", 204, ""),
    ("http://detectportal.firefox.com/success.txt", 200, "success"),
]

TIMEOUT = 6

# Sources whose Date header is generated live. Not captive.apple.com: it is
# served from a CDN cache and its Date can be months old.
CLOCK_SOURCES = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://1.1.1.1/cdn-cgi/trace",  # answers with a live 301 to HTTPS
]
# Certificates fail validation when the clock is outside their validity
# window; beyond this skew the clock is the likely cause, not a MITM.
CLOCK_SKEW_LIMIT = 300


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _probe(args):
    """Returns ('clean'|'redirect'|'portal'|'unreachable', detail).

    'redirect' (the detail is the absolute login URL) is the strong portal
    signal; 'portal' is any other wrong answer, which on its own may just
    be one filtered endpoint.
    """
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
            return ("redirect", urljoin(url, location))  # may be relative
        return ("portal", f"HTTP {e.code} from {url}")
    except (urllib.error.URLError, socket.timeout, OSError,
            http.client.HTTPException):
        return ("unreachable", url)


def clock_skew(timeout=TIMEOUT):
    """Seconds the local clock is ahead (+) or behind (-) server time, or None.

    Plain HTTP on purpose: HTTPS is exactly what breaks when the clock is
    wrong. A cache can only make a Date header older, so the smallest skew
    across sources wins — a stale cache never falsely blames the clock.
    """
    opener = urllib.request.build_opener(_NoRedirect)
    skews = []
    for url in CLOCK_SOURCES:
        req = urllib.request.Request(
            url, headers={"User-Agent": "network-manager-diag/1.0"})
        try:
            with opener.open(req, timeout=timeout) as resp:
                date = resp.headers.get("Date")
        except urllib.error.HTTPError as e:  # the 301 still carries a Date
            date = e.headers.get("Date")
            e.close()
        except (OSError, http.client.HTTPException):
            continue
        try:
            server = email.utils.parsedate_to_datetime(date).timestamp()
        except (TypeError, ValueError):
            continue
        skews.append(time.time() - server)
    return min(skews, key=abs) if skews else None


def describe_skew(seconds):
    """-259200 → 'your clock is 3 days behind'."""
    direction = "ahead" if seconds > 0 else "behind"
    s = abs(seconds)
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if s >= size:
            n = round(s / size)
            return f"your clock is {n} {unit}{'s' if n != 1 else ''} {direction}"
    return f"your clock is {s:.0f} seconds {direction}"


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

    redirects = [detail for verdict, detail in results if verdict == "redirect"]
    portals = redirects + [d for verdict, d in results if verdict == "portal"]
    clean = [1 for verdict, _ in results if verdict == "clean"]
    unreachable = [1 for verdict, _ in results if verdict == "unreachable"]

    # One odd answer (a firewall 403 on a single endpoint) must not outvote
    # clean probes; a portal intercepts all of them. Ties go to the portal
    # only when something actually redirected us to a login page.
    is_portal = len(portals) > len(clean) or (
        portals and len(portals) == len(clean) and redirects)

    if is_portal:
        findings["captive_portal"] = True
        redirect = redirects[0] if redirects else None
        findings["portal_url"] = redirect
        detail = f"login page: {redirect}" if redirect else portals[0]
        report.add(
            "Captive portal", "fail", detail,
            "This network requires a login before you can use it. Open "
            + (redirect or "http://captive.apple.com")
            + " in your browser to sign in.",
        )
    elif clean and portals:
        # Most checks came back clean: likely one filtered endpoint.
        report.add(
            "Captive portal", "info",
            f"no portal ({len(portals)} of {len(PROBES)} check endpoints "
            f"answered unexpectedly: {portals[0]})",
        )
    elif clean:
        report.add("Captive portal", "ok", "no portal — direct internet access")
    elif len(unreachable) == len(PROBES):
        report.add(
            "Captive portal", "fail", "all portal-check endpoints unreachable",
            "HTTP traffic isn't going through at all — see connectivity results.",
        )

    verdict, detail = check_tls_interception()
    # A wrong clock fails certificate checks exactly like a MITM does —
    # rule it out before raising the alarm.
    skew = clock_skew() if verdict == "intercepted" else None
    clock_wrong = skew is not None and abs(skew) > CLOCK_SKEW_LIMIT
    findings["clock_skew_s"] = skew
    findings["tls_interception"] = verdict == "intercepted" and not clock_wrong
    if verdict == "ok":
        report.add("TLS inspection (HTTPS MITM)", "ok", detail)
    elif clock_wrong:
        report.add(
            "System clock", "fail",
            f"{describe_skew(skew)} — HTTPS certificate checks fail because of it",
            "Turn on automatic time (System Settings → General → Date & "
            "Time) and re-run. Until then, HTTPS sites will show "
            "certificate errors.",
        )
        report.add("TLS inspection (HTTPS MITM)", "info",
                   "can't tell while your clock is wrong")
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
