"""Where does this network put you on the internet?

One request to Cloudflare's trace endpoint (by IP, so it works with broken
DNS) returns your public IP, egress country, and which Cloudflare edge you
hit — the edge is an IATA airport code, which happens to be the perfect
answer format for a travel tool. Also reveals whether WARP/a proxy is on.
"""

import http.client
import urllib.request

TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"


def trace(timeout=6):
    """Fetch and parse the trace. Returns dict of key=value lines, or None."""
    req = urllib.request.Request(
        TRACE_URL, headers={"User-Agent": "network-manager-diag/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", "replace")
    except (OSError, http.client.HTTPException):
        return None
    fields = dict(
        line.split("=", 1) for line in body.splitlines() if "=" in line)
    return fields if "ip" in fields else None


def collect(report):
    """Report public IP / egress location. Returns findings dict."""
    fields = trace()
    if not fields:
        report.add("Public egress", "info",
                   "unavailable (trace endpoint unreachable)")
        return {}

    findings = {
        "public_ip": fields.get("ip"),
        "country": fields.get("loc"),
        "colo": fields.get("colo"),
        "warp": fields.get("warp"),
    }

    report.add("Public IP", "info", findings["public_ip"] or "?")
    location = findings["country"] or "?"
    if findings["colo"]:
        location += f", via Cloudflare edge {findings['colo']}"
    report.add("Egress location", "info", location)

    if findings["warp"] and findings["warp"] != "off":
        report.add("Cloudflare WARP", "info",
                   "active — your traffic is tunnelled through WARP")
    return findings
