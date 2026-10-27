"""DNS health checks: resolution, hijacking, and access to public resolvers.

Includes a minimal DNS client (UDP) so we can query a *specific* server
without any third-party library, and a DNS-over-HTTPS check — so when the
advice is "use DNS-over-HTTPS", it's a verified fix, not a guess.
"""

import http.client
import json
import random
import secrets
import socket
import struct
import threading
import urllib.parse
import urllib.request

PUBLIC_RESOLVERS = {"1.1.1.1": "Cloudflare", "8.8.8.8": "Google"}
TEST_DOMAIN = "example.com"

# JSON DoH APIs, addressed by IP so the check works when DNS itself is
# broken (both certificates are valid for these IPs). Two providers, so
# one company being blocked doesn't decide the answer.
DOH_ENDPOINTS = [
    ("Cloudflare", "https://1.1.1.1/dns-query"),
    ("Google", "https://8.8.8.8/resolve"),
]


def build_query(name, qtype=1):
    """Build a DNS query packet for an A record (qtype=1)."""
    tid = random.getrandbits(16)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)  # RD flag, 1 question
    question = b"".join(
        bytes([len(label)]) + label.encode() for label in name.split(".")
    ) + b"\x00" + struct.pack(">HH", qtype, 1)  # IN class
    return tid, header + question


def _skip_name(data, offset):
    """Skip over a (possibly compressed) DNS name, return new offset."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            return offset + 2
        offset += 1 + length
    return offset


def query(name, server, timeout=3.0):
    """Query `server` directly for A records of `name`.

    Returns a list of IPs (possibly empty for NXDOMAIN/no answer),
    or None if the server did not respond (blocked/unreachable).
    """
    tid, packet = build_query(name)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (server, 53))
        data, _ = s.recvfrom(2048)
    except OSError:
        return None
    finally:
        s.close()

    if len(data) < 12 or struct.unpack(">H", data[:2])[0] != tid:
        return None
    ancount = struct.unpack(">H", data[6:8])[0]
    offset = _skip_name(data, 12) + 4  # skip question name + qtype/qclass
    ips = []
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4:
            ips.append(socket.inet_ntoa(data[offset:offset + 4]))
        offset += rdlength
    return ips


def system_resolve(name, timeout=4.0):
    """Resolve using the system resolver. Returns list of IPs or None.

    getaddrinfo ignores socket timeouts and can block for the OS resolver's
    full retry cycle on a dead DNS, so it runs in a daemon thread that we
    simply stop waiting for (a daemon thread never blocks interpreter exit).
    """
    result = []

    def resolve():
        try:
            infos = socket.getaddrinfo(name, None, socket.AF_INET)
            result.append(list({i[4][0] for i in infos}))
        except (socket.gaierror, UnicodeError):
            pass

    t = threading.Thread(target=resolve, daemon=True)
    t.start()
    t.join(timeout)
    return result[0] if result else None


def doh_query(name, url, timeout=5.0):
    """Resolve `name` over DNS-over-HTTPS (JSON API). Returns IPs or None.

    TLS verification is what makes this meaningful: a network can fake a
    port-53 answer, but not a 1.1.1.1 certificate.
    """
    query_string = urllib.parse.urlencode({"name": name, "type": "A"})
    req = urllib.request.Request(f"{url}?{query_string}", headers={
        "Accept": "application/dns-json",
        "User-Agent": "network-manager-diag/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(65536))
    except (OSError, ValueError, http.client.HTTPException):
        return None
    if not isinstance(data, dict) or data.get("Status") != 0:
        return None
    ips = [a.get("data") for a in data.get("Answer") or []
           if isinstance(a, dict) and a.get("type") == 1]
    return ips or None


def _workaround(doh_works):
    """The DNS workaround to recommend, given what the DoH check found."""
    if doh_works:
        return ("DNS-over-HTTPS works here — turn on \"Secure DNS\" in your "
                "browser, or use a VPN.")
    if doh_works is False:
        return ("DNS-over-HTTPS is blocked here too — only a VPN gets around "
                "this network's DNS.")
    return "Consider DNS-over-HTTPS in your browser, or a VPN."


def collect(report):
    """Run DNS diagnostics and add results to the report."""
    findings = {}

    ips = system_resolve(TEST_DOMAIN)
    findings["system_resolves"] = bool(ips)
    if ips:
        report.add("System DNS resolution", "ok", f"{TEST_DOMAIN} → {ips[0]}")
    else:
        report.add(
            "System DNS resolution", "fail", f"cannot resolve {TEST_DOMAIN}",
            "DNS is down on this network. Try setting your DNS to 1.1.1.1 "
            "(System Settings → Wi-Fi → Details → DNS).",
        )

    # Can we bypass the network's DNS and talk to public resolvers directly?
    blocked, working = [], []
    for server, label in PUBLIC_RESOLVERS.items():
        result = query(TEST_DOMAIN, server)
        (working if result else blocked).append(f"{label} ({server})")
    findings["public_dns_reachable"] = bool(working)

    doh_working = [label for label, url in DOH_ENDPOINTS
                   if doh_query(TEST_DOMAIN, url)]
    findings["doh_works"] = bool(doh_working)
    workaround = _workaround(findings["doh_works"])

    if working:
        report.add("Direct access to public DNS", "ok", ", ".join(working))
    else:
        report.add(
            "Direct access to public DNS", "warn",
            "port 53 to public resolvers is blocked",
            "This network forces you through its own DNS (common in hotels/"
            "airports). Assume DNS queries are visible to the operator. "
            + workaround,
        )

    if doh_working:
        report.add("DNS-over-HTTPS", "ok", "works — " + ", ".join(doh_working))
    elif not ips or not working:
        # It was the escape hatch for the DNS problems above — say so.
        report.add("DNS-over-HTTPS", "warn", "blocked",
                   "Encrypted DNS is blocked too; a VPN is the remaining way "
                   "around this network's DNS.")
    else:
        report.add("DNS-over-HTTPS", "info",
                   "blocked (only matters if you want encrypted DNS — this "
                   "network's own DNS works)")

    # NXDOMAIN hijack: a random domain that cannot exist must NOT resolve.
    # Meaningless when nothing resolves at all — a dead DNS would pass.
    if not ips:
        findings["nxdomain_hijack"] = None
        report.add("DNS hijack check", "info",
                   "skipped — system DNS isn't resolving anything")
        return findings

    fake = f"{secrets.token_hex(9)}-diag.com"
    hijack_ips = system_resolve(fake)
    findings["nxdomain_hijack"] = bool(hijack_ips)
    if hijack_ips:
        report.add(
            "DNS hijack check", "fail",
            f"nonexistent domain resolved to {hijack_ips[0]}",
            "The network's DNS is answering for domains that don't exist "
            "(hijacking). Expect ads/redirects. " + workaround,
        )
    else:
        report.add("DNS hijack check", "ok", "nonexistent domains correctly fail")

    return findings
