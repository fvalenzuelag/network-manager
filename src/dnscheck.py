"""DNS health checks: resolution, hijacking, and access to public resolvers.

Includes a minimal DNS client (UDP) so we can query a *specific* server
without any third-party library.
"""

import random
import secrets
import socket
import struct

PUBLIC_RESOLVERS = {"1.1.1.1": "Cloudflare", "8.8.8.8": "Google"}
TEST_DOMAIN = "example.com"


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
    """Resolve using the system resolver. Returns list of IPs or None."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET)
        return list({i[4][0] for i in infos})
    except socket.gaierror:
        return None
    finally:
        socket.setdefaulttimeout(old)


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
    if working:
        report.add("Direct access to public DNS", "ok", ", ".join(working))
    else:
        report.add(
            "Direct access to public DNS", "warn",
            "port 53 to public resolvers is blocked",
            "This network forces you through its own DNS (common in hotels/"
            "airports). Assume DNS queries are visible to the operator; "
            "consider DNS-over-HTTPS in your browser or a VPN.",
        )

    # NXDOMAIN hijack: a random domain that cannot exist must NOT resolve.
    fake = f"{secrets.token_hex(9)}-diag.com"
    hijack_ips = system_resolve(fake)
    findings["nxdomain_hijack"] = bool(hijack_ips)
    if hijack_ips:
        report.add(
            "DNS hijack check", "fail",
            f"nonexistent domain resolved to {hijack_ips[0]}",
            "The network's DNS is answering for domains that don't exist "
            "(hijacking). Expect ads/redirects; use DNS-over-HTTPS or a VPN.",
        )
    else:
        report.add("DNS hijack check", "ok", "nonexistent domains correctly fail")

    return findings
