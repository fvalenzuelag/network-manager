"""Check which common services/ports this network allows.

Public networks (hotels, airports, planes) frequently block anything that
isn't web traffic. Each check connects to a real public server, so a failure
means the network is blocking it (assuming basic internet works).
"""

import socket
import struct
from concurrent.futures import ThreadPoolExecutor

from . import dnscheck

TIMEOUT = 5

# name, host, port, advice-when-blocked
TCP_SERVICES = [
    ("Web — HTTPS (443)", "www.google.com", 443,
     "Even HTTPS is blocked — this network is unusable until you log in "
     "to its portal or switch networks."),
    ("Web — HTTP (80)", "detectportal.firefox.com", 80,
     "Plain HTTP is blocked. Mostly harmless — use https:// URLs."),
    ("SSH — port 22 (github.com)", "github.com", 22,
     "SSH is blocked. For git, use HTTPS remotes or SSH over port 443 "
     "(ssh.github.com:443)."),
    ("Email — IMAP 993 (Gmail)", "imap.gmail.com", 993,
     "IMAP is blocked — desktop mail clients won't sync. Use webmail or a VPN."),
    ("Email — SMTP 587 (Gmail)", "smtp.gmail.com", 587,
     "Outgoing mail (SMTP) is blocked. Use webmail or a VPN to send."),
    ("DNS over TCP (1.1.1.1:53)", "1.1.1.1", 53,
     "Custom DNS is blocked — you must use the network's own DNS."),
    ("DNS over TLS (1.1.1.1:853)", "1.1.1.1", 853,
     "Encrypted DNS (DoT) is blocked. Browsers' DNS-over-HTTPS usually "
     "still works since it rides on 443."),
    ("WhatsApp (g.whatsapp.net:5222)", "g.whatsapp.net", 5222,
     "WhatsApp's chat port is blocked; the app usually falls back to 443, "
     "but calls may fail. A VPN restores full function."),
]


def _connect_v4(host, port, timeout=TIMEOUT):
    """TCP connect forcing IPv4.

    Port-blocking must be tested deterministically: create_connection may
    pick an IPv6 address first and time out on networks with a broken v6
    path, which would look like a blocked port.
    """
    addr = socket.getaddrinfo(host, port, socket.AF_INET,
                              socket.SOCK_STREAM)[0][4]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(addr)


def _check_tcp(svc):
    name, host, port, advice = svc
    # Two attempts: one lost packet must not be reported as "blocked".
    for _ in range(2):
        try:
            _connect_v4(host, port)
            return (name, True, advice)
        except OSError:
            continue
    return (name, False, advice)


def check_udp_dns():
    """UDP 53 to a public resolver — verifiable because we get an answer."""
    return dnscheck.query("example.com", "8.8.8.8", timeout=TIMEOUT) is not None


def check_ntp(host="time.apple.com"):
    """UDP 123 — send a real NTP client request and wait for the reply."""
    packet = b"\x1b" + 47 * b"\x00"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        s.sendto(packet, (host, 123))
        data, _ = s.recvfrom(512)
        return len(data) >= 48 and struct.unpack(">B", data[:1])[0] != 0
    except OSError:
        return False
    finally:
        s.close()


def collect(report):
    """Check all services concurrently. Returns findings dict."""
    findings = {"blocked": [], "open": []}

    with ThreadPoolExecutor(max_workers=len(TCP_SERVICES)) as pool:
        tcp_future = pool.map(_check_tcp, TCP_SERVICES)
        results = list(tcp_future)

    for name, is_open, advice in results:
        if is_open:
            findings["open"].append(name)
            report.add(name, "ok", "reachable")
        else:
            findings["blocked"].append(name)
            report.add(name, "fail", "blocked or filtered", advice)

    if check_udp_dns():
        findings["open"].append("UDP DNS")
        report.add("UDP — DNS (8.8.8.8:53)", "ok", "reachable")
    else:
        findings["blocked"].append("UDP DNS")
        report.add(
            "UDP — DNS (8.8.8.8:53)", "fail", "blocked or filtered",
            "UDP to public DNS is blocked — common on restrictive networks. "
            "VPNs that use UDP (WireGuard, OpenVPN/UDP) will likely fail "
            "too; try a TCP-based VPN on port 443.",
        )

    if check_ntp():
        report.add("UDP — NTP time sync (123)", "ok", "reachable")
    else:
        findings["blocked"].append("NTP")
        report.add(
            "UDP — NTP time sync (123)", "warn", "blocked or filtered",
            "Time sync is blocked. If your clock drifts, HTTPS sites may "
            "show certificate errors.",
        )

    return findings
