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
    """Returns (name, 'open'|'blocked'|'unresolved', advice)."""
    name, host, port, advice = svc
    # Two attempts: one lost packet must not be reported as "blocked".
    for _ in range(2):
        try:
            _connect_v4(host, port)
            return (name, "open", advice)
        except socket.gaierror:
            # A DNS failure says nothing about the port — don't call it
            # blocked (history would then report it as newly unblocked).
            return (name, "unresolved", advice)
        except OSError:
            continue
    return (name, "blocked", advice)


def check_udp_dns():
    """UDP 53 to a public resolver — verifiable because we get an answer."""
    return dnscheck.query("example.com", "8.8.8.8", timeout=TIMEOUT) is not None


def check_ntp(host="time.apple.com"):
    """UDP 123 — send a real NTP client request and wait for the reply.

    Returns True/False, or None if the host name doesn't resolve.
    """
    try:
        addr = socket.getaddrinfo(host, 123, socket.AF_INET,
                                  socket.SOCK_DGRAM)[0][4]
    except socket.gaierror:
        return None
    packet = b"\x1b" + 47 * b"\x00"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        s.sendto(packet, addr)
        data, _ = s.recvfrom(512)
        return len(data) >= 48 and struct.unpack(">B", data[:1])[0] != 0
    except OSError:
        return False
    finally:
        s.close()


def _unresolved(report, findings, name):
    findings["unresolved"].append(name)
    report.add(name, "info", "not tested — server name didn't resolve",
               "DNS failed for this check's server, so port blocking "
               "couldn't be tested; fix DNS first.")


def collect(report):
    """Check all services concurrently. Returns findings dict."""
    findings = {"blocked": [], "open": [], "unresolved": []}

    with ThreadPoolExecutor(max_workers=len(TCP_SERVICES)) as pool:
        tcp_future = pool.map(_check_tcp, TCP_SERVICES)
        results = list(tcp_future)

    for name, state, advice in results:
        if state == "open":
            findings["open"].append(name)
            report.add(name, "ok", "reachable")
        elif state == "unresolved":
            _unresolved(report, findings, name)
        else:
            findings["blocked"].append(name)
            report.add(name, "fail", "blocked or filtered", advice)

    # UDP probes get the same one-lost-packet tolerance as the TCP checks.
    udp_dns_name = "UDP — DNS (8.8.8.8:53)"
    if any(check_udp_dns() for _ in range(2)):
        findings["open"].append(udp_dns_name)
        report.add(udp_dns_name, "ok", "reachable")
    else:
        findings["blocked"].append(udp_dns_name)
        report.add(
            udp_dns_name, "fail", "blocked or filtered",
            "UDP to public DNS is blocked — common on restrictive networks. "
            "VPNs that use UDP (WireGuard, OpenVPN/UDP) will likely fail "
            "too; try a TCP-based VPN on port 443.",
        )

    ntp_name = "UDP — NTP time sync (123)"
    ntp = check_ntp()
    if ntp is False:  # retry only a lost reply, not a DNS failure
        ntp = check_ntp()
    if ntp:
        findings["open"].append(ntp_name)
        report.add(ntp_name, "ok", "reachable")
    elif ntp is None:
        _unresolved(report, findings, ntp_name)
    else:
        findings["blocked"].append(ntp_name)
        report.add(
            ntp_name, "warn", "blocked or filtered",
            "Time sync is blocked. If your clock drifts, HTTPS sites may "
            "show certificate errors.",
        )

    return findings
