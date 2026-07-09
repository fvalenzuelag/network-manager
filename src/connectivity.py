"""Basic connectivity: gateway reachability, raw internet access, latency.

The internet check uses a direct IP (no DNS) so we can tell "no internet"
apart from "DNS is broken".
"""

import socket
import statistics
import subprocess
import sys
import time

LATENCY_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 443)]


def ping(host, count=2, timeout_s=2):
    """Ping via the system binary. Returns average ms, or None."""
    if sys.platform == "darwin":
        cmd = ["ping", "-c", str(count), "-t", str(timeout_s * count), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout_s), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout_s * count + 2)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    for line in out.stdout.splitlines():
        if "min/avg/max" in line:
            try:
                return float(line.split("=")[1].split("/")[1])
            except (IndexError, ValueError):
                pass
    return 0.0  # replied, but couldn't parse the time


def tcp_connect_ms(host, port, timeout=3.0):
    """Time a TCP connection in ms, or None if it failed."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.monotonic() - start) * 1000
    except OSError:
        return None


def check_ipv6():
    """Returns 'ok', 'broken', or 'none'.

    'broken' means the system believes it has IPv6 (global address present)
    but v6 connections fail — the worst case, because apps waste seconds
    timing out on v6 before falling back to v4.
    """
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.connect(("2606:4700:4700::1111", 443))  # no packets sent
            addr = s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "none"
    if addr.startswith(("fe80", "::")):
        return "none"
    for host in ("2606:4700:4700::1111", "2001:4860:4860::8888"):
        try:
            with socket.create_connection((host, 443), timeout=3):
                return "ok"
        except OSError:
            continue
    return "broken"


def internet_latency(samples=3):
    """Median TCP-connect latency to public anchors, or None if offline."""
    times = []
    for host, port in LATENCY_TARGETS:
        for _ in range(samples):
            ms = tcp_connect_ms(host, port, timeout=3)
            if ms is not None:
                times.append(ms)
    return statistics.median(times) if times else None


def collect(report, gateway=None):
    """Run connectivity checks. Returns findings dict."""
    findings = {}

    if gateway:
        # First ping after joining a network can fail on ARP warm-up alone,
        # so give it a second chance before reporting a problem.
        ms = ping(gateway)
        if ms is None:
            ms = ping(gateway)
        findings["gateway_reachable"] = ms is not None
        if ms is not None:
            report.add("Gateway (router)", "ok", f"reachable, {ms:.0f} ms")
        else:
            report.add(
                "Gateway (router)", "warn", "not answering ping",
                "The router isn't answering ping — it may just block ICMP; "
                "if everything else fails too, reconnect to the network.",
            )

    # Direct-to-IP check: works even when DNS is completely broken.
    online = tcp_connect_ms("1.1.1.1", 443) is not None or \
        tcp_connect_ms("8.8.8.8", 443) is not None
    findings["internet"] = online
    if online:
        report.add("Internet (direct IP, no DNS)", "ok", "reachable")

        ipv6 = check_ipv6()
        findings["ipv6"] = ipv6
        if ipv6 == "ok":
            report.add("IPv6", "ok", "working")
        elif ipv6 == "broken":
            report.add(
                "IPv6", "warn", "configured but not working",
                "This network advertises IPv6 but v6 connections fail — "
                "sites may take seconds to load while apps time out and "
                "fall back to IPv4. Disabling IPv6 on this connection can "
                "make everything feel faster.",
            )
        else:
            report.add("IPv6", "info", "not available (IPv4 only — fine)")

        latency = internet_latency()
        findings["latency_ms"] = latency
        if latency is not None:
            if latency < 100:
                report.add("Latency", "ok", f"{latency:.0f} ms")
            elif latency < 300:
                report.add(
                    "Latency", "warn", f"{latency:.0f} ms (slow)",
                    "High latency — typical of congested or satellite links. "
                    "Video calls may struggle.",
                )
            else:
                report.add(
                    "Latency", "warn", f"{latency:.0f} ms (very slow)",
                    "Very high latency (satellite/in-flight grade). Prefer "
                    "async work; avoid video calls.",
                )
    else:
        report.add(
            "Internet (direct IP, no DNS)", "fail", "no route to the internet",
            "No internet access at the IP level. If a captive portal was "
            "detected, log in first; otherwise reconnect or try another network.",
        )

    return findings
