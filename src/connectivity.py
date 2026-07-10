"""Basic connectivity: gateway reachability, raw internet access, latency.

The internet check uses a direct IP (no DNS) so we can tell "no internet"
apart from "DNS is broken".
"""

import re
import socket
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

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


def packet_loss(host, count=15, interval=0.2):
    """Send a quick ping burst and return the loss percentage.

    Returns None when nothing came back at all — that means ICMP is blocked
    or the host is down, which is not the same signal as partial loss.
    (0.2 s is the shortest interval allowed without root on macOS/Linux.)
    """
    cmd = ["ping", "-c", str(count), "-i", str(interval), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=count * interval + 8)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"([\d.]+)% packet loss", out.stdout)
    if not m:
        return None
    loss = float(m.group(1))
    return None if loss >= 100 else loss


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

        # Measure loss to the gateway and to the internet in parallel:
        # loss to the gateway = bad Wi-Fi link; loss only beyond it = the
        # venue's uplink is the problem and nothing local will help.
        with ThreadPoolExecutor(max_workers=2) as pool:
            gw_future = pool.submit(packet_loss, gateway) if gateway else None
            net_future = pool.submit(packet_loss, "1.1.1.1")
            gw_loss = gw_future.result() if gw_future else None
            net_loss = net_future.result()
        findings["loss_gateway_pct"] = gw_loss
        findings["loss_internet_pct"] = net_loss

        if gw_loss is not None:
            if gw_loss >= 5:
                report.add(
                    "Packet loss — Wi-Fi link", "warn", f"{gw_loss:.0f}% to gateway",
                    "Your link to the router is dropping packets — usually "
                    "weak signal. Move closer to the access point.",
                )
            else:
                report.add("Packet loss — Wi-Fi link", "ok", f"{gw_loss:.0f}%")
        if net_loss is not None:
            if net_loss >= 5 and (gw_loss is None or gw_loss < 5):
                report.add(
                    "Packet loss — internet path", "warn", f"{net_loss:.0f}%",
                    "Packets are lost beyond the router — the venue's uplink "
                    "is congested. Moving around won't help; expect dropped "
                    "calls, retry later or use mobile data.",
                )
            elif net_loss >= 5:
                report.add("Packet loss — internet path", "warn", f"{net_loss:.0f}%")
            else:
                report.add("Packet loss — internet path", "ok", f"{net_loss:.0f}%")
        elif gw_loss is not None:
            report.add("Packet loss — internet path", "info",
                       "can't measure (ICMP blocked upstream)")
    else:
        report.add(
            "Internet (direct IP, no DNS)", "fail", "no route to the internet",
            "No internet access at the IP level. If a captive portal was "
            "detected, log in first; otherwise reconnect or try another network.",
        )

    return findings
