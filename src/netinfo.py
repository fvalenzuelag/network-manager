"""Local network information: interface, SSID, IP, gateway, DNS servers.

Everything here is read-only and uses OS tools available out of the box
(macOS and Linux supported, degrades gracefully elsewhere).
"""

import re
import socket
import subprocess
import sys


def _run(cmd, timeout=5):
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return out.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def get_local_ip():
    """Local IP of the interface that would route to the internet.

    Uses a connected UDP socket — no packet is actually sent.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def get_default_route():
    """Return (gateway_ip, interface) for the default route, or (None, None)."""
    if sys.platform == "darwin":
        out = _run(["route", "-n", "get", "default"])
        gw = re.search(r"gateway:\s*(\S+)", out)
        iface = re.search(r"interface:\s*(\S+)", out)
        return (gw.group(1) if gw else None, iface.group(1) if iface else None)
    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\S+) dev (\S+)", out)
    return (m.group(1), m.group(2)) if m else (None, None)


def get_dns_servers():
    """DNS servers currently configured on the system."""
    servers = []
    if sys.platform == "darwin":
        out = _run(["scutil", "--dns"])
        servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out)
    else:
        try:
            with open("/etc/resolv.conf") as f:
                servers = re.findall(r"^nameserver\s+(\S+)", f.read(), re.M)
        except OSError:
            pass
    # Deduplicate preserving order
    return list(dict.fromkeys(servers))


def get_ssid(interface=None):
    """Current Wi-Fi network name, if connected via Wi-Fi (macOS only)."""
    if sys.platform != "darwin":
        return None
    interface = interface or "en0"
    out = _run(["ipconfig", "getsummary", interface])
    m = re.search(r"^\s+SSID\s*:\s*(.+)$", out, re.M)
    if m:
        return m.group(1).strip()
    out = _run(["networksetup", "-getairportnetwork", interface])
    m = re.search(r"Current Wi-Fi Network:\s*(.+)", out)
    return m.group(1).strip() if m else None


def collect(report):
    """Print local network info and flag obvious problems."""
    gateway, iface = get_default_route()
    local_ip = get_local_ip()
    ssid = get_ssid(iface)
    dns = get_dns_servers()

    if ssid:
        report.add("Wi-Fi network", "info", ssid)
    if iface:
        report.add("Interface", "info", iface)

    if local_ip:
        status = "ok"
        detail = local_ip
        advice = ""
        if local_ip.startswith("169.254."):
            status, advice = "fail", (
                "You have a self-assigned IP: DHCP failed. Reconnect to the "
                "network or renew the DHCP lease."
            )
            detail += " (self-assigned — no DHCP)"
        report.add("Local IP", status, detail, advice)
    else:
        report.add(
            "Local IP", "fail", "no IP address",
            "You are not connected to any network. Check Wi-Fi is on and connected.",
        )

    if gateway:
        report.add("Gateway", "info", gateway)
    else:
        report.add(
            "Gateway", "fail", "no default route",
            "No route to the internet. Reconnect to the network.",
        )

    if dns:
        report.add("DNS servers", "info", ", ".join(dns))
    else:
        report.add(
            "DNS servers", "fail", "none configured",
            "No DNS configured — set a public resolver like 1.1.1.1 manually.",
        )

    return {"ssid": ssid, "interface": iface, "local_ip": local_ip,
            "gateway": gateway, "dns_servers": dns}
