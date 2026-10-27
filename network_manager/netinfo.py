"""Local network information: interface, SSID, IP, gateway, DNS servers.

Everything here is read-only and uses OS tools available out of the box
(macOS and Linux supported, degrades gracefully elsewhere).
"""

import re
import socket
import subprocess
import sys


# Tunnel interfaces of VPN clients (WireGuard, OpenVPN, IPsec, Tailscale,
# ZeroTier, GlobalProtect, …). When one carries the default route, every
# check measures the tunnel instead of the network you joined.
VPN_INTERFACE = re.compile(r"^(utun|tun|tap|wg|ppp|ipsec|tailscale|zt|gpd)\d*$")


def is_vpn_interface(iface):
    return bool(iface and VPN_INTERFACE.match(iface))


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
    # Point-to-point tunnels have no "via": "default dev wg0 scope link".
    m = re.search(r"default(?: via (\S+))? dev (\S+)", out)
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
    """Current Wi-Fi network name, if connected via Wi-Fi (macOS only).

    macOS 14.4+ hides the SSID from unprivileged tools ("<redacted>");
    that is treated as unknown, never as a real network name.
    """
    if sys.platform != "darwin":
        return None
    interface = interface or "en0"
    out = _run(["ipconfig", "getsummary", interface])
    m = re.search(r"^\s+SSID\s*:\s*(.+)$", out, re.M)
    if m and m.group(1).strip() != "<redacted>":
        return m.group(1).strip()
    out = _run(["networksetup", "-getairportnetwork", interface])
    m = re.search(r"Current Wi-Fi Network:\s*(.+)", out)
    return m.group(1).strip() if m else None


_MAC = r"[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}"

# Beyond this many other IPs sharing the router's MAC, the network is using
# proxy ARP (the router answers for everyone — common on hotel/enterprise
# Wi-Fi with client isolation), not one device impersonating it.
PROXY_ARP_MIN = 3


def _normalize_mac(mac):
    # macOS drops leading zeros ("a:b:c..."); normalize for stable compares.
    return ":".join(f"{int(b, 16):02x}" for b in mac.split(":"))


def arp_table():
    """The IPv4 ARP/neighbour cache as {ip: mac}, MACs normalized.

    Broadcast/multicast entries are skipped. `-n` avoids a reverse-DNS
    lookup per entry, which crawls on a network with broken DNS.
    """
    if sys.platform == "darwin":
        out = _run(["arp", "-an"], timeout=10)
        pairs = re.findall(rf"\((\d+\.\d+\.\d+\.\d+)\) at ({_MAC})\b", out)
    else:
        out = _run(["ip", "-4", "neigh", "show"], timeout=10)
        pairs = re.findall(rf"^(\d+\.\d+\.\d+\.\d+) .*?lladdr ({_MAC})\b",
                           out, re.M)
    table = {}
    for ip, mac in pairs:
        mac = _normalize_mac(mac)
        if int(mac[:2], 16) & 1:  # group bit: broadcast/multicast
            continue
        table[ip] = mac
    return table


def check_router_impersonation(report, gateway, gateway_mac, arp=None):
    """Flag other IPs claiming the router's MAC — the mark of ARP spoofing.

    Returns 'clean' | 'suspicious' | 'proxy_arp', or None if unknown.
    """
    if not gateway or not gateway_mac:
        return None
    arp = arp_table() if arp is None else arp
    others = sorted(ip for ip, mac in arp.items()
                    if mac == gateway_mac and ip != gateway)
    name = "Router impersonation (ARP)"
    if not others:
        report.add(name, "ok", "no other device claims the router's address")
        return "clean"
    if len(others) >= PROXY_ARP_MIN:
        report.add(name, "info",
                   f"can't check — the router answers for {len(others)} other "
                   "addresses (proxy ARP, common on hotel/enterprise Wi-Fi)")
        return "proxy_arp"
    report.add(
        name, "warn",
        f"the router's hardware address is also claimed by {', '.join(others)}",
        "Another device may be impersonating the router to intercept "
        "traffic (ARP spoofing). Don't log in to anything sensitive here; "
        "use a VPN or mobile data.",
    )
    return "suspicious"


def get_gateway_mac(gateway):
    """MAC address of the router from the ARP/neighbour cache, or None.

    Identifies a network far better than its gateway IP (192.168.1.1 is
    everywhere), and needs no privileges even where the SSID is hidden.
    """
    if not gateway:
        return None
    if sys.platform == "darwin":
        out = _run(["arp", "-n", gateway])
    else:
        out = _run(["ip", "neigh", "show", gateway])
    m = re.search(rf"\b({_MAC})\b", out)
    return _normalize_mac(m.group(1)) if m else None


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
    vpn = iface if is_vpn_interface(iface) else None
    if vpn:
        # The verdict carries the "disconnect it" action, so no advice here.
        report.add(
            "VPN", "warn",
            f"active ({vpn}) — the checks below test the VPN tunnel, "
            "not this network",
        )

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

    gateway_mac = get_gateway_mac(gateway)
    if gateway:
        report.add("Gateway", "info", gateway)
    elif vpn:
        report.add("Gateway", "info", "none (point-to-point VPN tunnel)")
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

    impersonation = check_router_impersonation(report, gateway, gateway_mac)

    return {"ssid": ssid, "interface": iface, "local_ip": local_ip,
            "gateway": gateway, "gateway_mac": gateway_mac,
            "router_impersonation": impersonation,
            "vpn_interface": vpn, "dns_servers": dns}
