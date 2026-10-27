"""Discover devices on the local /24 network.

Probes every host concurrently on a handful of common ports, then enriches
with the system ARP table (which also catches devices that answered ARP but
have no open ports).
"""

import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .netinfo import get_local_ip

PROBE_PORTS = [80, 443, 22, 445, 8080, 62078]  # web, ssh, smb, alt-web, iOS
TIMEOUT = 0.4
# Next to the per-network history, not wherever the command was run from.
OUTPUT_FILE = os.path.expanduser("~/.network-manager/scans/network_devices.txt")


def _probe_host(ip):
    """Return ip if any probe port accepts a connection, else None."""
    for port in PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=TIMEOUT):
                return ip
        except OSError:
            continue
    return None


def _arp_table():
    """Parse `arp -a` into {ip: mac} (macOS and Linux share this format)."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    table = {}
    for line in out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)", line)
        if m:  # "(incomplete)" entries never match the MAC pattern
            table[m.group(1)] = m.group(2)
    return table


def _hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def discover_network():
    """Scan the local /24. Returns a list of dicts with ip/mac/hostname."""
    local_ip = get_local_ip()
    if not local_ip:
        return []
    prefix = ".".join(local_ip.split(".")[:-1])
    candidates = [f"{prefix}.{host}" for host in range(1, 255)]

    with ThreadPoolExecutor(max_workers=64) as pool:
        alive = {ip for ip in pool.map(_probe_host, candidates) if ip}

    # The probing itself populates the ARP cache; merge whatever ARP knows.
    arp = _arp_table()
    alive |= {ip for ip in arp if ip.startswith(prefix + ".")}
    alive.discard(f"{prefix}.255")
    # We rarely answer our own probes or sit in our own ARP table.
    alive.add(local_ip)

    def sort_key(ip):
        return int(ip.split(".")[-1])

    with ThreadPoolExecutor(max_workers=32) as pool:
        hostnames = dict(zip(sorted(alive, key=sort_key),
                             pool.map(_hostname, sorted(alive, key=sort_key))))

    devices = []
    for ip in sorted(alive, key=sort_key):
        devices.append({
            "ip": ip,
            "mac": arp.get(ip),
            "hostname": hostnames.get(ip)
            or (socket.gethostname() if ip == local_ip else None),
            "is_you": ip == local_ip,
        })

    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, "w") as f:
            for d in devices:
                f.write(f"{d['ip']}\t{d['mac'] or '-'}\t{d['hostname'] or '-'}\n")
    except OSError:
        pass  # saving a copy is a convenience; the scan result still stands

    return devices


def collect(report):
    devices = discover_network()
    if not devices:
        report.add("Local network scan", "fail", "no devices found (offline?)")
        return {"devices": []}
    report.add("Local network scan", "info", f"{len(devices)} device(s) found")
    for d in devices:
        label = d["hostname"] or d["mac"] or "unknown device"
        suffix = "  ← this machine" if d["is_you"] else ""
        report.add(f"  {d['ip']}", "info", f"{label}{suffix}")
    return {"devices": devices}
