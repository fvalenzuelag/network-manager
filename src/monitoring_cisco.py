"""Monitor status of Cisco IOS devices over SSH.

Standalone helper for managed networks — not part of the travel diagnosis
flow. Device list comes from environment variables:

    CISCO_HOSTS     comma-separated, e.g. "10.0.0.1,10.0.0.2"
    CISCO_USERNAME  defaults to "admin"
    CISCO_PASSWORD

Run:  python -m src.monitoring_cisco   (requires: pip install netmiko)
"""

import os
import re
import sys
from datetime import datetime

from netmiko import ConnectHandler

from .envfile import load_env


def parse_cpu(output):
    """'CPU utilization for five seconds: 5%/0%; one minute: 3%; five
    minutes: 2%' → '5% (5 s), 3% (1 min), 2% (5 min)', or None."""
    m = re.search(r"five seconds:\s*(\d+)%.*?one minute:\s*(\d+)%"
                  r".*?five minutes:\s*(\d+)%", output, re.S)
    if not m:
        return None
    return f"{m.group(1)}% (5 s), {m.group(2)}% (1 min), {m.group(3)}% (5 min)"


def parse_memory(output):
    """'Processor Pool Total: 816029576 Used: 246520824 Free: ...' →
    '30% of processor memory used', or None."""
    m = re.search(r"Processor Pool Total:\s*(\d+)\s+Used:\s*(\d+)", output)
    if not m or int(m.group(1)) == 0:
        return None
    return f"{100 * int(m.group(2)) / int(m.group(1)):.0f}% of processor memory used"


def get_device_status(device):
    try:
        conn = ConnectHandler(**device)
    except Exception as e:
        print(f"Error connecting to {device['host']}: {e}")
        return None
    try:
        hostname = conn.send_command("show run | include ^hostname")
        m = re.search(r"hostname\s+(\S+)", hostname)

        uptime = conn.send_command("show version | include uptime")
        u = re.search(r"uptime is\s+(.+)", uptime)

        cpu = conn.send_command("show processes cpu | include CPU utilization")
        mem = conn.send_command("show processes memory | include Processor")
        return {"hostname": m.group(1) if m else device["host"],
                "uptime": u.group(1).strip() if u else "?",
                "cpu_util": parse_cpu(cpu) or "?",
                "mem_util": parse_memory(mem) or "?"}
    except Exception as e:
        print(f"Error reading status from {device['host']}: {e}")
        return None
    finally:
        conn.disconnect()


def monitor_devices(devices):
    print(f"Monitoring started at {datetime.now():%Y-%m-%d %H:%M:%S}")
    for device in devices:
        status = get_device_status(device)
        if status:
            print(f"Device: {status['hostname']}")
            print(f"Uptime: {status['uptime']}")
            print(f"CPU Utilization: {status['cpu_util']}")
            print(f"Memory Utilization: {status['mem_util']}")
            print("-" * 30)


def main():
    load_env()
    hosts = os.environ.get("CISCO_HOSTS", "")
    password = os.environ.get("CISCO_PASSWORD")
    if not hosts or not password:
        print("Set CISCO_HOSTS and CISCO_PASSWORD (e.g. in .env) first.")
        return 1
    devices = [
        {
            "host": host.strip(),
            "device_type": "cisco_ios",
            "username": os.environ.get("CISCO_USERNAME", "admin"),
            "password": password,
        }
        for host in hosts.split(",") if host.strip()
    ]
    monitor_devices(devices)
    return 0


if __name__ == "__main__":
    sys.exit(main())
