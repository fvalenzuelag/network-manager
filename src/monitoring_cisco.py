"""Monitor status of Cisco IOS devices over SSH.

Standalone helper for managed networks — not part of the travel diagnosis
flow. Device list comes from environment variables:

    CISCO_HOSTS     comma-separated, e.g. "10.0.0.1,10.0.0.2"
    CISCO_USERNAME  defaults to "admin"
    CISCO_PASSWORD

Run:  python -m src.monitoring_cisco   (requires: pip install netmiko)
"""

import os
import sys
from datetime import datetime

from netmiko import ConnectHandler

from .monitoring_unifi import load_env


def get_device_status(device):
    try:
        conn = ConnectHandler(**device)
        hostname = conn.send_command("show run | inc hostname")
        hostname = hostname.split("hostname ")[1].strip()

        uptime = conn.send_command("show ver | inc uptime")
        uptime = uptime.split("uptime is")[1].strip()

        cpu_mem = conn.send_command("show proc cpu | exc CPU").split("\n")
        cpu_util = cpu_mem[1].split(":")[1].strip()
        mem_util = cpu_mem[2].split(":")[1].strip()

        conn.disconnect()
        return {"hostname": hostname, "uptime": uptime,
                "cpu_util": cpu_util, "mem_util": mem_util}
    except Exception as e:
        print(f"Error connecting to {device['host']}: {e}")
        return None


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
