"""Monitor device status on a UniFi Controller.

Standalone helper for managed (home/office) networks — not part of the
travel diagnosis flow. Credentials come from environment variables:

    UNIFI_URL       e.g. https://unifi.example.com:8443
    UNIFI_USERNAME  defaults to "admin"
    UNIFI_PASSWORD

Run:  python -m src.monitoring_unifi
"""

import os
import sys

import requests


def load_env(path=".env"):
    """Minimal .env loader (KEY='value' lines) so no dependency is needed."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    os.environ.setdefault(key.strip(), value.strip().strip("'\""))
    except OSError:
        pass


def monitor(controller_url, username, password, site="default", verify=True):
    session = requests.Session()
    session.verify = verify

    login = session.post(
        f"{controller_url}/api/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    if login.status_code != 200:
        print(f"Failed to authenticate with the UniFi Controller "
              f"(HTTP {login.status_code}).")
        return 1

    try:
        devices = session.get(
            f"{controller_url}/api/s/{site}/stat/device", timeout=10
        ).json()["data"]
        for device in devices:
            status = "CONNECTED" if device.get("state") else "DISCONNECTED"
            print(f"Device: {device.get('name', '?')} "
                  f"({device.get('model', '?')}) - Status: {status}")
    finally:
        session.get(f"{controller_url}/api/logout", timeout=10)
    return 0


def main():
    load_env()
    url = os.environ.get("UNIFI_URL")
    password = os.environ.get("UNIFI_PASSWORD")
    if not url or not password:
        print("Set UNIFI_URL and UNIFI_PASSWORD (e.g. in .env) first.")
        return 1
    return monitor(url, os.environ.get("UNIFI_USERNAME", "admin"), password)


if __name__ == "__main__":
    sys.exit(main())
