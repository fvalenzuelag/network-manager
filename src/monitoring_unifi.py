"""Monitor device status on a UniFi Controller or UniFi OS console.

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

from .envfile import load_env


# Device `state` codes from the controller API. Only 1 means connected —
# e.g. 6 (heartbeat missed) is truthy but the device is effectively down.
DEVICE_STATES = {
    0: "DISCONNECTED",
    1: "CONNECTED",
    2: "PENDING ADOPTION",
    4: "UPGRADING",
    5: "PROVISIONING",
    6: "HEARTBEAT MISSED",
    7: "ADOPTING",
    11: "ISOLATED",
}


def device_status(state):
    return DEVICE_STATES.get(state, f"UNKNOWN (state {state})")


def _login(session, controller_url, username, password):
    """Log in, returning (api_prefix, logout) or None on failure.

    Classic controllers use /api/login; UniFi OS consoles (UDM, Cloud Key
    Gen2+) answer that with 404 and use /api/auth/login, with the network
    API under /proxy/network and a CSRF token required for logout.
    """
    creds = {"username": username, "password": password}
    login = session.post(f"{controller_url}/api/login", json=creds, timeout=10)
    if login.status_code == 200:
        return "", lambda: session.get(f"{controller_url}/api/logout", timeout=10)
    if login.status_code != 404:
        print(f"Failed to authenticate with the UniFi Controller "
              f"(HTTP {login.status_code}).")
        return None

    login = session.post(f"{controller_url}/api/auth/login", json=creds,
                         timeout=10)
    if login.status_code != 200:
        print(f"Failed to authenticate with the UniFi OS console "
              f"(HTTP {login.status_code}).")
        return None
    csrf = {"X-CSRF-Token": login.headers.get("X-CSRF-Token", "")}
    return "/proxy/network", lambda: session.post(
        f"{controller_url}/api/auth/logout", headers=csrf, timeout=10)


def monitor(controller_url, username, password, site="default", verify=True):
    session = requests.Session()
    session.verify = verify

    logged_in = _login(session, controller_url, username, password)
    if not logged_in:
        return 1
    prefix, logout = logged_in

    try:
        devices = session.get(
            f"{controller_url}{prefix}/api/s/{site}/stat/device", timeout=10
        ).json()["data"]
        for device in devices:
            print(f"Device: {device.get('name', '?')} "
                  f"({device.get('model', '?')}) - "
                  f"Status: {device_status(device.get('state'))}")
    finally:
        logout()
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
