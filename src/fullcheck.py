"""The full diagnosis flow, shared by the CLI (main.py) and the GUI."""

import sys
from concurrent.futures import ThreadPoolExecutor

from . import captive, connectivity, dnscheck, geo, netinfo, services
from . import speed, wifi
from .reporting import cyan


def run_full(report, include_speed=False):
    findings = {}

    # system_profiler takes ~2 s on macOS; fetch it while other checks run.
    pool = ThreadPoolExecutor(max_workers=1)
    wifi_future = pool.submit(wifi.get_link_info)

    report.section("Network")
    findings["network"] = netinfo.collect(report)
    findings["wifi"] = wifi.collect(report, wifi_future.result())
    pool.shutdown()

    report.section("Connectivity")
    findings["connectivity"] = connectivity.collect(
        report, gateway=findings["network"].get("gateway"))

    # If there is no internet at the IP level, portal/DNS/service checks
    # would all fail for the same root cause — still run the portal check
    # (a portal is the most likely explanation), skip the rest.
    online = findings["connectivity"].get("internet", False)

    report.section("Captive portal & interception")
    findings["portal"] = captive.collect(report)

    if online and not findings["portal"].get("captive_portal"):
        report.section("DNS")
        findings["dns"] = dnscheck.collect(report)

        report.section("Public egress")
        findings["egress"] = geo.collect(report)

        report.section("Services & ports")
        findings["services"] = services.collect(report)

        if include_speed:
            report.section("Speed")
            findings["speed"] = speed.collect(report)
    elif findings["portal"].get("captive_portal") and not report.quiet:
        print(cyan("\n  Skipping DNS/service checks until you log in to the portal."))

    return findings
