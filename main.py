#!/usr/bin/env python3
"""network-manager — fast diagnosis of unfamiliar networks.

Built for travel: quickly answers "what's wrong with this Wi-Fi?" —
captive portals, hijacked DNS, blocked services, slow links.

Usage:
    python main.py              # full diagnosis (default)
    python main.py portal       # captive portal / TLS interception only
    python main.py dns          # DNS health only
    python main.py services     # which ports/services are blocked
    python main.py speed        # quick download speed estimate
    python main.py scan         # discover devices on the local network
    python main.py --json       # full diagnosis, JSON output

Requires only the Python standard library — nothing to install.
"""

import argparse
import json
import sys
import time

from src import captive, connectivity, dnscheck, netinfo, services, speed
from src import network_discovery
from src.reporting import Report, bold, cyan


def run_full(report, include_speed=False):
    findings = {}

    report.section("Network")
    findings["network"] = netinfo.collect(report)

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

        report.section("Services & ports")
        findings["services"] = services.collect(report)

        if include_speed:
            report.section("Speed")
            findings["speed"] = speed.collect(report)
    elif findings["portal"].get("captive_portal"):
        print(cyan("\n  Skipping DNS/service checks until you log in to the portal."))

    return findings


def main():
    parser = argparse.ArgumentParser(
        prog="network-manager",
        description="Diagnose what's wrong (or right) with the current network.",
    )
    parser.add_argument(
        "command", nargs="?", default="check",
        choices=["check", "portal", "dns", "services", "speed", "scan"],
        help="what to run (default: full check)",
    )
    parser.add_argument("--speed", action="store_true",
                        help="include a download speed test in the full check")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="print results as JSON instead of the report")
    args = parser.parse_args()

    report = Report()
    if args.as_json:
        # Silence the live output; we only want the JSON at the end.
        import src.reporting as reporting
        reporting.print_result = lambda r: None
        report.section = lambda title: None

    start = time.monotonic()
    if not args.as_json:
        print(bold("network-manager") + " — diagnosing the current network…")

    if args.command == "check":
        findings = run_full(report, include_speed=args.speed)
    elif args.command == "portal":
        report.section("Captive portal & interception")
        findings = captive.collect(report)
    elif args.command == "dns":
        report.section("DNS")
        findings = dnscheck.collect(report)
    elif args.command == "services":
        report.section("Services & ports")
        findings = services.collect(report)
    elif args.command == "speed":
        report.section("Speed")
        findings = speed.collect(report)
    elif args.command == "scan":
        report.section("Local network scan")
        findings = network_discovery.collect(report)

    elapsed = time.monotonic() - start
    if args.as_json:
        print(json.dumps({"findings": findings, **report.to_dict(),
                          "elapsed_seconds": round(elapsed, 1)},
                         indent=2, default=str))
    else:
        report.summary()
        print(f"\n  Done in {elapsed:.1f}s.")

    # Exit code 1 if any hard failures — usable in scripts.
    return 1 if any(r.status == "fail" for r in report.results) else 0


if __name__ == "__main__":
    sys.exit(main())
