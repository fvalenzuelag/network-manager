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
    python main.py watch        # live stability monitor (Ctrl-C to stop)
    python main.py gui          # open the web GUI in your browser
    python main.py --json       # full diagnosis, JSON output
    python main.py --open       # auto-open the captive portal login page

Requires only the Python standard library — nothing to install.
"""

import argparse
import json
import sys
import time
import webbrowser

from src import captive, dnscheck, gui, history
from src import network_discovery, services, speed, verdict, watch
from src.fullcheck import run_full
from src.reporting import Report, bold, cyan


def main():
    parser = argparse.ArgumentParser(
        prog="network-manager",
        description="Diagnose what's wrong (or right) with the current network.",
    )
    parser.add_argument(
        "command", nargs="?", default="check",
        choices=["check", "portal", "dns", "services", "speed", "scan",
                 "watch", "gui"],
        help="what to run (default: full check)",
    )
    parser.add_argument("--speed", action="store_true",
                        help="include a download speed test in the full check")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="print results as JSON instead of the report")
    parser.add_argument("--open", action="store_true", dest="open_portal",
                        help="open the captive portal login page in the browser")
    parser.add_argument("-i", "--interval", type=float, default=5.0,
                        help="probe interval in seconds for watch (default: 5)")
    parser.add_argument("--port", type=int, default=8765,
                        help="port for the gui server (default: 8765)")
    parser.add_argument("--no-browser", action="store_true",
                        help="gui: don't auto-open the browser")
    args = parser.parse_args()

    if args.command == "watch":
        try:
            watch.run(interval=max(1.0, args.interval))
        except KeyboardInterrupt:
            pass
        return 0

    if args.command == "gui":
        gui.serve(port=args.port, open_browser=not args.no_browser)
        return 0

    report = Report(quiet=args.as_json)

    start = time.monotonic()
    if not args.as_json:
        print(bold("network-manager") + " — diagnosing the current network…")

    diagnosis = None
    if args.command == "check":
        findings = run_full(report, include_speed=args.speed)
        history.compare(report, findings)
        diagnosis = verdict.diagnose(findings)
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

    portal_url = (findings.get("portal") or findings).get("portal_url") \
        if isinstance(findings, dict) else None
    if args.open_portal and portal_url:
        webbrowser.open(portal_url)
        if not args.as_json:
            print(cyan(f"\n  Opened portal login page: {portal_url}"))

    elapsed = time.monotonic() - start
    if args.as_json:
        payload = {"findings": findings, **report.to_dict(),
                   "elapsed_seconds": round(elapsed, 1)}
        if diagnosis:
            status, headline, action = diagnosis
            payload["verdict"] = {"status": status, "headline": headline,
                                  "action": action}
        print(json.dumps(payload, indent=2, default=str))
    else:
        report.summary(verdict=diagnosis)
        print(f"\n  Done in {elapsed:.1f}s.")

    # Exit code 1 if any hard failures — usable in scripts.
    return 1 if any(r.status == "fail" for r in report.results) else 0


if __name__ == "__main__":
    sys.exit(main())
