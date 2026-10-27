"""network-manager — fast diagnosis of unfamiliar networks.

Built for travel: quickly answers "what's wrong with this Wi-Fi?" —
captive portals, hijacked DNS, blocked services, slow links.

Usage (installed as `network-manager`; from a clone, `python3 main.py`):
    python main.py              # full diagnosis (default)
    python main.py portal       # captive portal / TLS interception only
    python main.py dns          # DNS health only
    python main.py services     # which ports/services are blocked
    python main.py speed        # download/upload speed + latency under load
    python main.py scan         # discover devices on the local network
    python main.py watch        # live stability monitor (Ctrl-C to stop)
    python main.py gui          # open the web GUI in your browser
    python main.py --json       # full diagnosis, JSON output
    python main.py --open       # open the portal login page, wait for you to
                                # log in, then finish the check

Requires only the Python standard library — nothing to install.
"""

import argparse
import json
import sys
import time
import webbrowser

from . import __version__, captive, dnscheck, gui, history
from . import network_discovery, services, speed, verdict, watch
from .fullcheck import run_full
from .reporting import Report, bold, cyan

LOGIN_TIMEOUT = 600  # seconds to wait for a captive portal login


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
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("--speed", action="store_true",
                        help="include a speed test (download, upload, latency under load)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="print results as JSON instead of the report")
    parser.add_argument("--open", action="store_true", dest="open_portal",
                        help="open the captive portal login page, wait for you "
                             "to log in, then run the check again")
    parser.add_argument("--no-wait", action="store_true",
                        help="with --open: just open the page, don't wait")
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

    start = time.monotonic()
    if not args.as_json:
        print(bold("network-manager") + " — diagnosing the current network…")
    report = Report(quiet=args.as_json)
    findings, diagnosis = run_command(args, report)

    portal_url = captive.login_url(
        (findings.get("portal") or findings) if isinstance(findings, dict) else {})
    if args.open_portal and portal_url:
        webbrowser.open(portal_url)
        say(args, cyan(f"\n  Opened portal login page: {portal_url}"))
        if not args.no_wait and _wait_for_login(args):
            # The network behind the portal is a different network: start over.
            say(args, cyan("  Logged in — running the check again.\n"))
            start = time.monotonic()
            report = Report(quiet=args.as_json)
            findings, diagnosis = run_command(args, report)

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


def say(args, message):
    """Progress messages: stdout normally, stderr in --json mode so the
    JSON on stdout stays parseable."""
    print(message, file=sys.stderr if args.as_json else sys.stdout, flush=True)


def _wait_for_login(args):
    """Wait for the portal to clear. True if it did."""
    minutes = LOGIN_TIMEOUT // 60
    say(args, f"  Waiting for you to log in (up to {minutes} min, "
              "Ctrl-C to stop waiting)…")
    try:
        cleared = captive.wait_for_login(timeout=LOGIN_TIMEOUT)
    except KeyboardInterrupt:
        say(args, "\n  Stopped waiting.")
        return False
    if not cleared:
        say(args, f"  Still behind the portal after {minutes} min — stopped waiting.")
    return cleared


def run_command(args, report):
    """Run one diagnosis command. Returns (findings, verdict or None)."""
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
    return findings, diagnosis

