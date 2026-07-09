"""Per-network history: remember what each network looked like last time.

Every full check saves a compact snapshot to ~/.network-manager/history/,
one JSON file per network (keyed by SSID, falling back to gateway IP).
On the next visit the tool reports what changed — "SSH worked here last
week, now it's blocked" is a much stronger signal than a bare failure.
"""

import json
import os
import re
from datetime import datetime, timezone

HISTORY_DIR = os.path.expanduser("~/.network-manager/history")
MAX_RUNS = 50


def _network_key(network):
    name = network.get("ssid")
    if not name and network.get("gateway"):
        name = f"gateway-{network['gateway']}"
    if not name:
        return None
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


def _path(key):
    return os.path.join(HISTORY_DIR, f"{key}.json")


def snapshot(findings):
    """Flatten a full-check findings dict into a compact comparable record."""
    conn = findings.get("connectivity", {})
    services = findings.get("services")
    speed = findings.get("speed") or {}
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "internet": conn.get("internet"),
        "latency_ms": conn.get("latency_ms"),
        "ipv6": conn.get("ipv6"),
        "loss_gateway_pct": conn.get("loss_gateway_pct"),
        "loss_internet_pct": conn.get("loss_internet_pct"),
        "captive_portal": findings.get("portal", {}).get("captive_portal"),
        "blocked": sorted(services["blocked"]) if services else None,
        "open": sorted(services["open"]) if services else None,
        "download_mbps": speed.get("download_mbps"),
    }


def load_runs(key):
    try:
        with open(_path(key)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def save_run(key, snap):
    os.makedirs(HISTORY_DIR, exist_ok=True)
    runs = load_runs(key) + [snap]
    with open(_path(key), "w") as f:
        json.dump(runs[-MAX_RUNS:], f, indent=1)


def _when(timestamp):
    """Humanize an ISO timestamp relative to now."""
    try:
        then = datetime.fromisoformat(timestamp)
    except ValueError:
        return "previously"
    days = (datetime.now(timezone.utc) - then).days
    if days <= 0:
        return "earlier today"
    if days == 1:
        return "yesterday"
    if days < 14:
        return f"{days} days ago"
    fmt = "on %b %d" if then.year == datetime.now(timezone.utc).year else "on %b %d, %Y"
    return then.strftime(fmt)


def compare(report, findings):
    """Compare this run to the previous visit on the same network, then save."""
    key = _network_key(findings.get("network", {}))
    if not key:
        return

    previous_runs = load_runs(key)
    snap = snapshot(findings)
    save_run(key, snap)

    report.section("Compared to last visit")
    if not previous_runs:
        report.add("History", "info", "first recorded visit — baseline saved")
        return

    prev = previous_runs[-1]
    when = _when(prev.get("timestamp", ""))
    changes = 0

    if snap["blocked"] is not None and prev.get("blocked") is not None:
        for name in sorted(set(snap["blocked"]) - set(prev["blocked"])):
            report.add(name, "warn", f"was reachable {when}, now blocked")
            changes += 1
        for name in sorted(set(prev["blocked"]) - set(snap["blocked"])):
            report.add(name, "info", f"was blocked {when}, now reachable")
            changes += 1

    if prev.get("captive_portal") is False and snap["captive_portal"]:
        report.add("Captive portal", "info",
                   f"portal is new — there was none {when}")
        changes += 1

    old_lat, new_lat = prev.get("latency_ms"), snap["latency_ms"]
    if old_lat and new_lat and new_lat > max(2 * old_lat, old_lat + 50):
        report.add("Latency", "warn",
                   f"{old_lat:.0f} ms {when} → {new_lat:.0f} ms now")
        changes += 1

    old_dl, new_dl = prev.get("download_mbps"), snap["download_mbps"]
    if old_dl and new_dl and new_dl < old_dl / 2:
        report.add("Download speed", "warn",
                   f"{old_dl:.0f} Mbps {when} → {new_dl:.0f} Mbps now")
        changes += 1

    if changes == 0:
        report.add("History", "info",
                   f"consistent with your last visit {when} "
                   f"({len(previous_runs) + 1} visits recorded)")
