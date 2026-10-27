"""Live connection monitor: is this network stable *right now*?

Prints one line per tick — gateway ping, internet TCP connect, DNS query —
so on flaky Wi-Fi (planes, trains, crowded lounges) you can see when and
where it drops. Ctrl-C prints an availability summary.
"""

import time
from datetime import datetime

from . import dnscheck, netinfo
from .connectivity import ping, tcp_connect_ms
from .reporting import bold, dim, green, red, yellow


def _fmt(ms, warn_at=150):
    if ms is None:
        return red("  lost")
    color = green if ms < warn_at else yellow
    return color(f"{ms:>4.0f}ms")


def _dns_ms(server, timeout=2.0):
    start = time.monotonic()
    if dnscheck.query("example.com", server, timeout=timeout) is None:
        return None
    return (time.monotonic() - start) * 1000


def run(interval=5.0):
    gateway, _ = netinfo.get_default_route()
    # Our tiny DNS client speaks IPv4 UDP, so pick an IPv4 resolver.
    dns_server = next((s for s in netinfo.get_dns_servers() if "." in s), None)

    targets = f"gateway {gateway or '—'}, internet 1.1.1.1:443, dns {dns_server or '—'}"
    print(bold("watch") + f" — probing every {interval:g}s ({targets}). Ctrl-C to stop.\n")

    ticks = 0
    lost = {"gateway": 0, "internet": 0, "dns": 0}
    outages = 0
    in_outage = False
    started = time.monotonic()

    try:
        while True:
            tick_start = time.monotonic()
            gw_ms = ping(gateway, count=1, timeout_s=2) if gateway else None
            net_ms = tcp_connect_ms("1.1.1.1", 443, timeout=2)
            dns_ms = _dns_ms(dns_server) if dns_server else None

            ticks += 1
            lost["gateway"] += gateway is not None and gw_ms is None
            lost["internet"] += net_ms is None
            lost["dns"] += dns_server is not None and dns_ms is None

            line = (f"{datetime.now():%H:%M:%S}  "
                    f"gateway {_fmt(gw_ms, warn_at=50)}   "
                    f"internet {_fmt(net_ms)}   "
                    f"dns {_fmt(dns_ms)}")
            if net_ms is None:
                if not in_outage:
                    outages += 1
                in_outage = True
                line += red("   ← OFFLINE")
            else:
                in_outage = False
            print(line, flush=True)

            time.sleep(max(0.0, interval - (time.monotonic() - tick_start)))
    except KeyboardInterrupt:
        print()

    if ticks == 0:
        return
    elapsed = time.monotonic() - started
    availability = 100 * (1 - lost["internet"] / ticks)
    print(bold("Session summary") + dim(f"  ({elapsed:.0f}s, {ticks} samples)"))
    color = green if availability >= 99 else (yellow if availability >= 90 else red)
    print(f"  Internet availability: {color(f'{availability:.0f}%')}"
          + (f", {outages} outage(s)" if outages else ""))
    for name, label in (("gateway", "Gateway"), ("dns", "DNS")):
        if lost[name]:
            print(f"  {label}: {lost[name]}/{ticks} probes failed")
