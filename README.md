# network-manager

Fast diagnosis of unfamiliar networks — built for travel.

When you land somewhere and connect to airport, hotel, café, or in-flight
Wi-Fi, this tool answers in ~10 seconds: **what's happening with this
network?** Is there a captive portal? Is DNS hijacked? Which services are
blocked? Is HTTPS being intercepted? How slow is it, really?

## Zero dependencies

The diagnostic tool uses **only the Python standard library** — deliberately,
because when you're on broken Wi-Fi you can't `pip install` anything. If you
have Python 3.10+, it runs.

```bash
git clone <this repo>
cd network_manager
python3 main.py
```

## Usage

```bash
python3 main.py              # full diagnosis (default)
python3 main.py --speed      # full diagnosis + download speed test
python3 main.py --json       # full diagnosis, JSON output (scriptable)
python3 main.py --open       # auto-open the captive portal login page if found

python3 main.py portal       # captive portal / TLS interception only
python3 main.py dns          # DNS health only
python3 main.py services     # which ports/services are blocked
python3 main.py speed        # quick download speed estimate
python3 main.py scan         # discover devices on the local network
python3 main.py watch        # live stability monitor (Ctrl-C for summary)
python3 main.py watch -i 2   # ...probing every 2 seconds
```

Exit code is `1` if any hard failure was found, so you can script on it.

### Network history

Every full check saves a snapshot to `~/.network-manager/history/`, one file
per network (keyed by SSID). On your next visit to the same network the
report includes a **"Compared to last visit"** section — e.g. *"SSH — was
reachable on Jul 5, now blocked"* or *"Latency: 25 ms then → 210 ms now"*.
A change since last time is a much stronger signal than a bare failure.

### Watch mode

`watch` prints one line per tick (gateway ping, internet TCP, DNS query) so
on flaky Wi-Fi — planes, trains, crowded lounges — you can see *when* and
*where* it drops. Ctrl-C prints availability % and outage count.

## What it checks

| Section | Checks |
|---|---|
| **Network** | Wi-Fi SSID, interface, local IP (flags self-assigned/DHCP failure), gateway, DNS servers |
| **Connectivity** | Gateway ping, internet reachability by direct IP (distinguishes "no internet" from "broken DNS"), IPv6 health, latency, packet loss split into Wi-Fi link vs venue uplink |
| **Captive portal** | Probes the same endpoints macOS/Android/Firefox use; extracts the portal login URL when one is found |
| **TLS interception** | Verifies the certificate chain of a well-known site — detects HTTPS man-in-the-middle |
| **DNS** | System resolution, direct access to public resolvers (are you forced through the network's DNS?), NXDOMAIN hijack detection |
| **Services** | Real connections to real servers: HTTPS, HTTP, SSH (22), IMAP (993), SMTP (587), DNS over TCP/TLS, WhatsApp, UDP DNS, NTP |
| **Speed** | Short download burst against Cloudflare (capped at ~8 s — kind to metered connections) |

Every failed check comes with a concrete suggestion — e.g. *"SSH is blocked →
use ssh.github.com:443"*, *"portal detected → open this URL to log in"*.

The full check is adaptive: if a captive portal is detected, it skips the
DNS/service checks (they'd all fail for the same root cause) and tells you to
log in first.

## Extras: managed-network monitoring

Two standalone helpers for networks you *own* (not part of the travel flow).
They read credentials from environment variables or a local `.env` file
(never hardcode them):

```bash
# UniFi Controller device status (needs: pip install requests)
UNIFI_URL=https://unifi.example.com:8443 UNIFI_PASSWORD=... \
    python3 -m src.monitoring_unifi

# Cisco IOS device status over SSH (needs: pip install netmiko)
CISCO_HOSTS=10.0.0.1,10.0.0.2 CISCO_PASSWORD=... \
    python3 -m src.monitoring_cisco
```

## Project layout

```
main.py                    CLI entry point
src/
  netinfo.py               local network info (IP, gateway, DNS, SSID)
  connectivity.py          gateway/internet/IPv6/latency/packet-loss checks
  captive.py               captive portal + TLS interception detection
  dnscheck.py              DNS health, incl. a minimal stdlib DNS client
  services.py              port/service blocking checks
  speed.py                 quick download speed estimate
  history.py               per-network snapshots + last-visit comparison
  watch.py                 live stability monitor
  network_discovery.py     concurrent local network scanner
  reporting.py             terminal report + summary/advice rendering
  monitoring_unifi.py      (extra) UniFi Controller monitoring
  monitoring_cisco.py      (extra) Cisco IOS monitoring
```

## License

MIT
