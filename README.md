# network-manager

[![tests](https://github.com/fvalenzuelag/network-manager/actions/workflows/tests.yml/badge.svg)](https://github.com/fvalenzuelag/network-manager/actions/workflows/tests.yml)

Fast diagnosis of unfamiliar networks — built for travel.

When you land somewhere and connect to airport, hotel, café, or in-flight
Wi-Fi, this tool answers in ~10 seconds: **what's happening with this
network?** Is there a captive portal? Is DNS hijacked? Which services are
blocked? Is HTTPS being intercepted? How slow is it, really?

## Zero dependencies

The diagnostic tool uses **only the Python standard library** — deliberately,
because when you're on broken Wi-Fi you can't `pip install` anything. If you
have Python 3.10+, it runs.

### Install (do it before you travel)

```bash
pipx install git+https://github.com/fvalenzuelag/network-manager
# or: uv tool install git+https://github.com/fvalenzuelag/network-manager
network-manager            # works from any directory
```

That gives you a `network-manager` command (and `python3 -m network_manager`).
Nothing else is downloaded, so it keeps working on any network afterwards.

### Or run it from a clone

```bash
git clone https://github.com/fvalenzuelag/network-manager
cd network-manager
python3 main.py
```

The examples below use `python3 main.py`; installed, it's the same with
`network-manager` instead.

## Usage

```bash
python3 main.py              # full diagnosis (default)
python3 main.py --speed      # full diagnosis + speed test
python3 main.py --json       # full diagnosis, JSON output (scriptable)
python3 main.py --open       # portal? open its login page, wait, then finish the check

python3 main.py portal       # captive portal / TLS interception only
python3 main.py dns          # DNS health only
python3 main.py services     # which ports/services are blocked
python3 main.py speed        # download, upload, latency under load (~10-20s)
python3 main.py scan         # discover devices (saved to ~/.network-manager/scans/)
python3 main.py watch        # live stability monitor (Ctrl-C for summary)
python3 main.py watch -i 2   # ...probing every 2 seconds
python3 main.py gui          # web GUI in your browser (see below)
```

Exit code is `1` if any hard failure was found, so you can script on it.

### Network history

Every full check saves a snapshot to `~/.network-manager/history/`, one file
per network (keyed by SSID, or by the router's MAC address where macOS hides
the SSID). On your next visit to the same network the
report includes a **"Compared to last visit"** section — e.g. *"SSH — was
reachable on Jul 5, now blocked"* or *"Latency: 25 ms then → 210 ms now"*.
A change since last time is a much stronger signal than a bare failure.

It also warns when a known network shows up with **different router
hardware** — usually new equipment, but also what a fake network copying the
name looks like. That needs the SSID: macOS 14.4+ hides it from
unprivileged tools, so history falls back to the router's MAC address (and
this warning can't fire). Running `sudo ipconfig setverbose 1` once is the
commonly cited way to make `ipconfig getsummary` show the SSID again.

Independently of history, every check looks for **router impersonation**:
another device on the network claiming the router's hardware address is the
mark of ARP spoofing (someone intercepting traffic). Networks that use proxy
ARP — the router answering for everyone — are recognized and not flagged.

### Watch mode

`watch` prints one line per tick (gateway ping, internet TCP, DNS query) so
on flaky Wi-Fi — planes, trains, crowded lounges — you can see *when* and
*where* it drops. Ctrl-C prints availability % and outage count.

### Web GUI

`python3 main.py gui` starts a localhost-only server (stdlib `http.server`,
still zero dependencies) and opens the browser:

- **Diagnosis tab** — one button runs the full check; results stream in live,
  grouped into cards, with the verdict as a glowing banner up top and every
  piece of advice inline.
- **Live monitor tab** — the watch mode as scrolling latency sparklines
  (gateway / internet / DNS) with min/max and availability %.
- **Cyberpunk theme** — a Three.js synthwave floor of glowing points runs
  staggered radial waves behind the UI (an homage to the anime.js stagger
  demos), and its tint follows the app state: cyan/magenta idle, violet
  while checking, green on a healthy verdict, red on failure. Respects
  `prefers-reduced-motion` (renders a still frame) and pauses when the tab
  is hidden. Phone-friendly.
- Works with **no internet at all**: Three.js is vendored into
  `web/vendor/` (a checked-in static asset — no CDN, no install step; the
  backend stays pure stdlib), and everything else is inline in
  `web/index.html`.

`--port 9000` to pick a port, `--no-browser` to just print the URL.

## What it checks

| Section | Checks |
|---|---|
| **Network** | Wi-Fi SSID, interface, local IP (flags self-assigned/DHCP failure), gateway, DNS servers, active VPN (results would describe the tunnel), router impersonation / ARP spoofing |
| **Wi-Fi** (macOS) | Signal quality (RSSI/SNR/channel/PHY rate), and security — warns on open or WEP networks |
| **Connectivity** | Gateway reachability (ping, or TCP for routers that ignore ping), internet reachability by direct IP (distinguishes "no internet" from "broken DNS"), IPv6 health, latency, packet loss split into Wi-Fi link vs venue uplink, path MTU — catches MTU blackholes where oversized packets vanish and VPNs/calls hang |
| **Captive portal** | Probes the same endpoints macOS/Android/Firefox use (most must agree); extracts the portal login URL when one is found |
| **TLS interception** | Verifies the certificate chain of a well-known site — detects HTTPS man-in-the-middle, after ruling out a wrong system clock |
| **DNS** | System resolution, direct access to public resolvers (are you forced through the network's DNS?), DNS-over-HTTPS (so "use DoH" is advice that's known to work here), NXDOMAIN hijack detection |
| **Public egress** | Your public IP, egress country, and the Cloudflare edge you hit (an IATA airport code — handy when traveling), WARP/VPN detection |
| **Services** | Real connections to real servers: HTTPS, HTTP, SSH (22), IMAP (993), SMTP (587), DNS over TCP/TLS, WhatsApp, UDP DNS, NTP |
| **Speed** (`--speed`) | Download and upload against Cloudflare (each capped at ~8 s / 25 MB — kind to metered connections), plus latency under load (bufferbloat — why calls stutter on a "fast" link) |

Every failed check comes with a concrete suggestion — e.g. *"SSH is blocked →
use ssh.github.com:443"*, *"portal detected → open this URL to log in"*.

The full check is adaptive: if a captive portal is detected, it skips the
DNS/service checks (they'd all fail for the same root cause) and tells you to
log in first. With `--open` (or the **Open login page** button in the GUI) it
opens the login page, waits for you to log in, and then runs the full check
on the now-open network — no second command needed. `--no-wait` only opens
the page. Only `http(s)` login URLs are ever opened: the network supplies
the URL, so `javascript:`/`file:` redirects are refused.

### The verdict

The summary opens with a single plain-language diagnosis that names the
failing **layer** and whether anything local can fix it:

> ✘ Your machine and the Wi-Fi link are fine — the failure is upstream: the
> venue's connection to the internet is down.
> → Nothing you do locally will fix this. Tell the staff, or tether to
> mobile data.

It distinguishes: not connected → DHCP failure → captive portal → dead
access point → dead venue uplink → wrong system clock → HTTPS interception →
dead DNS → degraded (weak signal, link vs uplink packet loss, MTU blackhole,
hijacked DNS, blocked services, broken IPv6) → healthy.

Two traps it avoids: a **wrong clock** fails certificate checks exactly like
HTTPS interception, so the clock is checked against live server time before
raising that alarm; and with a **VPN** on, every check measures the tunnel —
the report says so, and such runs aren't saved to the network's history.

## Extras: managed-network monitoring

Two standalone helpers for networks you *own* (not part of the travel flow).
They read credentials from environment variables or a local `.env` file
(never hardcode them):

```bash
# UniFi Controller or UniFi OS console device status
# (needs requests: pipx install "network-manager[unifi] @ git+https://...")
UNIFI_URL=https://unifi.example.com:8443 UNIFI_PASSWORD=... \
    python3 -m network_manager.monitoring_unifi

# Cisco IOS device status over SSH (needs netmiko: the [cisco] extra)
CISCO_HOSTS=10.0.0.1,10.0.0.2 CISCO_PASSWORD=... \
    python3 -m network_manager.monitoring_cisco
```

## Project layout

```
main.py                    run from a clone without installing (calls cli.py)
pyproject.toml             packaging: the `network-manager` command, extras
network_manager/
  cli.py                   CLI entry point (`network-manager`, `python3 -m network_manager`)
  web/index.html           web GUI (cyberpunk theme, CSS/JS inline)
  web/fx.js                Three.js animated background
  web/vendor/              vendored Three.js (works offline)
  fullcheck.py             the full diagnosis flow (shared by CLI and GUI)
  gui.py                   localhost web server for the GUI
  netinfo.py               local network info (IP, gateway, DNS, SSID)
  wifi.py                  Wi-Fi signal + security (open/WEP warning) (macOS)
  connectivity.py          gateway/internet/IPv6/latency/packet-loss checks
  captive.py               captive portal + TLS interception detection
  dnscheck.py              DNS health, incl. a minimal stdlib DNS client + DoH check
  geo.py                   public IP / egress country / Cloudflare edge
  services.py              port/service blocking checks
  speed.py                 download/upload speed + bufferbloat (latency under load)
  verdict.py               single plain-language diagnosis from all findings
  history.py               per-network snapshots + last-visit comparison
  watch.py                 live stability monitor
  network_discovery.py     concurrent local network scanner
  reporting.py             terminal report + summary/advice rendering
  monitoring_unifi.py      (extra) UniFi Controller / UniFi OS monitoring
  monitoring_cisco.py      (extra) Cisco IOS monitoring
  envfile.py               (extra) minimal .env loader for the helpers
tests/                     stdlib unittest suite (python3 -m unittest discover tests)
```

## License

MIT — see [LICENSE](LICENSE).
