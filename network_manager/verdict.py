"""Turn all findings into a single plain-language verdict.

The individual checks say *what* failed; this says *where the problem
lives* (your machine, the Wi-Fi link, the router, the venue's uplink,
DNS, a portal) and whether anything you do locally can fix it.
"""

from .captive import CLOCK_SKEW_LIMIT, describe_skew


def diagnose(findings):
    """Return (status, headline, action). status: 'ok' | 'warn' | 'fail'."""
    status, headline, action = _diagnose(findings)
    vpn = (findings.get("network") or {}).get("vpn_interface")
    open_wifi = (findings.get("wifi") or {}).get("security_level") == "open"
    if open_wifi and not vpn:  # a VPN already encrypts everything
        if status == "ok":
            status = "warn"
        headline += (" Note: this Wi-Fi is unencrypted — anyone nearby can "
                     "read traffic that isn't HTTPS.")
        action = action or "Use a VPN for anything sensitive on this network."
    elif open_wifi:
        headline += " (The Wi-Fi is unencrypted, but your VPN covers that.)"
    if vpn:
        headline += f" (Measured through your VPN on {vpn}, not this network.)"
        action = action or ("Disconnect the VPN and run again to check the "
                            "network itself.")
    return status, headline, action


def _diagnose(findings):
    net = findings.get("network", {})
    conn = findings.get("connectivity", {})
    portal = findings.get("portal", {})
    dns = findings.get("dns") or {}
    services = findings.get("services") or {}
    wifi = findings.get("wifi") or {}
    speed = findings.get("speed") or {}  # only with --speed

    # ── Hard failures, ordered by network layer ──────────────────────
    local_ip = net.get("local_ip")
    if not local_ip:
        return ("fail",
                "You're not connected to any network.",
                "Turn Wi-Fi on and join a network, then run this again.")

    if local_ip.startswith("169.254."):
        return ("fail",
                "You joined the Wi-Fi but never got an address — DHCP failed.",
                "Forget the network and rejoin it, or renew the DHCP lease. "
                "If it persists, the network side is broken.")

    # Full-tunnel VPNs often have no gateway on their default route.
    if not net.get("gateway") and not net.get("vpn_interface"):
        return ("fail",
                "You have an address but no route to a router.",
                "Reconnect to the network; this is a local configuration "
                "problem, not an internet outage.")

    # Before the internet check: portals often drop all direct-IP traffic
    # until you log in, so "no internet" plus a portal means "log in",
    # not "the uplink is down".
    if portal.get("captive_portal"):
        url = portal.get("portal_url")
        return ("warn",
                "The network works, but it's holding you at a captive portal.",
                "Log in at " + (url or "the portal page") + ". With --open "
                "(or the GUI's button) the tool opens it, waits for you to "
                "log in, and finishes the check.")

    if not conn.get("internet"):
        if conn.get("gateway_reachable"):
            return ("fail",
                    "Your machine and the Wi-Fi link are fine — the failure "
                    "is upstream: the venue's connection to the internet is down.",
                    "Nothing you do locally will fix this. Tell the staff, "
                    "or tether to mobile data.")
        return ("fail",
                "The router isn't answering (ping or TCP) and there's no "
                "internet — the access point itself looks dead.",
                "Reconnect once; if it persists, that AP is broken — try a "
                "different network.")

    skew = portal.get("clock_skew_s")
    if skew is not None and abs(skew) > CLOCK_SKEW_LIMIT:
        return ("fail",
                f"You're online, but {describe_skew(skew)} — so HTTPS "
                "certificate checks fail. This is your machine, not the network.",
                "Turn on automatic time (System Settings → General → Date & "
                "Time), then check again.")

    if portal.get("tls_interception"):
        return ("fail",
                "You're online, but this network is intercepting HTTPS — "
                "your encrypted traffic is being opened.",
                "Don't log in to anything sensitive here. Use a VPN or "
                "mobile data.")

    if net.get("router_impersonation") == "suspicious":
        return ("warn",
                "You're online, but another device on this network claims "
                "the router's address — a sign of ARP spoofing (someone "
                "intercepting traffic).",
                "Don't log in to anything sensitive here; use a VPN or "
                "mobile data.")

    if dns and not dns.get("system_resolves"):
        if dns.get("public_dns_reachable"):
            return ("fail",
                    "The internet works — only this network's DNS is dead.",
                    "Set your DNS to 1.1.1.1 (System Settings → Wi-Fi → "
                    "Details → DNS) and you'll be fully online.")
        if dns.get("doh_works") is False:
            return ("fail",
                    "The internet works at the IP level, but DNS is dead — and "
                    "public resolvers and DNS-over-HTTPS are blocked too.",
                    "Use a VPN or mobile data; there's no DNS workaround on "
                    "this network.")
        return ("fail",
                "The internet works at the IP level, but DNS is dead and "
                "public resolvers are blocked too.",
                ("Turn on DNS-over-HTTPS (\"Secure DNS\") in your browser — "
                 "it works on this network — or use a VPN."
                 if dns.get("doh_works") else
                 "Enable DNS-over-HTTPS in your browser (it rides on port "
                 "443), or use a VPN."))

    # ── Online, but degraded ─────────────────────────────────────────
    issues, actions = [], []

    rssi = wifi.get("rssi_dbm")
    gw_loss = conn.get("loss_gateway_pct")
    if gw_loss is not None and gw_loss >= 5:
        detail = f"the Wi-Fi link is dropping {gw_loss:.0f}% of packets"
        if rssi is not None:
            detail += f" (signal {rssi} dBm)"
        issues.append(detail)
        actions.append("move closer to the access point")
    elif rssi is not None and rssi < -78:
        issues.append(f"the Wi-Fi signal is weak ({rssi} dBm)")
        actions.append("move closer to the access point")

    net_loss = conn.get("loss_internet_pct")
    if net_loss is not None and net_loss >= 5 and (gw_loss or 0) < 5:
        issues.append(f"the venue's uplink is losing {net_loss:.0f}% of packets")
        actions.append("moving around won't help — expect instability, "
                       "consider mobile data for calls")

    if conn.get("mtu_blackhole"):
        issues.append(f"packets over {conn.get('path_mtu')} bytes vanish "
                      "silently (MTU blackhole) — VPNs and calls may hang")
        actions.append(f"set your MTU to {conn.get('path_mtu')}")

    latency = conn.get("latency_ms")
    if latency is not None and latency >= 300:
        issues.append(f"latency is very high ({latency:.0f} ms)")

    bloat, bloat_ms = speed.get("bufferbloat"), speed.get("bufferbloat_ms")
    if bloat in ("moderate", "severe"):
        issues.append(f"latency jumps by {bloat_ms} ms when the link is busy "
                      "(bufferbloat)" if bloat_ms is not None else
                      "connections time out when the link is busy (bufferbloat)")
        actions.append("pause uploads and cloud sync during calls")

    upload = speed.get("upload_mbps")
    if upload is not None and upload < 1.5:
        issues.append(f"upload is only {upload:.1f} Mbps")
        actions.append("turn your camera off on video calls")

    if dns.get("nxdomain_hijack"):
        issues.append("DNS answers are being tampered with")
        actions.append({True: "turn on DNS-over-HTTPS in your browser (it "
                              "works here) or use a VPN",
                        False: "use a VPN (DNS-over-HTTPS is blocked here)"}
                       .get(dns.get("doh_works"), "use DNS-over-HTTPS or a VPN"))

    blocked = services.get("blocked") or []
    if blocked:
        issues.append(f"{len(blocked)} service(s) are blocked "
                      f"({', '.join(b.split(' — ')[0] for b in blocked[:3])}"
                      + ("…" if len(blocked) > 3 else "") + ")")
        actions.append("see the per-service advice above for workarounds")

    if conn.get("ipv6") == "broken":
        issues.append("IPv6 is advertised but broken (sites may stall "
                      "before falling back to IPv4)")

    if issues:
        return ("warn",
                "You're online, but degraded: " + "; ".join(issues) + ".",
                # Not str.capitalize(): it lowercases the rest ("VPN" → "vpn").
                actions[0][0].upper() + actions[0][1:] + "." if actions else None)

    # ── All clear ────────────────────────────────────────────────────
    headline = "This network is healthy: no portal, clean DNS, nothing blocked"
    if latency is not None:
        headline += f", {latency:.0f} ms latency"
    return ("ok", headline + ".", None)
