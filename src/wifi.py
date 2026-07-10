"""Wi-Fi link quality: signal, noise, channel, PHY rate (macOS).

Weak signal is the most common invisible cause of "the Wi-Fi is bad" —
everything associates and gets an IP, but the radio link is barely alive.
Uses `system_profiler SPAirPortDataType`, which needs no root (the old
`airport` CLI is gone and `wdutil` wants sudo).
"""

import re
import subprocess
import sys


def get_link_info():
    """Return dict with rssi/noise/snr/channel/phy/tx_rate, or None."""
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.run(
            ["system_profiler", "SPAirPortDataType", "-detailLevel", "basic"],
            capture_output=True, text=True, timeout=15,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None

    # The primary interface's "Current Network Information" block comes
    # first; the awdl0 (AirDrop) block afterwards has no Signal/Noise line,
    # so first-match wins is safe.
    signal = re.search(r"Signal / Noise:\s*(-\d+)\s*dBm\s*/\s*(-\d+)\s*dBm", out)
    if not signal:
        return None
    rssi, noise = int(signal.group(1)), int(signal.group(2))
    channel = re.search(r"Channel:\s*(.+)", out)
    phy = re.search(r"PHY Mode:\s*(\S+)", out)
    tx = re.search(r"Transmit Rate:\s*(\d+)", out)
    return {
        "rssi_dbm": rssi,
        "noise_dbm": noise,
        "snr_db": rssi - noise,
        "channel": channel.group(1).strip() if channel else None,
        "phy_mode": phy.group(1) if phy else None,
        "tx_rate_mbps": int(tx.group(1)) if tx else None,
    }


def collect(report, link=None):
    """Report Wi-Fi link quality. Returns findings dict (empty off-macOS).

    `link` lets the caller pass a pre-fetched get_link_info() result
    (system_profiler takes ~2 s, so the full check starts it in a thread).
    """
    if link is None:
        link = get_link_info()
    if not link:
        return {}

    rssi, snr = link["rssi_dbm"], link["snr_db"]
    if rssi >= -60:
        quality, status, advice = "excellent", "ok", ""
    elif rssi >= -70:
        quality, status, advice = "good", "ok", ""
    elif rssi >= -78:
        quality, status, advice = "fair", "warn", (
            "Signal is fair — speeds may drop and calls may stutter. "
            "Moving closer to the access point will help."
        )
    else:
        quality, status, advice = "weak", "warn", (
            "Signal is weak — this alone can explain a bad connection. "
            "Move closer to the access point before blaming the network."
        )

    detail = f"{rssi} dBm ({quality}), SNR {snr} dB"
    if status == "ok" and snr < 15:
        status = "warn"
        detail += " — noisy environment"
        advice = ("High radio noise (crowded band/interference) — the 5 GHz "
                  "band or a different spot may work better.")
    report.add("Wi-Fi signal", status, detail, advice)

    parts = [p for p in (link["phy_mode"], link["channel"],
                         f"{link['tx_rate_mbps']} Mbps PHY" if link["tx_rate_mbps"] else None) if p]
    if parts:
        report.add("Wi-Fi link", "info", ", ".join(parts))

    return link
