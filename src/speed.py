"""Quick download speed estimate using Cloudflare's speed test endpoint.

Downloads for a few seconds and reports throughput. Deliberately short —
on metered or in-flight Wi-Fi you don't want a full speed test.
"""

import time
import urllib.request

URL = "https://speed.cloudflare.com/__down?bytes=25000000"
MAX_SECONDS = 8
CHUNK = 64 * 1024


def measure(max_seconds=MAX_SECONDS):
    """Return (mbps, seconds, bytes_downloaded) or None on failure."""
    req = urllib.request.Request(URL, headers={"User-Agent": "network-manager-diag/1.0"})
    total = 0
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            while True:
                chunk = resp.read(CHUNK)
                elapsed = time.monotonic() - start
                if not chunk or elapsed >= max_seconds:
                    break
                total += len(chunk)
    except OSError:
        return None
    elapsed = time.monotonic() - start
    if total == 0 or elapsed == 0:
        return None
    mbps = (total * 8) / elapsed / 1_000_000
    return (mbps, elapsed, total)


def collect(report):
    result = measure()
    if result is None:
        report.add(
            "Download speed", "fail", "measurement failed",
            "Could not run the speed test — check basic connectivity first.",
        )
        return {"download_mbps": None}

    mbps, elapsed, total = result
    detail = f"{mbps:.1f} Mbps ({total / 1e6:.1f} MB in {elapsed:.1f}s)"
    if mbps >= 20:
        report.add("Download speed", "ok", detail)
    elif mbps >= 3:
        report.add(
            "Download speed", "warn", detail,
            "Modest bandwidth — fine for browsing and email, video may buffer.",
        )
    else:
        report.add(
            "Download speed", "warn", detail,
            "Very low bandwidth — stick to text/email, disable auto-updates "
            "and cloud sync to save it.",
        )
    return {"download_mbps": round(mbps, 1)}
