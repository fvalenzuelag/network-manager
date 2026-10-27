"""Quick speed test: download, upload, and latency under load (Cloudflare).

Each direction transfers for a few seconds at most — on metered or in-flight
Wi-Fi you don't want a full speed test. While each transfer runs, a
background probe keeps timing TCP connects: the jump from idle latency is
*bufferbloat*, the usual reason video calls stutter on a link whose speed
test looks fine. Upload matters for calls too — it carries your own video.
"""

import http.client
import statistics
import threading
import time
import urllib.request

from .connectivity import tcp_connect_ms

DOWN_URL = "https://speed.cloudflare.com/__down?bytes=25000000"
UP_URL = "https://speed.cloudflare.com/__up"
MAX_SECONDS = 8           # per direction
UP_MAX_BYTES = 25_000_000  # same data budget as the download
CHUNK = 64 * 1024
HEADERS = {"User-Agent": "network-manager-diag/1.0"}

LATENCY_TARGET = ("1.1.1.1", 443)
PROBE_INTERVAL = 0.1  # fast links finish 25 MB in ~1 s; sample densely
MIN_SAMPLES = 3       # fewer than this under load → don't guess
# Added latency under load, on Waveform's bufferbloat scale: under 60 ms is
# grade A/B (calls are fine), 60–200 ms grade C, beyond that D/F.
MODERATE_MS, SEVERE_MS = 60, 200


class LoadLatency:
    """Times TCP connects in the background while a transfer runs.

    Failed probes are counted, not dropped: timeouts under load are the
    worst case of bufferbloat, not missing data.
    """

    def __init__(self):
        self.samples, self.failures = [], 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self._stop.is_set():
            ms = tcp_connect_ms(*LATENCY_TARGET, timeout=2)
            if ms is None:
                self.failures += 1
            else:
                self.samples.append(ms)
            self._stop.wait(PROBE_INTERVAL)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(3)


def idle_latency(samples=5):
    times = [ms for ms in (tcp_connect_ms(*LATENCY_TARGET, timeout=2)
                           for _ in range(samples)) if ms is not None]
    return statistics.median(times) if times else None


def measure(max_seconds=MAX_SECONDS):
    """Download. Returns (mbps, seconds, bytes_downloaded) or None."""
    req = urllib.request.Request(DOWN_URL, headers=HEADERS)
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
    except (OSError, http.client.HTTPException):  # e.g. IncompleteRead
        return None
    elapsed = time.monotonic() - start
    if total == 0 or elapsed == 0:
        return None
    mbps = (total * 8) / elapsed / 1_000_000
    return (mbps, elapsed, total)


def measure_upload(max_seconds=MAX_SECONDS, max_bytes=UP_MAX_BYTES):
    """Upload (chunked POST). Returns (mbps, seconds, bytes_sent) or None.

    The clock stops when the server's response arrives, i.e. after it has
    received every byte — so OS send buffers can't inflate the result.
    """
    block = b"\0" * CHUNK
    sent = 0
    start = time.monotonic()

    def body():
        nonlocal sent
        while sent < max_bytes and time.monotonic() - start < max_seconds:
            sent += len(block)
            yield block

    req = urllib.request.Request(
        UP_URL, data=body(), method="POST",
        headers={**HEADERS, "Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=max_seconds + 10) as resp:
            resp.read()
    except (OSError, http.client.HTTPException):
        return None
    elapsed = time.monotonic() - start
    if sent == 0 or elapsed == 0:
        return None
    return ((sent * 8) / elapsed / 1_000_000, elapsed, sent)


def grade_bufferbloat(idle_ms, probes):
    """Returns (grade, increase_ms) from idle latency and the probes taken
    under load. grade: 'ok' | 'moderate' | 'severe', or None if too little
    data. Graded on the median, so one spike doesn't cry wolf."""
    attempts = len(probes.samples) + probes.failures
    if idle_ms is None or attempts < MIN_SAMPLES:
        return None, None
    if probes.failures / attempts >= 0.25:
        return "severe", None  # probes timing out under load
    if len(probes.samples) < MIN_SAMPLES:
        return None, None
    increase = statistics.median(probes.samples) - idle_ms
    if increase < MODERATE_MS:
        return "ok", increase
    return ("moderate" if increase < SEVERE_MS else "severe"), increase


def _report_speed(report, name, result, thresholds, advice):
    """Shared download/upload reporting. thresholds = (ok_at, modest_at)."""
    if result is None:
        report.add(name, "fail", "measurement failed",
                   "Could not run the speed test — check basic connectivity first.")
        return None
    mbps, elapsed, total = result
    detail = f"{mbps:.1f} Mbps ({total / 1e6:.1f} MB in {elapsed:.1f}s)"
    ok_at, modest_at = thresholds
    if mbps >= ok_at:
        report.add(name, "ok", detail)
    elif mbps >= modest_at:
        report.add(name, "warn", detail, advice[0])
    else:
        report.add(name, "warn", detail, advice[1])
    return round(mbps, 1)


def collect(report):
    idle = idle_latency()

    with LoadLatency() as down_load:
        down = measure()
    download_mbps = _report_speed(report, "Download speed", down, (20, 3), (
        "Modest bandwidth — fine for browsing and email, video may buffer.",
        "Very low bandwidth — stick to text/email, disable auto-updates "
        "and cloud sync to save it.",
    ))

    with LoadLatency() as up_load:
        up = measure_upload()
    upload_mbps = _report_speed(report, "Upload speed", up, (5, 1.5), (
        "Modest upload — calls work, but sending files and photos is slow.",
        "Very low upload — video calls will struggle to send your video; "
        "turn your camera off or pause cloud photo/backup sync.",
    ))

    # The worse direction decides: upload bloat is common on asymmetric links.
    order = {"ok": 0, "moderate": 1, "severe": 2}
    graded = [(*grade_bufferbloat(idle, probes), direction)
              for probes, direction in ((down_load, "downloading"),
                                        (up_load, "uploading"))]
    graded = [g for g in graded if g[0]]
    grade, increase, direction = max(
        graded, key=lambda g: (order[g[0]], g[1] or 0)) \
        if graded else (None, None, None)

    name = "Latency under load"
    if grade is None:
        pass  # transfers too short or failed — nothing honest to say
    elif grade == "ok":
        report.add(name, "ok", f"+{max(increase, 0):.0f} ms while {direction} "
                               f"(idle {idle:.0f} ms) — calls unaffected")
    else:
        detail = (f"+{increase:.0f} ms while {direction} (idle {idle:.0f} ms)"
                  if increase is not None
                  else f"probes time out while {direction}")
        report.add(
            name, "warn", f"{detail} — {grade} bufferbloat",
            "Latency jumps whenever the connection is busy, so calls "
            "stutter while anyone downloads or syncs. On calls, pause "
            "uploads/backups; nothing else here will fix it.",
        )

    return {"download_mbps": download_mbps, "upload_mbps": upload_mbps,
            "idle_latency_ms": idle, "bufferbloat": grade,
            "bufferbloat_ms": None if increase is None else round(increase)}
