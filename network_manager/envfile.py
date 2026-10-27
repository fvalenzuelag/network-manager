"""Minimal .env loader shared by the monitoring helpers.

Kept in its own module so each helper only needs its own dependency
(importing it from monitoring_unifi would drag in `requests` for Cisco).
"""

import os


def load_env(path=".env"):
    """Minimal .env loader (KEY='value' lines) so no dependency is needed."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    os.environ.setdefault(key.strip(), value.strip().strip("'\""))
    except OSError:
        pass
