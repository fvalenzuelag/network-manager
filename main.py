#!/usr/bin/env python3
"""Run network-manager from a clone, no install needed: `python3 main.py`.

Installed, the same CLI is the `network-manager` command
(see network_manager/cli.py).
"""

import sys

from network_manager.cli import main

if __name__ == "__main__":
    sys.exit(main())
