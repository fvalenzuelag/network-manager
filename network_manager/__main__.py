"""`python -m network_manager` — same as the `network-manager` command."""

import sys

from .cli import main

sys.exit(main())
