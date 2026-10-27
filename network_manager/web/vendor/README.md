# Vendored frontend assets

Checked in so the GUI works with **no internet access** — the whole point of
this tool. No CDN, no build step, no install.

| File | What | Version | License |
|---|---|---|---|
| `three.module.min.js` | Three.js (ES module build) | 0.171.0 | MIT |
| `three.core.min.js` | Three.js core (imported by the module build) | 0.171.0 | MIT |

To update: download `build/three.module.min.js` **and** `build/three.core.min.js`
from the three.js release and replace both files (the module build imports the
core file since r167).
