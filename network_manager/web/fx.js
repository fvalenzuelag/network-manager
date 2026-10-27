/* Cyberpunk background: a tilted grid of glowing points with staggered
 * radial waves (an homage to the anime.js stagger-grid demos), rendered
 * with Three.js. The wave tint follows the app state via window.netfx.
 *
 * Respects prefers-reduced-motion (renders a single still frame) and
 * pauses when the tab is hidden.
 */
import * as THREE from "/vendor/three.module.min.js";

const COLS = 110, ROWS = 60;      // ~6600 points
const SPACING = 0.22;
const PULSE_EVERY = 3.2;          // seconds between wave launches

// State tints (cyberpunk, but status semantics survive: green/amber/red)
const TINTS = {
  idle:    { a: new THREE.Color("#00e5ff"), b: new THREE.Color("#ff2ec4"), speed: 1.0 },
  running: { a: new THREE.Color("#00e5ff"), b: new THREE.Color("#8b5cf6"), speed: 2.2 },
  ok:      { a: new THREE.Color("#0aff9d"), b: new THREE.Color("#00e5ff"), speed: 0.9 },
  warn:    { a: new THREE.Color("#fcee0a"), b: new THREE.Color("#ff2ec4"), speed: 1.3 },
  fail:    { a: new THREE.Color("#ff3860"), b: new THREE.Color("#ff2ec4"), speed: 1.6 },
};

let state = TINTS.idle;
window.netfx = {
  setState(name) { state = TINTS[name] || TINTS.idle; },
};

const canvas = document.getElementById("fx");
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

const renderer = new THREE.WebGLRenderer({ canvas, antialias: false, alpha: true });
renderer.setPixelRatio(Math.min(devicePixelRatio, 2));

const scene = new THREE.Scene();
scene.fog = new THREE.Fog(0x07070f, 6, 16);

const camera = new THREE.PerspectiveCamera(55, 1, 0.1, 40);
camera.position.set(0, 2.1, 7.5);
camera.lookAt(0, -0.5, 0);

// ── The grid ─────────────────────────────────────────────
const N = COLS * ROWS;
const positions = new Float32Array(N * 3);
const colors = new Float32Array(N * 3);
const gx = new Float32Array(N), gy = new Float32Array(N);
let i3 = 0;
for (let r = 0; r < ROWS; r++) {
  for (let c = 0; c < COLS; c++) {
    const x = (c - COLS / 2) * SPACING;
    const z = (r - ROWS / 2) * SPACING;
    const k = r * COLS + c;
    gx[k] = x; gy[k] = z;
    positions[i3] = x; positions[i3 + 1] = 0; positions[i3 + 2] = z;
    i3 += 3;
  }
}
const geo = new THREE.BufferGeometry();
geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
geo.setAttribute("color", new THREE.BufferAttribute(colors, 3));

// Round glow sprite — default Points render as hard squares.
function dotTexture() {
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const g = c.getContext("2d");
  const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, "rgba(255,255,255,1)");
  grad.addColorStop(0.35, "rgba(255,255,255,0.55)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.fillRect(0, 0, 64, 64);
  return new THREE.CanvasTexture(c);
}

const mat = new THREE.PointsMaterial({
  size: 0.07, map: dotTexture(), vertexColors: true,
  transparent: true, opacity: 0.9,
  blending: THREE.AdditiveBlending, depthWrite: false, sizeAttenuation: true,
});
const points = new THREE.Points(geo, mat);
points.position.y = -1.2;
scene.add(points);

// ── Staggered pulses ─────────────────────────────────────
const pulses = [];
function launchPulse(t) {
  pulses.push({
    x: (Math.random() - 0.5) * COLS * SPACING * 0.8,
    y: (Math.random() - 0.5) * ROWS * SPACING * 0.8,
    t0: t,
  });
  if (pulses.length > 4) pulses.shift();
}

let mouseX = 0, mouseY = 0;
addEventListener("pointermove", (e) => {
  mouseX = (e.clientX / innerWidth - 0.5);
  mouseY = (e.clientY / innerHeight - 0.5);
}, { passive: true });

function resize() {
  const w = innerWidth, h = innerHeight;
  renderer.setSize(w, h, false);
  camera.aspect = w / h;
  camera.updateProjectionMatrix();
}
addEventListener("resize", resize);
resize();

let lastPulse = -PULSE_EVERY;
const pos = geo.attributes.position.array;
const col = geo.attributes.color.array;
const cA = TINTS.idle.a.clone(), cB = TINTS.idle.b.clone();

function frame(tMs) {
  const t = tMs / 1000;
  if ((t - lastPulse) > PULSE_EVERY / state.speed) {
    launchPulse(t);
    lastPulse = t;
  }
  // Ease the palette toward the current state's tint.
  cA.lerp(state.a, 0.04);
  cB.lerp(state.b, 0.04);

  for (let k = 0; k < N; k++) {
    const x = gx[k], y = gy[k];
    // Gentle base undulation…
    let h = Math.sin(x * 0.7 + t * 0.6) * Math.cos(y * 0.5 + t * 0.45) * 0.07;
    // …plus anime.js-style radial waves, phase-delayed by distance.
    for (const p of pulses) {
      const age = (t - p.t0) * state.speed;
      const d = Math.hypot(x - p.x, y - p.y);
      h += Math.sin(d * 3.2 - age * 4.5)
         * Math.exp(-d * 0.35) * Math.exp(-age * 0.55) * 0.55;
    }
    pos[k * 3 + 1] = h;
    // Hue rides the wave (flat → hue A, crest → hue B) and so does
    // brightness — calm floor stays dim, wavefronts flare neon.
    const mix = Math.min(1, Math.max(0, h * 2.2 + 0.12));
    const glow = 0.35 + Math.min(1, Math.abs(h) * 2.4) * 1.05;
    col[k * 3]     = (cA.r + (cB.r - cA.r) * mix) * glow;
    col[k * 3 + 1] = (cA.g + (cB.g - cA.g) * mix) * glow;
    col[k * 3 + 2] = (cA.b + (cB.b - cA.b) * mix) * glow;
  }
  geo.attributes.position.needsUpdate = true;
  geo.attributes.color.needsUpdate = true;

  // Mouse parallax, softly.
  camera.position.x += (mouseX * 1.2 - camera.position.x) * 0.03;
  camera.position.y += (2.1 - mouseY * 0.8 - camera.position.y) * 0.03;
  camera.lookAt(0, -0.5, 0);

  renderer.render(scene, camera);
}

if (reduced) {
  launchPulse(0.5);
  frame(1200);                    // one composed still, no motion
} else {
  let raf = null;
  const loop = (t) => { frame(t); raf = requestAnimationFrame(loop); };
  raf = requestAnimationFrame(loop);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) { cancelAnimationFrame(raf); raf = null; }
    else if (!raf) raf = requestAnimationFrame(loop);
  });
}
