// Alien Agent ID — Human-like input.
//
// Why this exists: the network + fingerprint layers of bot detection are already
// solved for us — we drive the user's REAL Chrome, on their real profile, from
// their real residential IP, so TLS/HTTP2/fingerprint/IP all authenticate as the
// human (see lib/launch.mjs). Per the 2026 detection literature that leaves ONE
// residual signal: behaviour. Driving a page with instantaneous synthetic events
// (page.fill / page.click with no cursor trajectory and fixed pacing) is the
// textbook bot signature — and it fires HARDER precisely because the rest of the
// environment is pristine (pristine fingerprint + robotic motion is itself the
// anomaly). This module replaces those with human-shaped motion and typing:
//   - the cursor travels a curved (Bézier) path and dwells before a click,
//   - text is typed key-by-key with jittered, occasionally-paused cadence,
//   - scrolls are broken into eased wheel steps.
//
// The geometry/timing helpers are pure (injectable rng) so they unit-test with no
// browser; the driving functions take a patchright Page.
//
// Escape hatch: set AGENT_ID_HUMAN_INPUT=0 to fall back to fast direct calls
// (for speed-sensitive automation or debugging).

export function humanInputEnabled() {
  return process.env.AGENT_ID_HUMAN_INPUT !== "0";
}

// ─── Pure geometry / timing (unit-tested) ─────────────────────────────────────

export function randBetween(min, max, rng = Math.random) {
  return min + (max - min) * rng();
}

// A quadratic Bézier path from `from` to `to`, with the control point pushed
// off the straight line (perpendicular, magnitude scaled to distance + jitter)
// so the cursor arcs like a hand rather than sliding on a rail. Returns the
// ordered waypoints AFTER `from` (the cursor is assumed already at `from`); the
// final point is exactly `to`. Step count scales with distance.
export function bezierPath(from, to, { rng = Math.random, maxSteps = 26 } = {}) {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const dist = Math.hypot(dx, dy) || 1;
  const mx = (from.x + to.x) / 2;
  const my = (from.y + to.y) / 2;
  // Perpendicular unit vector × a signed, distance-bounded arc magnitude.
  const px = -dy / dist;
  const py = dx / dist;
  const arc = (rng() - 0.5) * Math.min(dist * 0.3, 120);
  const cx = mx + px * arc;
  const cy = my + py * arc;
  const steps = Math.max(3, Math.min(maxSteps, Math.round(dist / 12) + 4));
  const pts = [];
  for (let i = 1; i <= steps; i++) {
    const t = i / steps;
    const u = 1 - t;
    pts.push({
      x: u * u * from.x + 2 * u * t * cx + t * t * to.x,
      y: u * u * from.y + 2 * u * t * cy + t * t * to.y,
    });
  }
  return pts;
}

// Per-keystroke delays (ms): a human-ish base (≈45–120ms) with an occasional
// longer "think" pause. One entry per character.
export function keystrokeDelays(length, { rng = Math.random } = {}) {
  const out = [];
  for (let i = 0; i < length; i++) {
    let d = 45 + rng() * 75;
    if (rng() < 0.08) d += 120 + rng() * 220; // ~8% get a think-pause
    out.push(Math.round(d));
  }
  return out;
}

// A slightly off-centre point inside a bounding box (real clicks rarely hit the
// exact centre). Box is {x, y, width, height}.
export function pointInBox(box, rng = Math.random) {
  return {
    x: box.x + box.width * (0.3 + rng() * 0.4),
    y: box.y + box.height * (0.3 + rng() * 0.4),
  };
}

// ─── Page-driving functions (need a real patchright Page) ─────────────────────

// Track the virtual cursor position per page so successive moves start where the
// last one ended (the cursor doesn't teleport between actions).
const lastPos = new WeakMap();

const wait = (page, ms) => page.waitForTimeout(Math.max(0, Math.round(ms)));

// Move the cursor along a curved path to (x, y), emitting real mousemove events.
export async function humanMove(page, x, y, { rng = Math.random } = {}) {
  const from = lastPos.get(page) || { x: 6 + rng() * 40, y: 6 + rng() * 40 };
  const pts = bezierPath(from, { x, y }, { rng });
  for (const pt of pts) {
    await page.mouse.move(pt.x, pt.y);
    if (rng() < 0.5) await wait(page, 4 + rng() * 12); // human motion isn't uniform
  }
  lastPos.set(page, { x, y });
}

// Resolve a selector to a first visible element, scrolled into view. `root` is
// a Page OR a Frame — an element inside an iframe is located via its frame,
// while the mouse/keyboard (below) stay page-global (they address viewport
// coordinates and the focused element, which frames share).
async function locate(root, selector, timeout) {
  const el = root.locator(selector).first();
  await el.waitFor({ state: "visible", timeout });
  await el.scrollIntoViewIfNeeded({ timeout }).catch(() => {});
  return el;
}

// Click an element with a human cursor approach. The curved humanMove supplies
// the behavioural signal (real mousemove trail + arrival dwell); the actual
// click goes through the actionability-checked locator.click(), which auto-waits
// for the element to be visible/stable and to actually receive the event (it
// retries under overlays / sticky headers). Doing the click by raw page.mouse at
// a coordinate would skip those checks and silently miss when anything covers
// the point — so we keep the human motion but not the fragile raw click.
export async function humanClick(page, selector, { rng = Math.random, timeout = 15000, root = page } = {}) {
  if (!humanInputEnabled()) return void (await root.click(selector, { timeout }));
  const el = await locate(root, selector, timeout);
  // boundingBox is relative to the main-frame viewport even for iframe elements,
  // so page.mouse can travel to it.
  const box = await el.boundingBox().catch(() => null);
  if (box) {
    const { x, y } = pointInBox(box, rng);
    await humanMove(page, x, y, { rng });
    await wait(page, 30 + rng() * 90); // arrival dwell before the press
  }
  await el.click({ timeout });
}

// Focus an element (by clicking it) and type text key-by-key with human cadence.
// `submit` presses Enter afterwards. NOTE: callers injecting a secret must wrap
// this in their own try/catch that emits a value-free error — an underlying
// keyboard error can echo the character being typed.
export async function humanType(
  page,
  selector,
  text,
  { rng = Math.random, timeout = 15000, submit = false, root = page } = {},
) {
  const value = String(text ?? "");
  if (!humanInputEnabled()) {
    await root.fill(selector, value, { timeout });
    if (submit) await root.press(selector, "Enter");
    return;
  }
  await humanClick(page, selector, { rng, timeout, root });
  // Deterministic replace (parity with fill): clear the field first — fill("")
  // is actionability-checked and always empties, so the subsequent keystrokes
  // never append to stale content, and an empty `value` clears correctly. NOT
  // swallowed: if the field can't be cleared we must fail rather than type into
  // (and corrupt) leftover content — the secret paths wrap this in a value-free
  // catch, so a throw never leaks the value.
  await root.locator(selector).first().fill("", { timeout });
  const delays = keystrokeDelays(value.length, { rng });
  for (let i = 0; i < value.length; i++) {
    await page.keyboard.type(value[i]);
    await wait(page, delays[i]);
  }
  if (submit) {
    await wait(page, 80 + rng() * 160);
    await page.keyboard.press("Enter");
  }
}

export async function humanHover(page, selector, { rng = Math.random, timeout = 15000, root = page } = {}) {
  if (!humanInputEnabled()) return void (await root.hover(selector, { timeout }));
  const el = await locate(root, selector, timeout);
  const box = await el.boundingBox();
  if (!box) return void (await el.hover({ timeout }));
  const { x, y } = pointInBox(box, rng);
  await humanMove(page, x, y, { rng });
}

// Break a scroll into a few eased wheel steps with short pauses.
export async function humanScroll(page, dx, dy, { rng = Math.random } = {}) {
  const totalY = Number(dy) || 0;
  const totalX = Number(dx) || 0;
  if (!humanInputEnabled() || (totalY === 0 && totalX === 0)) {
    return void (await page.mouse.wheel(totalX, totalY));
  }
  const steps = Math.max(2, Math.min(6, Math.round(Math.abs(totalY || totalX) / 220) + 2));
  let sentX = 0;
  let sentY = 0;
  for (let i = 1; i <= steps; i++) {
    const t = i / steps;
    const targetY = Math.round(totalY * t);
    const targetX = Math.round(totalX * t);
    await page.mouse.wheel(targetX - sentX, targetY - sentY);
    sentX = targetX;
    sentY = targetY;
    await wait(page, 40 + rng() * 90);
  }
}

// A small pre-press dwell, then the key. For submitting a field, etc.
export async function humanPress(page, selector, key, { rng = Math.random, timeout = 15000 } = {}) {
  await wait(page, 40 + rng() * 120);
  if (selector) await page.press(selector, key, { timeout });
  else await page.keyboard.press(key);
}

// ─── Driver: the surface auto-login's recipe engine uses (injectable for tests) ─
//
// Maps the recipe action vocabulary to human-input calls behind one object, so
// runRecipe stays testable (tests pass a recording driver) while production uses
// real human motion.
export const humanDriver = {
  navigate: (page, url) => page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 }),
  fill: (page, selector, value) => humanType(page, selector, value),
  type: (page, selector, value) => humanType(page, selector, value),
  click: (page, selector) => humanClick(page, selector),
  press: (page, selector, key) => humanPress(page, selector, key),
  wait: (page, ms) => page.waitForTimeout(ms),
};
