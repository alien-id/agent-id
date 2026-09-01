#!/usr/bin/env node

// Unit tests for the pure geometry/timing helpers behind human-like input
// (lib/human-input.mjs). No browser — deterministic via an injected rng.
//
// Run: node --test tests/test-human-input.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  bezierPath,
  keystrokeDelays,
  pointInBox,
  randBetween,
} from "../plugins/agent-id-browser/lib/human-input.mjs";

// Deterministic rng: a fixed repeating sequence so assertions are stable.
function seq(values) {
  let i = 0;
  return () => values[i++ % values.length];
}

describe("bezierPath", () => {
  it("ends exactly at the target and starts moving away from the origin", () => {
    const from = { x: 0, y: 0 };
    const to = { x: 300, y: 120 };
    const pts = bezierPath(from, to, { rng: seq([0.5]) });
    assert.ok(pts.length >= 3, "should have several waypoints");
    const last = pts[pts.length - 1];
    assert.ok(Math.abs(last.x - to.x) < 1e-6 && Math.abs(last.y - to.y) < 1e-6, "last point is the target");
    // first waypoint is past the origin, not the origin itself
    assert.ok(pts[0].x !== from.x || pts[0].y !== from.y);
  });

  it("arcs off the straight line (control point offset), not a rail", () => {
    const from = { x: 0, y: 0 };
    const to = { x: 200, y: 0 }; // horizontal line → any y-deviation is the arc
    // rng=0.9 pushes the control point strongly off-axis
    const pts = bezierPath(from, to, { rng: seq([0.9]) });
    const maxY = Math.max(...pts.map((p) => Math.abs(p.y)));
    assert.ok(maxY > 1, `path should bow off the straight line (maxY=${maxY})`);
  });

  it("scales waypoint count with distance and is finite", () => {
    const short = bezierPath({ x: 0, y: 0 }, { x: 20, y: 0 }, { rng: seq([0.5]) });
    const long = bezierPath({ x: 0, y: 0 }, { x: 600, y: 0 }, { rng: seq([0.5]) });
    assert.ok(long.length > short.length, "longer move → more waypoints");
    for (const p of [...short, ...long]) {
      assert.ok(Number.isFinite(p.x) && Number.isFinite(p.y));
    }
  });

  it("handles a zero-length move without NaN", () => {
    const pts = bezierPath({ x: 10, y: 10 }, { x: 10, y: 10 }, { rng: seq([0.5]) });
    for (const p of pts) assert.ok(Number.isFinite(p.x) && Number.isFinite(p.y));
    const last = pts[pts.length - 1];
    assert.deepEqual({ x: last.x, y: last.y }, { x: 10, y: 10 });
  });
});

describe("keystrokeDelays", () => {
  it("returns one delay per character, all within human bounds", () => {
    const d = keystrokeDelays(12, { rng: seq([0.5]) }); // 0.5 → never a think-pause
    assert.equal(d.length, 12);
    for (const ms of d) {
      assert.ok(ms >= 45 && ms <= 120, `base delay in range: ${ms}`);
    }
  });

  it("injects longer think-pauses when the rng crosses the threshold", () => {
    // A small constant rng forces the <0.08 pause branch on every key, so the
    // resulting delays exceed the 45–120ms base band.
    const d = keystrokeDelays(20, { rng: () => 0.01 });
    assert.ok(
      d.every((ms) => ms > 120),
      "think-pause branch should push delays past the base range",
    );
  });

  it("empty text → no delays", () => {
    assert.deepEqual(keystrokeDelays(0, { rng: seq([0.5]) }), []);
  });
});

describe("pointInBox / randBetween", () => {
  it("pointInBox stays inside the box and off dead-centre", () => {
    const box = { x: 100, y: 200, width: 40, height: 20 };
    const p = pointInBox(box, seq([0.5]));
    assert.ok(p.x > box.x && p.x < box.x + box.width);
    assert.ok(p.y > box.y && p.y < box.y + box.height);
  });

  it("randBetween respects bounds", () => {
    assert.equal(randBetween(10, 20, () => 0), 10);
    assert.equal(randBetween(10, 20, () => 1), 20);
    assert.equal(randBetween(10, 20, () => 0.5), 15);
  });
});
