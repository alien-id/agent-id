#!/usr/bin/env node

// Tests for the scaled-session pointer calibration: the probe measurement
// (calibratePointer) and the inverse correction (withPointerCal). Driven
// against a stub page — the displacement itself is host-specific, so what is
// testable here is the contract: a displaced probe produces the inverse
// transform, an identity probe produces no correction, and a page that
// cannot run the probe degrades to no correction rather than a guessed one.
//
// Run: node --test tests/test-stream-input-cal.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { calibratePointer, withPointerCal } from "../plugins/agent-id-browser/lib/stream-server.mjs";

// A stub page whose pointer space is displaced by `factor`: the page "sees"
// every dispatched move at dispatched×factor, the way the affected host
// delivers them. evaluate() is called by the calibrator three ways —
// install listener, read the captured point, clean up — modeled by call
// order, which is exactly how the real page experiences it.
function stubPage(factor) {
  let moved = null;
  let calls = 0;
  return {
    moves: [],
    mouse: {
      move(x, y) {
        moved = { x, y };
        return Promise.resolve();
      },
      down() {
        return Promise.resolve();
      },
      up() {
        return Promise.resolve();
      },
    },
    evaluate() {
      calls++;
      if (calls === 1) return Promise.resolve(undefined); // listener install
      if (moved && calls >= 2 && this.__cleaned !== true) {
        return Promise.resolve({ x: moved.x * factor, y: moved.y * factor });
      }
      return Promise.resolve(undefined);
    },
  };
}

test("a displaced pointer space yields the measured factors", async () => {
  const cal = await calibratePointer(stubPage(0.5));
  assert.ok(cal, "displacement must be detected");
  assert.ok(Math.abs(cal.fx - 0.5) < 1e-9 && Math.abs(cal.fy - 0.5) < 1e-9, `got ${JSON.stringify(cal)}`);
});

test("an aligned pointer space yields no correction", async () => {
  assert.equal(await calibratePointer(stubPage(1)), null);
});

test("a page that cannot run the probe yields no correction", async () => {
  const hostile = {
    mouse: { move: () => Promise.resolve() },
    evaluate() {
      return Promise.reject(new Error("Execution context was destroyed"));
    },
  };
  assert.equal(await calibratePointer(hostile), null);
});

test("withPointerCal pre-scales pointer coordinates by the inverse", () => {
  const cal = { fx: 0.5, fy: 0.5 };
  const out = withPointerCal({ type: "input_mouse", eventType: "mousePressed", x: 100, y: 200 }, cal);
  assert.equal(out.x, 200);
  assert.equal(out.y, 400);
  assert.equal(out.eventType, "mousePressed");
});

test("withPointerCal leaves non-pointer messages and identity untouched", () => {
  const key = { type: "input_keyboard", eventType: "char", text: "a" };
  assert.equal(withPointerCal(key, { fx: 0.5, fy: 0.5 }), key);
  const mouse = { type: "input_mouse", eventType: "mouseMoved", x: 10, y: 20 };
  assert.equal(withPointerCal(mouse, null), mouse);
});

test("wheel deltas survive correction untouched — only the position moves", () => {
  const wheel = { type: "input_mouse", eventType: "mouseWheel", x: 100, y: 100, deltaX: 3, deltaY: -24 };
  const out = withPointerCal(wheel, { fx: 0.5, fy: 0.5 });
  assert.equal(out.x, 200);
  assert.equal(out.y, 200);
  assert.equal(out.deltaX, 3);
  assert.equal(out.deltaY, -24);
});
