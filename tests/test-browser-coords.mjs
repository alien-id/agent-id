#!/usr/bin/env node

// Tests for imageToViewport — the screenshot-pixel → viewport-CSS-pixel mapping
// behind the coordinate (vision) actions (click-xy/move-xy/drag-xy). The agent
// points at a pixel in the PNG it read; the PNG is captured at the context's
// devicePixelRatio, so the coordinate must be divided by dpr before it reaches
// page.mouse (which addresses CSS pixels). Getting this wrong lands the cursor
// dpr× off on every retina display. Pure — no browser.
//
// Run: node --test tests/test-browser-coords.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { imageToViewport, regionToClip } from "../plugins/agent-id-browser/lib/session-server.mjs";

test("imageToViewport: dpr=1 is identity", () => {
  assert.deepEqual(imageToViewport(300, 200, 1), { x: 300, y: 200 });
});

test("imageToViewport: retina (dpr=2) halves image coords into CSS px", () => {
  assert.deepEqual(imageToViewport(1800, 1000, 2), { x: 900, y: 500 });
});

test("imageToViewport: fractional dpr scales correctly", () => {
  assert.deepEqual(imageToViewport(300, 150, 1.5), { x: 200, y: 100 });
});

test("imageToViewport: missing/invalid dpr defaults to 1 (no scaling)", () => {
  assert.deepEqual(imageToViewport(300, 200, undefined), { x: 300, y: 200 });
  assert.deepEqual(imageToViewport(300, 200, 0), { x: 300, y: 200 });
  assert.deepEqual(imageToViewport(300, 200, -2), { x: 300, y: 200 });
  assert.deepEqual(imageToViewport(300, 200, NaN), { x: 300, y: 200 });
});

test("imageToViewport: string coords (from CLI flags) are coerced", () => {
  assert.deepEqual(imageToViewport("1800", "1000", "2"), { x: 900, y: 500 });
});

test("imageToViewport: origin stays put under any dpr", () => {
  assert.deepEqual(imageToViewport(0, 0, 2), { x: 0, y: 0 });
});

// regionToClip — screenshot region (image px) → Playwright clip (CSS px)

test("regionToClip: dpr=1 maps region straight to a clip", () => {
  assert.deepEqual(regionToClip([100, 50, 400, 250], 1), { x: 100, y: 50, width: 300, height: 200 });
});

test("regionToClip: retina (dpr=2) halves position and size", () => {
  assert.deepEqual(regionToClip([200, 100, 800, 500], 2), { x: 100, y: 50, width: 300, height: 200 });
});

test("regionToClip: order-agnostic (x1<x0 / y1<y0 still yields positive size)", () => {
  assert.deepEqual(regionToClip([400, 250, 100, 50], 1), { x: 100, y: 50, width: 300, height: 200 });
});

test("regionToClip: string coords (from CLI) are coerced", () => {
  assert.deepEqual(regionToClip(["200", "100", "800", "500"], "2"), { x: 100, y: 50, width: 300, height: 200 });
});
