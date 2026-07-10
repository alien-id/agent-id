#!/usr/bin/env node

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { withFileLock } from "../plugins/agent-id-core/lib/file-lock.mjs";

test("bakery doorway prevents a delayed chooser from overlapping a later contender", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-bakery-lock-"));
  let releaseChooser;
  let chooserPublished;
  const chooserReady = new Promise((resolve) => {
    chooserPublished = resolve;
  });
  const chooserGate = new Promise((resolve) => {
    releaseChooser = resolve;
  });
  let active = 0;
  let maxActive = 0;
  const entered = [];
  const critical = async (label) => {
    active += 1;
    maxActive = Math.max(maxActive, active);
    entered.push(label);
    await new Promise((resolve) => setTimeout(resolve, 20));
    active -= 1;
  };

  try {
    const delayed = withFileLock(
      {
        directory,
        name: "shared-resource",
        pollMs: 2,
        testHooks: {
          async afterChoosing() {
            chooserPublished();
            await chooserGate;
          },
        },
      },
      () => critical("delayed"),
    );
    await chooserReady;
    const later = withFileLock(
      { directory, name: "shared-resource", pollMs: 2 },
      () => critical("later"),
    );

    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.equal(active, 0, "a live choosing marker blocks every ticket holder");
    releaseChooser();
    await Promise.all([delayed, later]);
    assert.equal(maxActive, 1);
    assert.deepEqual(new Set(entered), new Set(["delayed", "later"]));
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
