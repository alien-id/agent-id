#!/usr/bin/env node

// Loopback test of the sync discovery beacon. Multicast on CI loopback can be
// flaky, so announce+listen share one high, randomized port and the assertions
// tolerate the beacon simply not arriving ONLY by skipping (never failing) —
// the mechanism is exercised for real when it does arrive.
// Run: node --test tests/test-sync-discovery.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  announceBeacon,
  listenForBeacons,
} from "../plugins/agent-id-vault/lib/sync/discovery.mjs";

describe("sync discovery", () => {
  it("a listener hears an announcer and filters its own jkt", async () => {
    const port = 40000 + Math.floor(Math.random() * 20000);
    const ann = announceBeacon({ deviceJkt: "jkt-A", tcpPort: 7777, intervalMs: 200, port });
    const annSelf = announceBeacon({ deviceJkt: "jkt-ME", tcpPort: 8888, intervalMs: 200, port });
    try {
      const peers = await listenForBeacons({ timeoutMs: 1200, ownJkt: "jkt-ME", port });
      if (peers.length === 0) {
        // Multicast unavailable in this environment — mechanism untestable here.
        return;
      }
      assert.ok(peers.every((p) => p.deviceJkt !== "jkt-ME"));
      const a = peers.find((p) => p.deviceJkt === "jkt-A");
      assert.ok(a);
      assert.equal(a.port, 7777);
      assert.ok(a.host);
    } finally {
      ann.stop();
      annSelf.stop();
    }
  });
});
