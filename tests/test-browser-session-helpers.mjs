#!/usr/bin/env node

// Tests for the pure session-server helpers behind the iframe/tab/download
// additions: frameRefId (ref → frame prefix parsing, the contract every
// ref-based action resolves through), safeFilename (download names must be
// joinable under the sessions dir without traversal), sessionRecord (the
// session file body a viewer discovers a stream by), and
// chromeCompensatedBounds (the viewport→outer-window conversion behind the
// stream's viewer resize). Pure — no browser.
//
// Run: node --test tests/test-browser-session-helpers.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import net from "node:net";
import path from "node:path";

import {
  chromeCompensatedBounds,
  frameRefId,
  probeSession,
  pruneDeadSessions,
  refuseRef,
  safeFilename,
  sessionAlive,
  sessionRecord,
  errorReply,
} from "../plugins/agent-id-browser/lib/session-server.mjs";

test("refuseRef: a ref on a focus-typing action is refused, not dropped", () => {
  // The failure this guards: `type-text --ref e27 --text Switzerland` typed
  // into whatever held focus and reported success, so the country combobox
  // never saw the text and answered "There were no results".
  assert.throws(
    () => refuseRef("type-text", { ref: "e27", text: "Switzerland" }, "type --ref eN --text T"),
    (err) => {
      assert.match(err.message, /takes no --ref/);
      assert.match(err.message, /e27/); // names the ref it was handed
      assert.match(err.message, /type --ref eN/); // and the tool that accepts one
      return true;
    },
  );
});

test("refuseRef: absent/empty refs pass through untouched", () => {
  assert.doesNotThrow(() => refuseRef("type-text", { text: "hi" }, "type"));
  assert.doesNotThrow(() => refuseRef("type-text", { ref: undefined }, "type"));
  assert.doesNotThrow(() => refuseRef("type-text", { ref: null }, "type"));
  assert.doesNotThrow(() => refuseRef("type-text", { ref: "" }, "type"));
});

test("frameRefId: main-frame refs have no frame id", () => {
  assert.equal(frameRefId("e1"), null);
  assert.equal(frameRefId("e42"), null);
});

test("frameRefId: frame-prefixed refs resolve to their prefix", () => {
  assert.equal(frameRefId("f1e3"), "f1");
  assert.equal(frameRefId("f12e7"), "f12");
});

test("frameRefId: junk / partial refs are treated as main-frame (null)", () => {
  // These won't match any [data-aibref] anyway; the important part is that a
  // malformed ref can't be parsed into a surprising frame lookup.
  assert.equal(frameRefId("f1"), null);
  assert.equal(frameRefId("fe3"), null);
  assert.equal(frameRefId("f1e"), null);
  assert.equal(frameRefId(""), null);
  assert.equal(frameRefId(null), null);
  assert.equal(frameRefId(undefined), null);
});

test("safeFilename: separators and traversal are neutralized", () => {
  assert.equal(safeFilename("report.pdf"), "report.pdf");
  assert.ok(!safeFilename("../../etc/passwd").includes("/"));
  assert.ok(!safeFilename("..\\..\\x").includes("\\"));
  assert.notEqual(safeFilename("..")[0], ".");
  assert.equal(safeFilename("a b:c*d.png"), "a_b_c_d.png");
});

test("sessionRecord: the body names its profile — discovery must not guess", () => {
  // The failure this guards: the session file carried streamPort/streamToken/
  // startedAt but not the profile, so a viewer scanning the sessions dir could
  // only take the newest file and could attach to the wrong profile.
  const rec = sessionRecord("work", {
    port: 4001,
    token: "t0k",
    pid: 123,
    headless: true,
    startedAt: 1754300000000,
    streamPort: 4002,
    streamToken: "s3cret",
  });
  assert.equal(rec.profile, "work");
  // The coordinates the viewer connects with ride along untouched.
  assert.equal(rec.streamPort, 4002);
  assert.equal(rec.streamToken, "s3cret");
  assert.equal(rec.startedAt, 1754300000000);
});

test("chromeCompensatedBounds: grows the outer size by the chrome the window ate", () => {
  // A viewer asked for a 390×844 viewport; the straight outer resize yielded
  // 390×757 — the window chrome ate 87px of height. The second pass must ask
  // for exactly that much more.
  assert.deepEqual(
    chromeCompensatedBounds({ width: 390, height: 844 }, { width: 390, height: 757 }),
    { width: 390, height: 931 },
  );
});

test("chromeCompensatedBounds: no second pass when the first one landed", () => {
  assert.equal(chromeCompensatedBounds({ width: 390, height: 844 }, { width: 390, height: 844 }), null);
  // Unmeasurable page (JS-hostile): nothing to compensate against.
  assert.equal(chromeCompensatedBounds({ width: 390, height: 844 }, null), null);
});

test("chromeCompensatedBounds: an OVERSHOOT never shrinks the request", () => {
  // A window-manager minimum can hand back MORE than asked (got > want).
  // Compensating downward would fight the WM forever — the delta clamps at 0,
  // and if both axes overshot there is no second pass at all.
  assert.deepEqual(
    chromeCompensatedBounds({ width: 200, height: 844 }, { width: 500, height: 757 }),
    { width: 200, height: 931 },
  );
  assert.equal(chromeCompensatedBounds({ width: 200, height: 200 }, { width: 500, height: 400 }), null);
});

test("safeFilename: empty / dot-only names fall back, long names are bounded", () => {
  assert.equal(safeFilename(""), "file");
  assert.equal(safeFilename(null), "file");
  assert.equal(safeFilename("..."), "file");
  assert.ok(safeFilename("x".repeat(500)).length <= 80);
});

// --- session liveness + orphan pruning ---------------------------------------

test("sessionAlive: this process is alive, an absurd pid is not", () => {
  assert.equal(sessionAlive({ pid: process.pid }), true);
  assert.equal(sessionAlive({ pid: 0x7ffffff }), false);
  assert.equal(sessionAlive({ pid: 0 }), false);
  assert.equal(sessionAlive({}), false);
  assert.equal(sessionAlive(null), false);
});

// A stand-in for the daemon's control server: reads one line per connection
// and answers with the daemon's own token rule — ok:true for a match, "bad
// token" otherwise. Returns { port, close }.
function daemonStub(expectedToken) {
  const server = net.createServer((sock) => {
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      let msg;
      try {
        msg = JSON.parse(buf.slice(0, nl));
      } catch {
        sock.end(JSON.stringify({ ok: false, error: "bad json" }) + "\n");
        return;
      }
      const reply =
        msg.token === expectedToken
          ? { ok: true, url: "about:blank", title: "", tabs: 1 }
          : { ok: false, error: "bad token" };
      sock.end(JSON.stringify(reply) + "\n");
    });
    sock.on("error", () => {});
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ port: server.address().port, close: () => server.close() });
    });
  });
}

test("probeSession: token identity, not connectability, decides the verdict", async (t) => {
  const stub = await daemonStub("right-token");
  t.after(() => stub.close());
  assert.equal(await probeSession({ port: stub.port, token: "right-token" }), "ours");
  // The incident shape: the port answers, but it is not this session's
  // daemon — a recycled port after a container restart.
  assert.equal(await probeSession({ port: stub.port, token: "stale-token" }), "gone");
  // Nothing listening at all.
  const vacated = await daemonStub("x");
  vacated.close();
  assert.equal(await probeSession({ port: vacated.port, token: "x" }), "gone");
  // No control coordinates: nothing to disprove with.
  assert.equal(await probeSession({ pid: process.pid }), "unsure");
  // A listener that never answers is not proof of death.
  const silent = net.createServer(() => {});
  await new Promise((r) => silent.listen(0, "127.0.0.1", r));
  t.after(() => silent.close());
  assert.equal(
    await probeSession({ port: silent.address().port, token: "x" }, 200),
    "unsure",
  );
});

test("pruneDeadSessions: drops orphans, keeps live sessions and young work dirs", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "aid-prune-"));
  const sessions = path.join(dir, "browser-sessions");
  await fs.mkdir(sessions, { recursive: true });
  const stub = await daemonStub("live-token");
  t.after(() => stub.close());
  t.after(() => fs.rm(dir, { recursive: true, force: true }));

  const write = (name, info) =>
    fs.writeFile(path.join(sessions, `${name}.json`), JSON.stringify(info));
  // A dead daemon with the NEWEST startedAt — the shape that hijacks a viewer
  // picking "the newest session advertising a stream".
  await write("dead", { pid: 0x7ffffff, startedAt: Date.now() + 1e6, streamPort: 1 });
  await write("live", { pid: process.pid, startedAt: 1, streamPort: 2, port: stub.port, token: "live-token" });
  // A live pid whose port is answered by a STRANGER (recycled port after a
  // container restart): the token handshake is what unmasks it.
  await write("impostor", { pid: process.pid, startedAt: 2, streamPort: 3, port: stub.port, token: "someone-elses-token" });
  // No control coordinates at all: the pid answer is all there is — kept.
  await write("legacy", { pid: process.pid, startedAt: 3, streamPort: 4 });
  await fs.writeFile(path.join(sessions, "junk.json"), "not json");
  // Work dirs: one orphaned and old, one orphaned but fresh (a launch in
  // flight), one belonging to the live session.
  const old = path.join(sessions, "dead.work");
  await fs.mkdir(old, { recursive: true });
  const past = new Date(Date.now() - 3 * 60 * 60 * 1000);
  await fs.utimes(old, past, past);
  await fs.mkdir(path.join(sessions, "fresh.work"), { recursive: true });
  await fs.mkdir(path.join(sessions, "live.work"), { recursive: true });

  const pruned = await pruneDeadSessions(dir);

  const left = (await fs.readdir(sessions)).sort();
  assert.deepEqual(left, ["fresh.work", "junk.json", "legacy.json", "live.json", "live.work"]);
  assert.ok(pruned.includes("dead"));
  assert.ok(pruned.includes("impostor"));
  assert.ok(pruned.includes("dead.work"));
});

// ─── a failure the caller can act on ──────────────────────────────────────────────

// The socket reply is everything the caller sees of an action. Flattening a throw to
// its message left "the owner chose the browser" and "the page would not load"
// indistinguishable, so whatever a thrower attaches as `detail` has to survive.
test("errorReply carries the thrower's detail beside the message", () => {
  const err = new Error("fill-otp: the owner closed the code card");
  err.detail = { action: "owner_must_drive", reason: "owner_chose_the_browser", profile: "main" };

  assert.deepEqual(errorReply(err), {
    ok: false,
    error: "fill-otp: the owner closed the code card",
    action: "owner_must_drive",
    reason: "owner_chose_the_browser",
    profile: "main",
  });
});

test("errorReply is unchanged for an ordinary failure", () => {
  assert.deepEqual(errorReply(new Error("boom")), { ok: false, error: "boom" });
});

test("errorReply ignores a detail that is not an object, and never loses the error", () => {
  const err = new Error("boom");
  err.detail = "not an object";

  assert.deepEqual(errorReply(err), { ok: false, error: "boom" });
  assert.equal(errorReply({}).error, "[object Object]");
});
