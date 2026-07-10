// Dependency-free cross-process mutual exclusion for local state files.
//
// This is Lamport's bakery algorithm represented by unique filesystem paths.
// A contender first publishes a `choosing` marker, then chooses 1+max(ticket),
// publishes its unique ticket, and removes the marker. Entrants wait for all
// live choosers and then for the lowest (ticket, unique name). Because every
// path contains a random UUID and is never reused, reaping a dead participant
// cannot suffer the canonical-lock ABA race (unlinking a live successor).

import fs from "node:fs/promises";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === "EPERM";
  }
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function fileLockPrefix(name) {
  return `lock-${createHash("sha256").update(String(name)).digest("hex")}`;
}

export async function withFileLock(
  { directory, name, timeoutMs = 120_000, pollMs = 20, testHooks = null },
  operation,
) {
  if (!directory || !name || typeof operation !== "function") {
    throw new Error("withFileLock requires directory, name, and operation");
  }
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await fs.chmod(directory, 0o700).catch(() => {});

  const prefix = fileLockPrefix(name);
  const id = `${process.pid}.${randomUUID()}`;
  const choosingName = `${prefix}.choosing.${id}`;
  const choosingPath = path.join(directory, choosingName);
  const deadline = Date.now() + timeoutMs;
  let ticketName = null;
  let ticketPath = null;

  const parse = (entry) => {
    let match = new RegExp(
      `^${prefix}\\.choosing\\.(\\d+)\\.([0-9a-f-]{36})$`,
      "i",
    ).exec(entry);
    if (match) return { kind: "choosing", name: entry, pid: Number(match[1]) };
    match = new RegExp(
      `^${prefix}\\.ticket\\.(\\d+)\\.(\\d+)\\.([0-9a-f-]{36})$`,
      "i",
    ).exec(entry);
    if (!match) return null;
    return {
      kind: "ticket",
      name: entry,
      ticket: BigInt(match[1]),
      pid: Number(match[2]),
    };
  };

  const liveParticipants = async () => {
    const parsed = (await fs.readdir(directory)).map(parse).filter(Boolean);
    for (const participant of parsed) {
      if (participant.pid !== process.pid && !processIsAlive(participant.pid)) {
        // Unique, never-reused pathname: safe even if multiple reapers race.
        await fs.unlink(path.join(directory, participant.name)).catch(() => {});
      }
    }
    return (await fs.readdir(directory))
      .map(parse)
      .filter(Boolean)
      .filter((participant) =>
        participant.pid === process.pid || processIsAlive(participant.pid),
      );
  };

  const busyError = () => {
    const err = new Error(`Timed out waiting for local lock '${name}'`);
    err.code = "FILE_LOCK_BUSY";
    return err;
  };

  try {
    // Doorway: no entrant may pass while any live participant is choosing.
    await fs.writeFile(choosingPath, `${process.pid}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    if (testHooks?.afterChoosing) await testHooks.afterChoosing({ choosingPath });
    const existing = await liveParticipants();
    const maxTicket = existing.reduce(
      (max, participant) =>
        participant.kind === "ticket" && participant.ticket > max
          ? participant.ticket
          : max,
      0n,
    );
    const ticket = maxTicket + 1n;
    ticketName = `${prefix}.ticket.${ticket}.${id}`;
    ticketPath = path.join(directory, ticketName);
    await fs.writeFile(ticketPath, `${process.pid}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    await fs.unlink(choosingPath);

    while (true) {
      const participants = await liveParticipants();
      const hasChooser = participants.some(
        (participant) => participant.kind === "choosing",
      );
      const tickets = participants
        .filter((participant) => participant.kind === "ticket")
        .sort((left, right) =>
          left.ticket < right.ticket
            ? -1
            : left.ticket > right.ticket
              ? 1
              : left.name < right.name
                ? -1
                : left.name > right.name
                  ? 1
                  : 0,
        );
      if (!hasChooser && tickets[0]?.name === ticketName) break;
      if (Date.now() >= deadline) throw busyError();
      await delay(pollMs);
    }

    const assertOwned = async () => {
      try {
        await fs.access(ticketPath);
      } catch {
        const err = new Error(`Local lock '${name}' ownership was lost`);
        err.code = "FILE_LOCK_LOST";
        throw err;
      }
    };
    return await operation({ assertOwned, renewAndAssert: assertOwned });
  } finally {
    await fs.unlink(choosingPath).catch(() => {});
    if (ticketPath) await fs.unlink(ticketPath).catch(() => {});
  }
}
