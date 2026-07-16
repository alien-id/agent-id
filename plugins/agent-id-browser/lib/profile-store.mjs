// Alien Agent ID — Browser profile sealing.
//
// A browser profile (cookies, tokens, the logged-in session) is a *directory*,
// not a small secret, so it doesn't live inside the vault's encrypted JSON.
// Instead the vault holds a per-profile data-encryption key (DEK) in a
// `browser-profile` credential, and the profile is sealed as a sidecar archive
// at <stateDir>/browser-profiles/<name>.tar.enc, encrypted with that DEK
// (AES-256-GCM). Unlocking the vault is therefore required to open a profile.
//
// On launch the sidecar is unsealed into a temp working dir; on close it is
// re-sealed (capturing the refreshed session) and the plaintext working copy is
// wiped. The only plaintext-at-rest window is while the browser is running.

import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const pExecFile = promisify(execFile);

const PROFILES_SUBDIR = "browser-profiles";
const SESSION_COOKIES_FILE = ".agent-id-session-cookies.json";

// Chrome writes large, regenerable caches into the profile; excluding them keeps
// a sealed profile to ~2 MB instead of tens of MB.
const CACHE_EXCLUDES = [
  "--exclude=*Cache*",
  "--exclude=GPUPersistentCache",
  "--exclude=GraphiteDawnCache",
  "--exclude=*ShaderCache",
  "--exclude=Crash Reports",
];

export function profilesDir(stateDir) {
  return path.join(stateDir, PROFILES_SUBDIR);
}

export function sealedProfilePath(stateDir, file) {
  return path.join(profilesDir(stateDir), file);
}

export function newDek() {
  return crypto.randomBytes(32).toString("hex");
}

// Chrome removes session-only cookies from its cookie database on a clean
// shutdown. Keep those cookies inside the plaintext working profile while the
// browser is live so they are included in the encrypted profile sidecar and can
// be restored on the next launch. Persistent cookies remain Chrome-managed.
export async function captureSessionCookies({ context, profileDir }) {
  const cookies = await context.cookies();
  const sessionCookies = cookies.filter((cookie) => cookie.expires === -1);
  const file = path.join(profileDir, SESSION_COOKIES_FILE);
  const tmp = `${file}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(sessionCookies), { mode: 0o600 });
  await fs.rename(tmp, file);
  return sessionCookies.length;
}

export async function restoreSessionCookies({ context, profileDir }) {
  let cookies;
  try {
    cookies = JSON.parse(await fs.readFile(path.join(profileDir, SESSION_COOKIES_FILE), "utf8"));
  } catch (err) {
    if (err?.code === "ENOENT" || err instanceof SyntaxError) return 0;
    throw err;
  }
  if (!Array.isArray(cookies) || cookies.length === 0) return 0;
  const valid = cookies.filter(
    (cookie) =>
      cookie &&
      typeof cookie.name === "string" &&
      typeof cookie.value === "string" &&
      typeof cookie.domain === "string" &&
      typeof cookie.path === "string",
  );
  if (valid.length) await context.addCookies(valid);
  return valid.length;
}

// Layout: iv(12) | gcm-tag(16) | ciphertext
function sealBytes(dekHex, plaintext) {
  const key = Buffer.from(dekHex, "hex");
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
}

function unsealBytes(dekHex, blob) {
  const key = Buffer.from(dekHex, "hex");
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

export async function sealedProfileExists(stateDir, file) {
  try {
    await fs.access(sealedProfilePath(stateDir, file));
    return true;
  } catch {
    return false;
  }
}

// tar the profile dir (excluding caches) → AES-256-GCM seal with the DEK →
// write the sidecar (0600). Returns the sealed byte count.
export async function sealProfile({ stateDir, file, dekHex, sourceDir }) {
  const dir = profilesDir(stateDir);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-bprof-"));
  const tarPath = path.join(tmp, "p.tar");
  try {
    await pExecFile("tar", ["-cf", tarPath, "-C", sourceDir, ...CACHE_EXCLUDES, "."], {
      timeout: 120000,
    });
    const plaintext = await fs.readFile(tarPath);
    const blob = sealBytes(dekHex, plaintext);
    await fs.writeFile(sealedProfilePath(stateDir, file), blob, { mode: 0o600 });
    return { bytes: blob.length };
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
}

// Decrypt the sidecar with the DEK → extract the tar into destDir (created 0700).
export async function unsealProfile({ stateDir, file, dekHex, destDir }) {
  const blob = await fs.readFile(sealedProfilePath(stateDir, file));
  const tar = unsealBytes(dekHex, blob);
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-bprof-"));
  const tarPath = path.join(tmp, "p.tar");
  try {
    await fs.writeFile(tarPath, tar, { mode: 0o600 });
    await fs.mkdir(destDir, { recursive: true, mode: 0o700 });
    await pExecFile("tar", ["-xf", tarPath, "-C", destDir], { timeout: 120000 });
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
}
