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

// Bootstrap the shared default cookie jar for an L0 identity. Public browsing
// must not require a fake login credential, while explicitly named profiles
// remain opt-in account boundaries and therefore never auto-create.
//
// `allowCreate` is that opt-in, and the ONLY way a named profile is minted
// without a login: an owner-driven sign-in (headed login impossible, auto-login
// refused by the site) needs an empty jar to sign into and seal, and there was
// no way to make one — so "open the browser view and sign in yourself" pointed
// at a profile that could never exist. Callers pass it deliberately; the
// default stays refuse-by-name.
export async function ensureAnonymousDefaultProfile({
  vault,
  stateDir,
  name,
  defaultName = "main",
  allowCreate = false,
}) {
  const existing = vault.get(name);
  if (existing) return existing;
  if (name !== defaultName && !allowCreate) {
    const error = new Error(`no browser-profile named '${name}'`);
    error.code = "NO_PROFILE";
    throw error;
  }

  const file = `${name}.tar.enc`;
  const dek = newDek();
  const empty = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-banon-"));
  try {
    await sealProfile({ stateDir, file, dekHex: dek, sourceDir: empty });
  } finally {
    await fs.rm(empty, { recursive: true, force: true });
  }
  const record = vault.add({
    name,
    type: "browser-profile",
    domains: ["*"],
    description:
      name === defaultName
        ? "Anonymous L0 browser profile (agent-id-browser)"
        : `Empty browser profile for owner-driven sign-in (${name})`,
    dek,
    profileFile: file,
    headless: true,
    exportable: false,
    bootstrap: "anonymous-l0",
    lastSyncedAt: Date.now(),
  });
  await vault.save();
  return record;
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
