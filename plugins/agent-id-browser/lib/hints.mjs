// User-facing hint strings for the browser CLI, kept in a pure module so they
// can be unit-tested without importing bin/cli.mjs (which runs the CLI on load).

export const DEFAULT_PROFILE = "main";

// Session names become filenames under browser-sessions/browser-profiles.
// Keep the public name identical to the filesystem slug rather than trying to
// sanitize a dangerous value differently at each call site.
export function profileName(value = DEFAULT_PROFILE) {
  const name = String(value || DEFAULT_PROFILE);
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) {
    const error = new Error("browser profile name must be 1-64 letters, digits, '_' or '-'");
    error.code = "INVALID_PROFILE_NAME";
    throw error;
  }
  return name;
}

// Re-authenticate an EXISTING profile (headed). Used when a sealed session has
// gone stale (logged out) — headed `login` re-signs into the same session.
export const loginHint = (name) =>
  name === DEFAULT_PROFILE ? "`login`" : "`login --name " + name + "`";

// No profile exists YET. Both ways to create one are valid, but headed `login`
// needs a display, so name the headless `auto-login` path first — it's the only
// one available on a server / in a container.
export const noProfileHint = (name) =>
  `create one first with \`auto-login --cred <LOGIN_CRED>\` (headless, from a stored ` +
  `login credential) or ${loginHint(name)} (headed, needs a display)`;
