#!/usr/bin/env node

// Alien Agent ID — Vault plugin CLI.
//
// Portable encrypted credential vault. Backed by a single file
// (~/.agent-id/vault.enc) with a LUKS-style slot construction:
//
//   slot 0: passphrase-wrapped master key (Argon2id-class KDF; scrypt v1)
//   slot 1: agent-key-wrapped master key (fast, unattended unlock)
//
// Subcommands:
//   init                        — create new vault (passphrase + agent-key slots)
//   add                         — add a credential record (typed, domain-scoped)
//   show --name <N>             — retrieve plaintext (use sparingly; prefer the proxy)
//   list                        — metadata only, never plaintext
//   remove --name <N>           — delete a record
//   exec --env VAR=cred.field … -- <cmd>  — run <cmd> with credentials injected
//                                 into its environment (secret never hits disk/argv/stdout)
//   rekey add-passphrase        — append a passphrase slot
//   rekey add-agent-key         — append an agent-key slot
//   rekey add-mobile            — append a phone-approved (mobile) unlock slot
//   rekey add-owner-approval    — append an SSO owner-approval unlock slot
//   rekey remove-slot --id <N>  — remove a slot
//   export --out <PATH>         — copy the encrypted vault file
//   import --in <PATH>          — install an encrypted vault file
//   migrate                     — convert legacy ~/.agent-id/vault/*.json → vault.enc
//
// Unlock inputs:
//   --passphrase-file <path>    — read from file (recommended for automation)
//   --passphrase-env <VAR>      — read from env
//   --unlock-via-agent-key      — explicit; otherwise auto-tried if available
//   (interactive trusted /dev/tty prompt as last resort)

import fs from "node:fs/promises";
import {
  mkdtempSync,
  writeFileSync,
  chmodSync,
  unlinkSync,
  rmSync,
  statSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

import {
  outputError,
  outputJson,
  parseFlags,
  resolveStateDir,
  runCli,
  stderr,
} from "@alien-id/agent-id-core/lib/cli-runtime.mjs";
import {
  readJsonFile,
  statePaths,
} from "@alien-id/agent-id-core/lib/state.mjs";

import {
  exportVault,
  importVault,
  initVault,
  loadAgentPrivateKey,
  openVault,
  readPasskeyChallenges,
  vaultFileExists,
} from "../lib/vault.mjs";
import { registerPasskey, authenticatePasskey } from "../lib/passkey.mjs";
import { readLegacyVault } from "../lib/legacy.mjs";
import { ownerApprovalKekBytes } from "../lib/format.mjs";
import { enrollOwnerApproval } from "../lib/owner-approval.mjs";
import { SignatureEngine } from "@alien-id/agent-id-core/lib/signature-engine.mjs";
import {
  hasTty,
  promptNewPassphrase,
  promptSecret,
  TrustedInputUnavailable,
} from "../lib/trusted-input.mjs";
import {
  ADDRESS_FIELDS,
  ADDRESS_OPTIONAL_FIELDS,
  CARD_FIELDS,
  cardLast4,
  CREDENTIAL_TYPES,
  loginOtpMode,
  LOGIN_OTP_MODES,
  SECRET_FIELDS,
  isTransient,
  validateRecord,
} from "../lib/store.mjs";
import {
  ACCESS_LEVELS,
  credentialHost,
  siteName,
  effectiveAccess,
  isAccessRelaxation,
  isAccessRestricted,
} from "../lib/access.mjs";
import { collectSecret } from "@alien-id/agent-id-core/lib/secure-prompt.mjs";
import { normalizeTotpInput } from "@alien-id/agent-id-core/lib/totp.mjs";
import { generateSolanaKeypair } from "@alien-id/agent-id-core/lib/solana.mjs";
import { generateEvmKeypair } from "@alien-id/agent-id-core/lib/evm.mjs";

// ─── Input helpers ──────────────────────────────────────────────────────────────

async function readStdin() {
  if (process.stdin.isTTY) return null;
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const s = Buffer.concat(chunks).toString("utf8");
  return s.length === 0 ? null : s.replace(/\n$/, "");
}

async function resolvePassphrase(flags, { allowPrompt = true, promptMsg = "Passphrase: " } = {}) {
  if (flags["passphrase-file"]) {
    const raw = await fs.readFile(flags["passphrase-file"], "utf8");
    return raw.replace(/\n$/, "");
  }
  if (flags["passphrase-env"]) {
    const val = process.env[flags["passphrase-env"]];
    if (!val) throw new Error(`Env var ${flags["passphrase-env"]} is not set`);
    return val;
  }
  if (flags.passphrase) return String(flags.passphrase);
  if (allowPrompt && hasTty()) return promptSecret(promptMsg);
  return null;
}

async function resolveValue(flags, fieldName = "credential") {
  if (flags[`${fieldName}-file`]) {
    const raw = await fs.readFile(flags[`${fieldName}-file`], "utf8");
    return raw.replace(/\n$/, "");
  }
  if (flags[`${fieldName}-env`]) {
    const val = process.env[flags[`${fieldName}-env`]];
    if (!val) throw new Error(`Env var ${flags[`${fieldName}-env`]} is not set`);
    return val;
  }
  const piped = await readStdin();
  if (piped != null) return piped;
  if (hasTty()) return promptSecret(`${fieldName}: `);
  return null;
}

// Read a value from --<field>-file / --<field>-env / --<field> (direct), in
// that order. Unlike resolveValue it never falls back to stdin/tty, so several
// of these can be read in one command (e.g. oauth2's secret + refresh token).
async function resolveFileEnvFlag(flags, field) {
  if (flags[`${field}-file`]) {
    const raw = await fs.readFile(flags[`${field}-file`], "utf8");
    return raw.replace(/\n$/, "");
  }
  if (flags[`${field}-env`]) {
    const val = process.env[flags[`${field}-env`]];
    if (!val) throw new Error(`Env var ${flags[`${field}-env`]} is not set`);
    return val;
  }
  if (flags[field] != null) return String(flags[field]);
  return null;
}

function parseDomains(flags) {
  const raw = flags.domains;
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  return String(raw)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// Parse a comma-separated flag into a trimmed string array, or null when absent
// (so callers can distinguish "unset" from "empty").
function parseCsvFlag(raw) {
  if (raw == null) return null;
  const list = (Array.isArray(raw) ? raw : String(raw).split(","))
    .map((s) => String(s).trim())
    .filter(Boolean);
  return list.length ? list : null;
}

async function openWithFlags(flags, { allowPrompt = true } = {}) {
  const stateDir = resolveStateDir(flags);
  const useAgentKey = flags["agent-key"] !== false; // `--no-agent-key` opts out
  const privateKeyPem = useAgentKey ? await loadAgentPrivateKey(stateDir) : null;
  const hasPassphraseFlag =
    flags["passphrase-file"] || flags["passphrase-env"] || flags.passphrase;

  // 1. Agent-key (fast, unattended) — unless a passphrase was explicitly supplied.
  if (privateKeyPem && !hasPassphraseFlag) {
    try {
      return await openVault({ stateDir, privateKeyPem });
    } catch (err) {
      if (err.code !== "VAULT_UNLOCK_FAILED") throw err;
      // fall through
    }
  }

  // 2. An explicit passphrase source (file/env/arg).
  if (hasPassphraseFlag) {
    const passphrase = await resolvePassphrase(flags, { allowPrompt: false });
    return openVault({ stateDir, privateKeyPem, passphrase });
  }

  // 3. A passkey slot → run the WebAuthn ceremony in the browser (preferred over a
  //    /dev/tty prompt; a passkey vault has no passphrase to type).
  if (allowPrompt) {
    const challenges = await readPasskeyChallenges(stateDir);
    if (challenges.length) {
      const prfSecret = await authenticatePasskey(challenges[0]);
      return openVault({ stateDir, passkeyPrfSecret: prfSecret });
    }
  }

  // 4. Interactive passphrase prompt (a dev vault, on a TTY).
  const passphrase = await resolvePassphrase(flags, { allowPrompt });
  return openVault({ stateDir, privateKeyPem, passphrase });
}

// ─── Commands ───────────────────────────────────────────────────────────────────

async function cmdInit(flags) {
  const stateDir = resolveStateDir(flags);
  if (await vaultFileExists(stateDir)) {
    outputError(`Vault already exists at ${statePaths(stateDir).vaultFile}`);
    return;
  }

  // Choose the unlock method. `--unlock passkey|passphrase|agent-key` is explicit;
  // otherwise the default is agent-key (user mode). The hard-boundary methods
  // (passkey, passphrase — the agent doesn't hold them) default to NO agent-key
  // slot, so the agent can't silently self-unlock.
  const method = flags.unlock ? String(flags.unlock) : null;
  if (method && !["passkey", "passphrase", "agent-key"].includes(method)) {
    return outputError(`--unlock must be passkey | passphrase | agent-key (got '${method}')`);
  }

  let passphrase = await resolvePassphrase(flags, { allowPrompt: false });
  const dev = flags.dev === true || passphrase != null || method === "passphrase";

  // Passkey: enroll via the secure form (Touch ID / Face ID / security key).
  let passkey = null;
  if (method === "passkey") {
    try {
      passkey = await registerPasskey({
        deviceLabel: flags["device-label"] || null,
      });
    } catch (err) {
      return outputError(`passkey registration failed: ${err.message}`);
    }
  }

  // Dev/passphrase path with no passphrase given: prompt on an interactive TTY.
  if (dev && passphrase == null && method !== "passkey" && hasTty()) {
    passphrase = promptNewPassphrase({
      prompt: "New vault passphrase (dev mode): ",
      confirm: "Confirm passphrase: ",
    });
  }

  // Agent-key default: on, EXCEPT when passkey/passphrase was the chosen method.
  const agentKeyDefault = !(method === "passkey" || method === "passphrase");
  const useAgentKey =
    flags["agent-key"] === true || (flags["agent-key"] !== false && agentKeyDefault);
  const privateKeyPem = useAgentKey ? await loadAgentPrivateKey(stateDir) : null;
  const agentId = privateKeyPem
    ? (await readJsonFile(statePaths(stateDir).mainKey, null))?.agentId || null
    : null;

  try {
    const result = await initVault({
      stateDir,
      passphrase,
      privateKeyPem,
      agentId,
      passkey,
      dev,
    });
    stderr(
      `Vault initialized (${result.mode} mode, ${result.slots} slot${
        result.slots > 1 ? "s" : ""
      }): ${result.path}`
    );
    if (passkey) {
      stderr("Unlock with your passkey (the agent can't unlock it itself). Add `rekey add-passkey` for more devices.");
    } else if (result.mode === "user") {
      stderr(
        "User mode: unlock via agent-key or owner-approval (Alien app). A passphrase " +
          "can never be added, and this vault cannot be converted to dev mode."
      );
    }
    outputJson({ ok: true, ...result });
  } catch (err) {
    outputError(err.message);
  }
}

// Secret fields each type needs from the out-of-band form (--form). Non-secret
// metadata (header/param/cookie name, token endpoint, client id) still comes from
// flags; only the secret VALUE is typed by the human into the browser form.
// The card the owner reads, in three parts. The credential's `name` is not among
// them while there is a host to show — it is an internal key the agent picks, and
// it reached the screen verbatim: someone was asked to "Add credential:
// airbnb-passwordless-again", which names the agent's second attempt rather than
// the site in front of them. With no host derivable the name is still the last
// thing left, and better than a card that names nothing at all.
//
// The title says what is being asked of them and nothing else. What it is FOR
// goes in the line below, where there is room to say it in words: the site, and
// what happens to what they type. The type and the domain allowlist are gone
// from both — they are how the agent addresses a credential, and `*.booking.com`
// reads to a person as a typo.
const CARD_TITLE = "Enter it securely";

function formDescription({
  name,
  type,
  loginUrl,
  domains,
  access,
  passwordless,
}) {
  // A card gets its own sentence, and skips the `ro` grant below, because that
  // grant reads here as the opposite of what it means. On a login it says the agent
  // may read the account and not change it. On the screen where somebody is typing
  // a card number, "the agent can read this" is the thing they are most afraid of —
  // and it would sit directly above a security note promising that it never sees
  // the value. The stored name is left out for the reason given above CARD_TITLE:
  // it is a key the agent invented, and this is not where it belongs.
  if (type === "card") {
    const kept = saveToVaultBoxEnabled()
      ? " Turn off Save to vault to use it for this purchase only."
      : "";
    return (
      "A payment card for the agent to pay with. It asks you to approve every " +
      `payment before using it — the amount and the site, every time.${kept}`
    );
  }
  const site = siteName(credentialHost({ loginUrl, domains }));
  const lead = type === "login"
    ? `${site ? `${site} sign-in` : `Sign-in for ${name}`}. You type it on a sealed screen.`
    : `${site ? `A credential for ${site}` : `Credential ${name}`}. You type it on a sealed screen.`;
  // A passwordless card asks for an identifier and stops; nothing visibly happens
  // when it is submitted, because the site has yet to send anything.
  const step = type === "login" && passwordless ? " The code comes at sign-in." : "";
  // `ro` is a grant being made in the moment of typing, so it stays on the card
  // even though the rest of the metadata does not.
  const grant = access === "ro" ? " The agent can read this, never change it." : "";
  const once =
    type === "login" && saveToVaultBoxEnabled() ? " Turn off Save to vault to use it once." : "";

  return `${lead}${step}${grant}${once}`;
}


function formFieldsForType(type, flags) {
  switch (type) {
    case "bearer":
      return [{ name: "value", label: "Token / bearer value" }];
    case "header":
      return [
        { name: "value", label: `Value for header "${flags["header-name"]}"` },
      ];
    case "query":
      return [
        {
          name: "value",
          label: `Value for query param "${flags["param-name"]}"`,
        },
      ];
    case "cookie":
      return [
        { name: "value", label: `Value for cookie "${flags["cookie-name"]}"` },
      ];
    case "basic":
      return [
        { name: "username", label: "Username", secret: false },
        { name: "password", label: "Password" },
      ];
    case "totp":
      return [{ name: "secret", label: "TOTP secret (base32)" }];
    case "secret":
      return [
        {
          name: "value",
          label: "Secret — SSH/RSA private key, PEM, JSON, or token",
          multiline: true,
        },
      ];
    case "cookie-jar":
      return [{ name: "jar", label: "Cookie jar JSON", multiline: true }];
    case "oauth2":
      return [
        { name: "client-secret", label: "Client secret", required: false },
        { name: "refresh-token", label: "Refresh token" },
      ];
    case "login":
      return [
        // A passwordless site takes whatever it can mail or text a code to, and
        // Airbnb's first screen says so outright ("Phone number or email"). The
        // owner read "Username / email", entered a mail address, and waited for a
        // letter the site had sent as an SMS. A password site keeps the old label:
        // there the field really can be a username.
        {
          name: "username",
          label: flags.passwordless
            ? "Email or phone number"
            : "Username / email",
          secret: false,
        },
        // A passwordless site has none to store — the only secret is the code that
        // arrives out of band, collected at sign-in time rather than here. That
        // leaves this form a single field, which is the whole point.
        ...(flags.passwordless
          ? []
          : [{ name: "password", label: "Password" }]),
        // Only ask for the 2FA seed up front when the policy is `totp`; otherwise
        // it's added later (when available) via `set-totp`.
        ...(flags.otp === "totp"
          ? [
              {
                name: "totpSecret",
                label: "TOTP secret (base32) or otpauth:// URI",
              },
            ]
          : []),
        // The owner's say over whether the credential outlives this sign-in. On
        // by default; unticked, the record is kept only until the sign-in that
        // asked for it completes (see `transient` below). It rides the same
        // sealed form as the values, so nothing between here and the phone sees
        // the choice — the value comes back as the string "true" / "false", and
        // a client that never rendered the row sends nothing, which is "true".
        ...(saveToVaultBoxEnabled() ? [SAVE_TO_VAULT_FIELD] : []),
      ];
    case "card":
      return [
        // These four names are a wire contract, not labels: the secure-input
        // envelope carries no field type, so the name a value is sealed under is
        // what picks the phone's keyboard and the paired expiry/code row. Renaming
        // one downgrades that screen to a plain text box and nothing fails.
        //
        // `secret` masks the input as it is typed and nothing more — storage
        // secrecy is `SECRET_FIELDS`, by name, and covers all four regardless. Only
        // the code keeps the mask: the rest is copied off a card in hand, and a
        // masked number cannot be read back and checked.
        { name: "cardNumber", label: "Card number", secret: false },
        { name: "cardExpiry", label: "Expiry (MM/YY)", secret: false },
        { name: "cardSecurityCode", label: "Security code" },
        { name: "cardholderName", label: "Name on card", secret: false },
        // The same box the login form offers, and for the same reason: whether
        // the record outlives the thing it was typed for is the owner's to say.
        // A card is the one credential where the answer is worth asking twice,
        // and until it was here the owner typed a card and was told nothing
        // about where it went.
        ...(saveToVaultBoxEnabled() ? [SAVE_CARD_FIELD] : []),
      ];
    default:
      return null;
  }
}

// Off until the phone draws the box: a client that predates it renders a
// checkbox field as an empty text box under a line telling the owner to turn it
// off. Set AGENT_ID_SAVE_TO_VAULT_BOX=1 once the iOS build carrying the switch
// has shipped; the gate itself goes in the release after that.
function saveToVaultBoxEnabled(env = process.env) {
  return env.AGENT_ID_SAVE_TO_VAULT_BOX === "1";
}

// The billing-address form. Not raised when the card is stored: whether the
// shop will ask for an address, and for which boxes, is known only once its
// form is in front of the agent, so `set-address` raises this then — and only
// when the vault has no address to answer with. The same contract as the card's
// four: the name a value is sealed under is what the phone draws it by.
//
// The billing page, in the order the design draws it. The second street line,
// the state and the postal code are optional — most countries have no states
// and some sixty issue no postal code, and a checkout that insists on one
// refuses the fill before anything is spent. The rest is required, which is
// what makes the phone's Done wait for it.
const ADDRESS_FIELD_SPECS = Object.freeze([
  { name: "billingFirstName", label: "First name", secret: false },
  { name: "billingLastName", label: "Last name", secret: false },
  { name: "billingCountry", label: "Country", secret: false },
  { name: "billingAddressLine1", label: "Address", secret: false },
  { name: "billingAddressLine2", label: "Apt, suite (optional)", secret: false, required: false },
  { name: "billingCity", label: "City", secret: false },
  { name: "billingState", label: "State", secret: false, required: false },
  { name: "billingPostalCode", label: "ZIP", secret: false, required: false },
]);

// Ticked, the address becomes a credential of its own that the next card can
// name; unticked, the same values ride on the card and no other card sees them.
// Either way it is stored — a card that cannot be billed cannot be paid with.
const SAVE_BILLING_ADDRESS_FIELD = Object.freeze({
  name: "saveBillingAddress",
  label: "Save address to Secure Vault for future use",
  kind: "checkbox",
  default: "true",
  secret: false,
  required: false,
});

const SAVE_TO_VAULT_FIELD = Object.freeze({
  name: "saveToVault",
  label: "Save to vault",
  kind: "checkbox",
  default: "true",
  secret: false,
  required: false,
});

// The same box under the same name — the clients find it by name — with the
// wording the card screen needs. A sign-in's "Save to vault" says nothing about
// where it goes, and on the one screen where the owner is typing a card number
// that is the thing they are looking for.
const SAVE_CARD_FIELD = Object.freeze({
  ...SAVE_TO_VAULT_FIELD,
  label: "Save card to Secure Vault for future use",
});

// The billing-address form, raised by `set-address` once a checkout has asked
// for an address the vault cannot answer.
//
// An owner's decision — closing it, choosing the browser, letting it expire —
// is thrown as it is: this form is the whole command, so its outcome is the
// command's, and `cmdSetAddress` is where it is told apart from a fault.
async function collectBillingAddress(name) {
  const out = await collectSecret({
    title: "Billing address",
    description:
      "The address this card is billed to. Your bank checks it against the " +
      "card, so a payment without it is often declined.",
    fields: [
      ...ADDRESS_FIELD_SPECS,
      ...(saveToVaultBoxEnabled() ? [SAVE_BILLING_ADDRESS_FIELD] : []),
    ],
    label: `enter the billing address for "${name}"`,
    security: "I never see it. It goes straight into your encrypted vault.",
  });
  return out.values;
}

// Where the billing address the owner just typed ends up.
//
// Ticked — the design's "for future use" — it becomes a credential of its own,
// and the card keeps only its name, so the next card can be billed to the same
// address without asking again. Unticked, the same values ride on the card and
// no other card can see them. Either way it is stored: an address is not
// optional decoration, it is what the issuer checks.
function attachBillingAddress(record, formValues, vault) {
  if (!formValues) return;
  const typed = {};
  for (const field of ADDRESS_FIELDS) {
    const value = (formValues[field] || "").trim();
    if (value.length > 0) typed[field] = value;
  }
  // A form that came back with none of it leaves the card as it was: a card
  // without an address is still a card — the fill simply has nothing to type
  // into a checkout's address boxes.
  if (Object.keys(typed).length === 0) return;
  if (typed.billingCountry) typed.billingCountry = typed.billingCountry.toUpperCase();
  // A card either names a stored address or carries its own, never both — so
  // whichever way this one goes, what it held before is cleared first, or the
  // record fails validation on the way in.
  delete record.billingAddress;
  for (const field of ADDRESS_FIELDS) delete record[field];

  if (formValues.saveBillingAddress === "false") {
    Object.assign(record, typed);
    return;
  }
  const name = billingAddressName(typed, vault);
  vault.add({
    name,
    type: "address",
    domains: [],
    access: "ro",
    description: "Billing address",
    ...typed,
  });
  record.billingAddress = name;
}

// The name a stored address gets, and what it must not say.
//
// Its fields are sealed, so the name cannot be derived from them: `list` is what
// the agent sees, and a name like `billing-us-94025` would hand over the very
// thing `show` refuses. So the name carries nothing — and re-use is decided by
// comparing the values instead, which is the real question anyway. Typing the
// same address twice updates one record; typing a different one adds another.
function billingAddressName(typed, vault) {
  const same = (record) =>
    record.type === "address" &&
    ADDRESS_FIELDS.every((field) => (record[field] ?? "") === (typed[field] ?? ""));
  const existing = vault.list().find((record) => same(vault.get(record.name)));
  if (existing) return existing.name;
  for (let index = 1; index < 1000; index += 1) {
    if (!vault.get(`billing-${index}`)) return `billing-${index}`;
  }
  return `billing-${Date.now()}`;
}

// A credential the owner chose not to keep lives this long at most: longer than
// the card's own 15-minute budget plus one auto-login, so a sign-in that is
// under way never loses its credential mid-run, and short enough that "not
// saved" stays true when nothing consumes it.
const TRANSIENT_TTL_MS = 30 * 60 * 1000;

// A card is not a sign-in. Nothing consumes it at a known moment: the purchase
// it was typed for runs as the agent's own turns, through an approval the owner
// answers from their phone, and half an hour is well inside that. A card that
// disappeared mid-checkout would be a worse defect than the one the box fixes,
// so an unkept card is measured in a day — long enough that no purchase loses
// it, short enough that "not saved" still means something.
const CARD_TRANSIENT_TTL_MS = 24 * 60 * 60 * 1000;

function transientTtlMs(type) {
  return type === "card" ? CARD_TRANSIENT_TTL_MS : TRANSIENT_TTL_MS;
}

// The owner's answer to the "Save to vault" box, taken OUT of the form values
// so it can never be written into a record as if it were a field. Absent means
// kept — the card of an older client, or one raised with the box off, has none.
function takeSaveToVault(formValues) {
  if (!formValues || !(SAVE_TO_VAULT_FIELD.name in formValues)) return true;
  const raw = formValues[SAVE_TO_VAULT_FIELD.name];
  delete formValues[SAVE_TO_VAULT_FIELD.name];
  return String(raw) !== "false";
}

// A card the OWNER ended, told apart from a card that broke. All three are
// `ok:false`, and the difference is what the caller does next: a fault invites a
// retry, and a decision must not — re-raising a card someone just closed is the
// loop this exists to stop. `use_browser` is the one that carries an `action`,
// because it is the only one where something else should happen instead.
function ownerEndedTheCard(err, extra = {}) {
  if (err?.code === "FORM_USE_BROWSER") {
    return {
      error: "FORM_USE_BROWSER",
      action: "owner_must_drive",
      reason: "owner_chose_the_browser",
      retryable: false,
      message:
        "The owner closed the card and asked to sign in from the browser themselves. " +
        "That is not a refusal. Do not raise this card again and do not ask for the value here.",
      ...extra,
    };
  }
  if (err?.code === "FORM_CANCELLED") {
    return {
      error: "FORM_CANCELLED",
      reason: "owner_dismissed_the_card",
      retryable: false,
      message:
        "The owner dismissed the card — they were asked and said no. " +
        "Do not raise it again unless they ask for it.",
      ...extra,
    };
  }
  if (err?.code === "FORM_TIMEOUT") {
    return {
      error: "FORM_TIMEOUT",
      reason: "card_timed_out",
      retryable: false,
      message:
        "The card expired before the owner answered. Ask them to be ready, then run this again.",
      ...extra,
    };
  }

  return null;
}

async function cmdAdd(flags) {
  const name = flags.name;
  const type = flags.type;
  if (!name) return outputError("--name <NAME> is required");
  if (!type) return outputError(`--type <${CREDENTIAL_TYPES.join("|")}> is required`);
  if (!CREDENTIAL_TYPES.includes(type)) {
    return outputError(`Unknown type: ${type}. Allowed: ${CREDENTIAL_TYPES.join(", ")}`);
  }
  const access = flags.access != null ? String(flags.access) : null;
  if (access && !ACCESS_LEVELS.includes(access)) {
    return outputError(`--access must be one of ${ACCESS_LEVELS.join(", ")}`);
  }
  // A card is sealed by its access level, so the level is not the caller's to pick:
  // `rw` leaves `show` returning the number, the expiry and the code in clear, and the
  // caller here is the agent. Refused rather than quietly corrected, so a caller that
  // asked for it learns that it was refused.
  if (type === "card" && access != null && access !== "ro") {
    return outputError(
      "A card is stored read-only. Where its values may go is decided by the owner when " +
        "they approve a payment, not by --access.",
    );
  }
  let domains = parseDomains(flags);
  // Declaring where a card may be used would be granting oneself a merchant: the
  // owner's per-payment approval is what says where it may go.
  if (type === "card" && domains.length > 0) {
    return outputError(
      "A card takes no --domains. Where it may be used is decided by the owner when they " +
        "approve a payment, not here.",
    );
  }
  if (domains.length === 0) {
    // `secret` is not host-scoped (it's used via exec/file, not the HTTP proxy),
    // so it doesn't need a domain allowlist; everything else is default-deny.
    if (type === "secret") domains = ["*"];
    // A card carries no allowlist at all: it stays empty, which matches no host, so
    // default-deny holds literally. Nothing writes to it — what says where a card may
    // be typed is the merchant host on the owner's approved payment intent.
    else if (type === "card") domains = [];
    else if (type === "login") {
      // `login` IS host-scoped — the browser gates fill-secret / fill-otp and every
      // auto-login recipe step on this list. Default to the loginUrl host; falling
      // back to ["*"] (as this did) minted a credential that could never be typed
      // anywhere, because "*" is a not-applicable placeholder and matches no host.
      let host = null;
      if (flags["login-url"]) {
        try {
          host = new URL(String(flags["login-url"])).hostname;
        } catch {
          /* invalid URL caught later by validateRecord */
        }
      }
      if (!host) {
        return outputError(
          "login needs --domains <host[,host…]> or a --login-url to derive it from (default-deny)"
        );
      }
      domains = [host];
    } else return outputError("--domains <host[,host…]> is required (default-deny)");
  }

  // Login-shape flags are checked before anything is collected: `--passwordless`
  // decides how many fields the form has, so getting it wrong must fail here and
  // not after the owner has typed into the wrong card.
  let recipe = null;
  if (type === "login") {
    // Against the resolved mode, not the raw flag: a silent `--otp` now resolves
    // to `interactive`, which is exactly what a passwordless sign-in needs, and
    // testing the flag demanded the owner spell out the default.
    if (
      flags.passwordless &&
      loginOtpMode({ otp: flags.otp ? String(flags.otp) : null }) === "none"
    ) {
      return outputError(
        "--passwordless needs --otp interactive (a code mailed/SMSed at sign-in) or --otp totp"
      );
    }
    if (flags.recipe != null) {
      try {
        recipe = JSON.parse(String(flags.recipe));
      } catch (err) {
        return outputError(`--recipe is not valid JSON: ${err.message}`);
      }
    }
  }

  // --form: collect the secret value(s) out of band via a one-shot localhost
  // browser form. The agent supplies the metadata; the human types the value into
  // the form, so it never enters the agent's stdin/stdout/transcript. Validate the
  // required metadata flags FIRST so we don't prompt and then reject.
  let formValues = null;
  if (flags.form) {
    if (type === "header" && !flags["header-name"]) return outputError("--header-name is required");
    if (type === "query" && !flags["param-name"]) return outputError("--param-name is required");
    if (type === "cookie" && !flags["cookie-name"]) return outputError("--cookie-name is required");
    if (type === "oauth2" && (!flags["token-endpoint"] || !flags["client-id"])) {
      return outputError("oauth2 --form needs --token-endpoint and --client-id");
    }
    const specs = formFieldsForType(type, flags);
    if (!specs) {
      return outputError(`--form is not supported for type ${type}`);
    }
    try {
      // collectSecret routes through the secure-prompt resolver (browser form →
      // /dev/tty → hosted harness), so this works where no GUI browser is present.
      const out = await collectSecret({
        title: CARD_TITLE,
        description: formDescription({
          name,
          type,
          loginUrl: flags["login-url"],
          domains,
          access,
          passwordless: flags.passwordless,
        }),
        fields: specs,
        label: `enter the "${name}" secret`,
        // The promise, not the primitive: the algorithm names told the owner nothing
        // they could act on and read as a warning label on a screen meant to
        // reassure. It has to stay true, though — this card's whole purpose is to
        // store the value, so "isn't saved anywhere" would be a lie told on the one
        // screen where trust is the point.
        security: "I never see it. It goes straight into your encrypted vault.",
      });
      formValues = out.values;
    } catch (err) {
      const ended = ownerEndedTheCard(err, {
        name,
        type,
        url: flags["login-url"] || null,
      });
      if (ended) {
        outputJson({ ok: false, stored: false, ...ended });
        process.exitCode = 1;
        return;
      }
      return outputError(`secure form: ${err.message}`);
    }
  }

  const keep = takeSaveToVault(formValues);

  // Read a secret either from the form (--form) or the existing file/env/stdin/tty
  // channels — never from argv.
  const secret = (field) =>
    formValues ? Promise.resolve(formValues[field] ?? "") : resolveValue(flags, field);
  const secretFileEnv = (field) =>
    formValues ? Promise.resolve(formValues[field] ?? "") : resolveFileEnvFlag(flags, field);

  const vault = await openWithFlags(flags);
  try {
    const record = {
      name,
      type,
      domains,
      description: flags.description || null,
    };
    if (flags["upstream-scheme"] != null) {
      record.upstreamScheme = String(flags["upstream-scheme"]);
    }
    if (access) record.access = access;

    // Upserting must never silently widen access: preserve the stored policy
    // when no --access flag is given, and refuse a widening flag — only
    // `set-access` (owner-confirmed) may relax.
    const existing = vault.get(name);
    if (existing) {
      if (!access && existing.access != null) record.access = existing.access;
      if (existing.accessRules != null) record.accessRules = existing.accessRules;
      if (isAccessRelaxation(existing, record)) {
        return outputError(
          `Credential '${name}' has access level '${effectiveAccess(
            existing
          )}' — re-adding it ` +
            `with '${access}' would widen what the agent may do. Use \`set-access\` (owner-confirmed).`
        );
      }
    }
    // A credential the owner already keeps stays kept: turning the box off on a
    // re-add would otherwise swap a saved record for one that is deleted after
    // the next sign-in, which is not what a card about THIS sign-in asked.
    const keepsExisting = existing != null && !isTransient(existing);
    const transient = !keep && !keepsExisting;

    switch (type) {
      case "bearer":
      case "secret": {
        const value = await secret("value");
        if (!value) return outputError("Value required (--value-file / --value-env / stdin / --form)");
        record.value = value;
        break;
      }
      case "basic": {
        record.username = formValues ? formValues.username : flags.username;
        record.password = await secret("password");
        if (!record.username || !record.password) {
          return outputError("--username and password input required for basic auth");
        }
        break;
      }
      case "header": {
        record.headerName = flags["header-name"];
        record.value = await secret("value");
        if (!record.headerName || !record.value) {
          return outputError("--header-name and value input required");
        }
        break;
      }
      case "query": {
        record.paramName = flags["param-name"];
        record.value = await secret("value");
        if (!record.paramName || !record.value) {
          return outputError("--param-name and value input required");
        }
        break;
      }
      case "cookie": {
        record.cookieName = flags["cookie-name"];
        record.value = await secret("value");
        if (!record.cookieName || !record.value) {
          return outputError("--cookie-name and value input required");
        }
        break;
      }
      case "totp": {
        record.secret = await secret("secret");
        record.period = Number(flags.period || 30);
        record.digits = Number(flags.digits || 6);
        record.algorithm = flags.algorithm || "SHA1";
        if (!record.secret) return outputError("TOTP secret required");
        break;
      }
      case "cookie-jar": {
        const json = await secret("jar");
        if (!json) return outputError("Cookie jar JSON required");
        record.cookies = JSON.parse(json);
        break;
      }
      case "solana-keypair":
      case "evm-keypair": {
        return outputError(
          `${type} credentials are created with \`agent-id-vault generate\` — ` +
            "the private key is generated inside the vault and never crosses a process boundary"
        );
      }
      case "oauth2": {
        record.tokenEndpoint = flags["token-endpoint"];
        record.clientId = flags["client-id"];
        const clientSecret = await secretFileEnv("client-secret");
        if (clientSecret) record.clientSecret = clientSecret;
        if (flags.scope) record.scope = String(flags.scope);
        // The refresh token is the long-lived secret — from form/file/env/stdin, never argv.
        record.refreshToken = await secret("refresh-token");
        if (!record.tokenEndpoint || !record.clientId || !record.refreshToken) {
          return outputError(
            "oauth2 needs --token-endpoint, --client-id, and a refresh token " +
              "(--refresh-token-file / --refresh-token-env / stdin / --form)"
          );
        }
        break;
      }
      case "card": {
        // Form-only, and not for tidiness: a PAN passed as a flag is a PAN in the
        // process table, in `ps` output, and in whatever shell history saw it.
        if (!formValues) {
          return outputError("A card is typed into the secure form — re-run with --form");
        }
        // Copied off a card face, so the separators the labels invite arrive with
        // the values — a slash in the expiry, groups of four in the number. The
        // stored form is bare digits, which is what the validators and the fill
        // both expect, so strip on the way in rather than refuse the owner's
        // typing.
        const digitsOf = (value) => (value || "").replace(/\D/g, "");
        record.cardNumber = digitsOf(formValues.cardNumber);
        record.cardExpiry = digitsOf(formValues.cardExpiry);
        record.cardSecurityCode = digitsOf(formValues.cardSecurityCode);
        record.cardholderName = formValues.cardholderName || "";
        // A read of this record is a complete card-not-present instrument, so it
        // never comes back out: `ro` makes it access-restricted, which is what
        // `show` redacts every SECRET_FIELD on. Set, not defaulted — a caller that
        // passed anything else was already refused above. Not `exportable: false` —
        // that means "generated in-vault, never typed into a page", which is the one
        // thing a card exists to do, and assertFillAllowed enforces it literally.
        record.access = "ro";
        attachBillingAddress(record, formValues, vault);
        break;
      }
      case "login": {
        record.username = formValues ? formValues.username : flags.username;
        if (!record.username) {
          return outputError("--username input required for login");
        }
        if (flags.passwordless) {
          record.passwordless = true;
        } else {
          record.password = await secret("password");
          if (!record.password) {
            return outputError("password input required for login (or pass --passwordless)");
          }
        }
        // Through the store's normaliser, so what a silent `--otp` means here is
        // the same thing a silent `otp` field means to every reader of the record.
        const otp = loginOtpMode({
          otp: flags.otp ? String(flags.otp) : null,
        });
        record.otp = otp;
        if (otp === "totp") {
          // Seed from the form, or --totp-secret-file/-env. Accepts a raw base32
          // secret or a full otpauth:// URI; parsed + validated in-vault.
          const seedInput = formValues
            ? formValues.totpSecret
            : await secretFileEnv("totp-secret");
          if (!seedInput) {
            return outputError(
              "otp totp needs a TOTP seed (--form, --totp-secret-file/-env) — " +
                "or add it later with `set-totp`"
            );
          }
          let parsed;
          try {
            parsed = normalizeTotpInput(seedInput);
          } catch (err) {
            return outputError(`TOTP seed: ${err.message}`);
          }
          record.totpSecret = parsed.secret;
          if (parsed.period) record.period = parsed.period;
          if (parsed.digits) record.digits = parsed.digits;
          if (parsed.algorithm) record.algorithm = parsed.algorithm;
        }
        if (flags["login-url"]) record.loginUrl = String(flags["login-url"]);
        if (recipe != null) record.recipe = recipe;
        if (flags.profile) {
          // The sealed browser-profile is a separate record sharing this name
          // namespace — it must not collide with the login credential's own name.
          if (String(flags.profile) === name) {
            return outputError(
              `--profile '${flags.profile}' must differ from the login name '${name}' ` +
                "(the login and its sealed browser-profile are separate vault records)"
            );
          }
          record.profile = String(flags.profile);
        }
        break;
      }
    }

    if (transient) record.transient = { until: Date.now() + transientTtlMs(type) };

    const transientFor = type === "card" ? "this purchase" : "this sign-in";
    const stored = vault.add(record);
    await vault.save();
    stderr(
      `Added credential '${name}' (${type}) for ${domains.join(", ")}` +
        `${stored.access ? ` — access: ${stored.access}` : ""}` +
        `${transient ? ` — for ${transientFor} only` : ""}.`
    );
    outputJson({
      ok: true,
      name: stored.name,
      type: stored.type,
      domains: stored.domains,
      access: effectiveAccess(stored),
      createdAt: stored.createdAt,
      updatedAt: stored.updatedAt,
      ...(transient
        ? {
            transient: true,
            note:
              type === "card"
                ? "The owner chose not to keep this card. It exists for the purchase it was " +
                  "typed for, and is dropped on the next vault open after 24 hours. Pay with " +
                  "it now; do not offer it as a stored card later."
                : "The owner chose not to keep this credential. It exists for this sign-in " +
                  "only: auto-login removes it once the sign-in completes, and otherwise it " +
                  "is dropped on the next vault open after 30 minutes.",
          }
        : {}),
      ...(!keep && keepsExisting
        ? {
            note:
              `The owner turned off Save to vault, but '${name}' was already saved; ` +
              "the stored credential was updated and kept.",
          }
        : {}),
    });
  } finally {
    vault.lock();
  }
}

// set-totp: securely attach (or update) a 2FA seed on an existing `login` or
// `totp` credential — for the common case where the seed only becomes available
// AFTER the login was first stored (the user enables 2FA later). The seed is
// entered out-of-band via the secure prompt (so it never enters the agent's
// transcript) and may be a raw base32 secret OR a full otpauth:// URI.
async function cmdSetTotp(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");

  let seedInput;
  if (flags.form) {
    try {
      const out = await collectSecret({
        title: `Set TOTP seed: ${name}`,
        description:
          "Paste the base32 secret, or the full otpauth:// URI from the QR code",
        fields: [
          { name: "seed", label: "TOTP secret (base32) or otpauth:// URI" },
        ],
        label: `enter the TOTP seed for "${name}"`,
        security: "Sealed with <code>AES-256-GCM</code>. Never shown to the agent.",
      });
      seedInput = out.values.seed;
    } catch (err) {
      const ended = ownerEndedTheCard(err, { name });
      if (ended) {
        // A seed lives behind the site's own 2FA settings: a browser view can
        // show it to the owner but cannot put it in the vault, so handing one
        // over would land them back on this card. Dropping the `action` stops
        // the caller acting — but the model can open a viewport itself, and the
        // stock wording invites exactly that. So the message has to say it.
        if (ended.error === "FORM_USE_BROWSER") {
          delete ended.action;
          ended.message =
            "The owner closed the card and asked for the browser, but a browser cannot finish " +
            "this one: the seed lives behind the site's own two-factor settings and nothing in " +
            "a view can put it in the vault. Do not raise this card again, do not open a " +
            "browser for it, and do not ask for the seed in the chat.";
        }
        outputJson({ ok: false, stored: false, ...ended });
        process.exitCode = 1;
        return;
      }
      return outputError(`secure form: ${err.message}`);
    }
  } else {
    seedInput = await resolveValue(flags, "seed"); // --seed-file / --seed-env / stdin / tty
  }
  if (!seedInput) {
    return outputError("TOTP seed required (--form, --seed-file, --seed-env, or stdin)");
  }
  let parsed;
  try {
    parsed = normalizeTotpInput(seedInput);
  } catch (err) {
    return outputError(`TOTP seed: ${err.message}`);
  }

  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    if (rec.type === "login") {
      rec.otp = "totp";
      rec.totpSecret = parsed.secret;
    } else if (rec.type === "totp") {
      rec.secret = parsed.secret;
    } else {
      return outputError(`set-totp works on 'login' or 'totp' credentials, not '${rec.type}'`);
    }
    if (parsed.period) rec.period = parsed.period;
    if (parsed.digits) rec.digits = parsed.digits;
    if (parsed.algorithm) rec.algorithm = parsed.algorithm;
    vault.add(rec); // re-validates + upserts (createdAt preserved)
    await vault.save();
    stderr(`Set TOTP seed on '${name}' (${rec.type}).`);
    outputJson({
      ok: true,
      name,
      type: rec.type,
      ...(rec.type === "login" ? { otp: "totp" } : {}),
    });
  } finally {
    vault.lock();
  }
}

// Attach or replace the auto-login recipe on a `login` credential. Separate from
// `add` because a recipe is usually derived from looking at the sign-in page, which
// happens after the credential exists — and re-adding would re-prompt the owner for
// the username they already entered.
async function cmdSetRecipe(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  if (flags.recipe == null && !flags.clear) {
    return outputError("--recipe '<JSON steps>' is required (or --clear to drop it)");
  }
  let recipe = null;
  if (!flags.clear) {
    try {
      recipe = JSON.parse(String(flags.recipe));
    } catch (err) {
      return outputError(`--recipe is not valid JSON: ${err.message}`);
    }
  }

  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    if (rec.type !== "login") {
      return outputError(`set-recipe works on 'login' credentials, not '${rec.type}'`);
    }
    if (flags.clear) delete rec.recipe;
    else rec.recipe = recipe;
    vault.add(rec); // re-validates the step vocabulary + upserts
    await vault.save();
    stderr(flags.clear ? `Cleared the recipe on '${name}'.` : `Set the recipe on '${name}'.`);
    outputJson({ ok: true, name, steps: flags.clear ? 0 : recipe.length });
  } finally {
    vault.lock();
  }
}

// Replace the host allowlist on an existing credential. Needed because `domains`
// is load-bearing for a `login` — the browser refuses a secret anywhere off it, and
// auto-login refuses to navigate off it — while a sign-in that redirects between
// subdomains only reveals which hosts it needs once it has been driven. Without
// this the only fix is remove + re-add, which asks the owner for the secret again.
async function cmdSetDomains(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  const domains = parseDomains(flags);
  if (domains.length === 0) {
    return outputError("--domains <host[,host…]> is required (wildcards like *.example.com are allowed)");
  }

  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    const previous = rec.domains;
    rec.domains = domains;
    vault.add(rec); // re-validates + upserts (createdAt preserved)
    await vault.save();
    stderr(`Set domains on '${name}': ${previous.join(", ")} -> ${domains.join(", ")}.`);
    outputJson({ ok: true, name, domains });
  } finally {
    vault.lock();
  }
}

// Replace the sign-in address on an existing credential. Needed for the same
// reason `set-domains` is: `loginUrl` is load-bearing for a `login` — auto-login
// has nowhere to start without it — and whether it is right is only discovered
// by driving it. A site moves its sign-in page, or the address was a guess at a
// path that never existed; either way the secret is still correct, and without
// this the only fix is re-adding the credential, which asks the owner to type
// that secret again for a field they never got wrong.
async function cmdSetLoginUrl(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  const loginUrl = flags["login-url"] ? String(flags["login-url"]).trim() : "";
  if (!loginUrl) return outputError("--login-url <URL> is required");

  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    // `loginUrl` is a login's field; every sibling that edits one type's field
    // refuses the others the same way, rather than writing a key that means
    // nothing on a bearer and reads as policy in `vault show`.
    if (rec.type !== "login") {
      return outputError(`set-login-url works on 'login' credentials, not '${rec.type}'`);
    }
    const previous = rec.loginUrl || null;
    rec.loginUrl = loginUrl;
    vault.add(rec); // re-validates + upserts (createdAt preserved)
    await vault.save();
    stderr(`Set login URL on '${name}': ${previous ?? "(none)"} -> ${loginUrl}.`);
    outputJson({ ok: true, name, loginUrl });
  } finally {
    vault.lock();
  }
}

async function cmdSetOtp(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  const otp = flags.otp ? String(flags.otp) : "";
  if (!LOGIN_OTP_MODES.includes(otp)) {
    return outputError(`--otp must be one of: ${LOGIN_OTP_MODES.join(", ")}`);
  }

  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    // `otp` is a login's field and validation only checks it for a login, so
    // without this the flag writes a silently meaningless key onto a bearer or a
    // cookie — invisible in `vault list`, which reports `otp` only for a login,
    // and sitting in `vault show` for someone to read as policy. Every sibling
    // that edits one type's field refuses the others the same way.
    if (rec.type !== "login") {
      return outputError(
        `set-otp works on 'login' credentials, not '${rec.type}'`
      );
    }
    // The seed lives under a different key for each of the two types that hold
    // one, and set-totp writes both: `totpSecret` on a login, `secret` on a
    // `totp` credential. Checking only the first told a fully seeded credential
    // to go and run the command it had already run.
    if (otp === "totp" && !rec.totpSecret && !rec.secret) {
      return outputError(
        `'${name}' has no TOTP seed — attach one with set-totp first`
      );
    }
    const previous = loginOtpMode(rec);
    rec.otp = otp;
    vault.add(rec); // re-validates + upserts (createdAt preserved)
    await vault.save();
    stderr(`Set otp on '${name}': ${previous} -> ${otp}.`);
    outputJson({ ok: true, name, otp });
  } finally {
    vault.lock();
  }
}

async function cmdShow(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    // Two sealing reasons: in-vault-generated secrets never export, and an
    // access-restricted ("ro") credential's plaintext must not reach the agent
    // — otherwise the proxy/browser read-only enforcement would be theater.
    const sealedWhy =
      rec.exportable === false
        ? "generated in-vault, not exportable"
        : isAccessRestricted(rec)
          ? `access-restricted (${describeAccess(rec)}) — enforced via the proxy/browser only`
          : null;
    if (sealedWhy) {
      const redacted = { ...rec };
      for (const f of SECRET_FIELDS) {
        if (redacted[f] != null) redacted[f] = `[sealed — ${sealedWhy}]`;
      }
      stderr(
        `Credential '${name}' is sealed (${sealedWhy}). ` +
          "Use the proxy or the sealed browser to exercise it."
      );
      outputJson({ ok: true, credential: redacted, sealed: true });
      return;
    }
    outputJson({ ok: true, credential: rec });
  } finally {
    vault.lock();
  }
}

// ─── generate: create a keypair INSIDE the vault; only the public key leaves ───

const GENERATE_TYPES = ["solana-keypair", "evm-keypair"];

async function cmdGenerate(flags) {
  const name = flags.name;
  const type = flags.type || "solana-keypair";
  if (!name) return outputError("--name <NAME> is required");
  if (!GENERATE_TYPES.includes(type)) {
    return outputError(`generate supports types: ${GENERATE_TYPES.join(", ")} (got '${type}')`);
  }
  const domains = parseDomains(flags);
  if (domains.length === 0) {
    return outputError(
      "--domains <host[,host…]> is required (RPC hosts the proxy may sign for, default-deny)"
    );
  }

  const access = flags.access != null ? String(flags.access) : null;
  if (access && !ACCESS_LEVELS.includes(access)) {
    return outputError(`--access must be one of ${ACCESS_LEVELS.join(", ")}`);
  }

  const vault = await openWithFlags(flags);
  try {
    if (vault.has(name) && !flags.overwrite) {
      return outputError(`Credential '${name}' already exists (pass --overwrite to replace it)`);
    }
    const record = {
      name,
      type,
      domains,
      description: flags.description || null,
      exportable: false,
    };
    if (access) record.access = access;
    // Overwriting must not silently widen access (same rule as `add`).
    const existing = vault.get(name);
    if (existing) {
      if (!access && existing.access != null) record.access = existing.access;
      if (existing.accessRules != null) record.accessRules = existing.accessRules;
      if (isAccessRelaxation(existing, record)) {
        return outputError(
          `Credential '${name}' has access level '${effectiveAccess(
            existing
          )}' — ` +
            "overwriting cannot widen it. Use `set-access` (owner-confirmed)."
        );
      }
    }
    let address;
    if (type === "solana-keypair") {
      const { publicKey, secretSeedHex } = generateSolanaKeypair();
      record.publicKey = publicKey;
      record.secretSeed = secretSeedHex;
      address = publicKey;
      // Optional signing constraint: restrict which programs the key will sign for.
      const programAllowlist = parseCsvFlag(flags["program-allowlist"]);
      if (programAllowlist) record.programAllowlist = programAllowlist;
    } else {
      const { address: evmAddress, privateKeyHex } = generateEvmKeypair();
      record.address = evmAddress;
      record.privateKey = privateKeyHex;
      address = evmAddress;
      // Optional signing constraints: bound chains and recipients.
      const chainIds = parseCsvFlag(flags["chain-id-allowlist"]);
      if (chainIds) record.chainIdAllowlist = chainIds.map((n) => Number(n));
      const toAllowlist = parseCsvFlag(flags["to-allowlist"]);
      if (toAllowlist) record.toAllowlist = toAllowlist;
    }
    const stored = vault.add(record);
    await vault.save();
    stderr(`Generated ${type === "solana-keypair" ? "Solana" : "EVM"} keypair '${name}'.`);
    stderr(`  Address: ${address}`);
    stderr("  The private key is sealed in the vault and will never be shown.");
    outputJson({
      ok: true,
      name: stored.name,
      type: stored.type,
      ...(record.publicKey ? { publicKey: record.publicKey } : {}),
      ...(record.address ? { address: record.address } : {}),
      domains: stored.domains,
      exportable: false,
      createdAt: stored.createdAt,
    });
  } finally {
    vault.lock();
  }
}

// ─── set-access: change a credential's access level / rules ────────────────────
//
// TIGHTENING (rw→ro, adding deny rules, dropping allow rules) applies
// immediately — an agent may always give capabilities up. RELAXING (ro→rw,
// adding allow rules, dropping deny rules) asks the OWNER to confirm
// out-of-band via the secure prompt (they type the credential name), so an
// agent cannot self-upgrade what its credentials permit.

function describeAccess(rec) {
  const rules = Array.isArray(rec.accessRules) ? ` + ${rec.accessRules.length} rule(s)` : "";
  return `${effectiveAccess(rec)}${rules}`;
}

async function cmdSetAccess(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  const wantLevel = flags.access != null ? String(flags.access) : null;
  if (wantLevel && !ACCESS_LEVELS.includes(wantLevel)) {
    return outputError(`--access must be one of ${ACCESS_LEVELS.join(", ")}`);
  }
  let wantRules; // undefined = leave untouched; null = clear; array = replace
  if (flags["clear-rules"] === true) {
    wantRules = null;
  } else if (flags.rules != null) {
    try {
      wantRules = JSON.parse(String(flags.rules));
    } catch (err) {
      return outputError(`--rules must be a JSON array: ${err.message}`);
    }
  }
  if (wantLevel == null && wantRules === undefined) {
    return outputError(
      "Nothing to change — pass --access ro|rw and/or --rules '<JSON array>' / --clear-rules"
    );
  }

  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);

    const after = { ...rec };
    if (wantLevel != null) after.access = wantLevel;
    if (wantRules !== undefined) {
      if (wantRules == null) delete after.accessRules;
      else after.accessRules = wantRules;
    }
    try {
      validateRecord(after); // fail fast, before any owner ceremony
    } catch (err) {
      return outputError(err.message);
    }

    if (isAccessRelaxation(rec, after)) {
      stderr(
        `Widening access on '${name}' (${describeAccess(
          rec
        )} → ${describeAccess(after)}) ` +
          "needs the owner's out-of-band confirmation…"
      );
      let values;
      try {
        ({ values } = await collectSecret({
          title: `Allow MORE access: ${name}`,
          description:
            `The agent asks to widen what '${name}' may do: ` +
            `${describeAccess(rec)} → ${describeAccess(after)}. ` +
            "Approve only if YOU intend this.",
          fields: [
            {
              name: "confirm",
              label: `Type the credential name (${name}) to approve`,
              secret: false,
            },
          ],
          label: `approve wider access for "${name}"`,
          security: "Typed by you, out of the agent's sight. Mismatch = no change.",
        }));
      } catch (err) {
        // This card is an APPROVAL, not a secret. Nothing in a browser can
        // approve it, so any way the owner ends it leaves the access alone —
        // and asking again in the same turn is the loop, not the recovery.
        if (ownerEndedTheCard(err)) {
          outputJson({
            ok: false,
            error: "OWNER_DID_NOT_APPROVE",
            reason: "owner_ended_the_card",
            retryable: false,
            access: describeAccess(rec),
            message:
              "Access unchanged — the owner did not approve the widen. Do not ask again in this turn.",
          });
          process.exitCode = 1;
          return;
        }
        return outputError(`owner confirmation: ${err.message}`);
      }
      if (String(values.confirm || "").trim() !== name) {
        return outputError("owner confirmation did not match the credential name — access unchanged");
      }
    }

    vault.add(after);
    await vault.save();
    stderr(`Access on '${name}' is now: ${describeAccess(after)}.`);
    outputJson({
      ok: true,
      name,
      access: effectiveAccess(after),
      accessRules: after.accessRules ?? null,
    });
  } finally {
    vault.lock();
  }
}

// The card's values, for the one process that types them into a page.
//
// `show` seals a card, because `access: "ro"` means its plaintext must not be
// what the agent reads when it asks what it has stored — and a PAN printed into
// a tool result is a PAN in the turn's transcript. But something has to hand the
// four values to whatever fills the checkout form, and since the browser session
// server was removed (#151) that is the caller's payment tool.
//
// So the read is a command of its own rather than a flag on `show`: it names
// what it does in the audit log, it reads nothing but a card, and a reader of
// this file can find every caller by its name. It is not a privilege boundary —
// the vault opens with the agent key and anything that can run this can import
// the library instead. What guards a card is the owner's per-payment approval,
// which the caller enforces on every payment, not here.
async function cmdReadCard(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    if (rec.type !== "card") {
      return outputError(
        `'${name}' is a ${rec.type}, and read-card reads nothing but a card`,
      );
    }
    const card = {};
    for (const field of CARD_FIELDS) card[field] = rec[field] ?? "";
    card.cardLast4 = cardLast4(rec);
    // The address comes back the same way whichever place it was stored in —
    // its own credential, or the card itself. This is the only reader that knows
    // there are two places, so nothing downstream has to choose between them.
    card.billing = billingOf(rec, vault);
    outputJson({ ok: true, card });
  } finally {
    vault.lock();
  }
}

// Which of a card's fields have a value — the names, and nothing else.
//
// The caller that types a card has to know, before it spends the owner's
// approval, whether the boxes it was handed are ones this card can answer.
// Until now the only reader that knew was `read-card`, which answers with the
// plaintext, so the question could not be asked without opening the card. This
// one answers with the names: it is safe to call at any time, it appears in the
// audit log as what it is, and a ref the card cannot fill can be refused before
// anything is spent.
async function cmdCardFields(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    if (rec.type !== "card") {
      return outputError(
        `'${name}' is a ${rec.type}, and card-fields reads nothing but a card`,
      );
    }
    outputJson({ ok: true, fields: answeredFields(rec, vault) });
  } finally {
    vault.lock();
  }
}

// Which of a card's fields have a value — the names, and nothing else. One
// list for `card-fields` and `set-address`, so what the two report never drifts.
function answeredFields(rec, vault) {
  const billing = billingOf(rec, vault) ?? {};
  const answered = (source) => (field) => (source[field] ?? "").length > 0;
  return [...CARD_FIELDS.filter(answered(rec)), ...ADDRESS_FIELDS.filter(answered(billing))];
}

// The address a card is billed to, without the card.
//
// A checkout asks for an address on its delivery step, on its billing block and
// sometimes once more on the page after the payment, and only the first of those
// has anything to do with spending. So the address is readable on its own, and
// this reader never touches the number, the expiry or the security code — the
// caller that fills an address form has no business holding them.
async function cmdReadAddress(flags) {
  const name = flags.card;
  if (!name) return outputError("--card <NAME> is required");
  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    if (rec.type !== "card") {
      return outputError(
        `'${name}' is a ${rec.type}, and read-address reads the address a card is billed to`,
      );
    }
    outputJson({ ok: true, billing: billingOf(rec, vault) });
  } finally {
    vault.lock();
  }
}

// The billing address of a card: resolved from the credential it names, else
// read off the card, else null for a card stored before there was one.
function billingOf(rec, vault) {
  const source =
    typeof rec.billingAddress === "string" && rec.billingAddress.length > 0
      ? vault.get(rec.billingAddress)
      : rec;
  if (!source) return null;
  const billing = {};
  let present = false;
  for (const field of ADDRESS_FIELDS) {
    const value = source[field] ?? "";
    if (value.length > 0 && !ADDRESS_OPTIONAL_FIELDS.includes(field)) present = true;
    billing[field] = value;
  }
  return present ? billing : null;
}

// The address a card is billed to, asked for when a checkout needs it.
//
// Not at `add`: the card is what the owner has in hand, and whether the shop
// will ask for an address — and for which boxes — is known only once its form
// is in front of the agent. Asked then, the screen is raised once per address
// rather than once per card: an address the vault already holds is linked to
// the card without a word, and only a vault with none (or `--replace`, for an
// address that lacks a box this shop insists on) puts the form in front of the
// owner. Names only come back; the values stay sealed.
async function cmdSetAddress(flags) {
  const name = flags.card;
  if (!name) return outputError("--card <NAME> is required");
  if (!flags.form) {
    return outputError("set-address takes --form: the owner types the address, never the agent");
  }
  const vault = await openWithFlags(flags);
  try {
    const rec = vault.get(name);
    if (!rec) return outputError(`No credential named '${name}'`);
    if (rec.type !== "card") {
      return outputError(
        `'${name}' is a ${rec.type}, and set-address sets the address a card is billed to`,
      );
    }
    const answer = (source) =>
      outputJson({
        ok: true,
        card: name,
        address: typeof rec.billingAddress === "string" ? rec.billingAddress : null,
        source,
        fields: answeredFields(rec, vault),
      });
    if (!flags.replace) {
      if (billingOf(rec, vault)) return answer("already");
      const stored = vault.list().filter((entry) => entry.type === "address");
      if (stored.length === 1) {
        rec.billingAddress = stored[0].name;
        vault.add(rec);
        await vault.save();
        stderr(`Linked '${name}' to the stored address '${stored[0].name}'; nothing was asked.`);
        return answer("existing");
      }
    }
    let values;
    try {
      values = await collectBillingAddress(name);
    } catch (err) {
      const ended = ownerEndedTheCard(err, { card: name });
      if (ended) {
        // The stock wording is about a sign-in. An address the owner would
        // rather type into the page themselves is exactly what a browser view
        // is for, so the `action` stays and only the words change.
        if (ended.error === "FORM_USE_BROWSER") {
          ended.message =
            "The owner closed the card and asked to type the address into the page " +
            "themselves. That is not a refusal. Do not raise this card again and do not " +
            "ask for the address here.";
        }
        outputJson({ ok: false, stored: false, ...ended });
        process.exitCode = 1;
        return;
      }
      return outputError(`secure form: ${err.message}`);
    }
    attachBillingAddress(rec, values, vault);
    if (!billingOf(rec, vault)) {
      return outputError("the address form came back empty; nothing was stored");
    }
    vault.add(rec); // re-validates + upserts (createdAt preserved)
    await vault.save();
    stderr(`Set the billing address on '${name}'.`);
    return answer("typed");
  } finally {
    vault.lock();
  }
}

async function cmdList(flags) {
  const vault = await openWithFlags(flags);
  try {
    outputJson({
      ok: true,
      mode: vault.mode,
      credentials: vault.list(),
      slots: vault.slots,
    });
  } finally {
    vault.lock();
  }
}

async function cmdRemove(flags) {
  const name = flags.name;
  if (!name) return outputError("--name <NAME> is required");
  const vault = await openWithFlags(flags);
  try {
    const removed = vault.remove(name);
    if (!removed) return outputError(`No credential named '${name}'`);
    await vault.save();
    stderr(`Removed credential '${name}'.`);
    outputJson({ ok: true, name });
  } finally {
    vault.lock();
  }
}

async function cmdRekey(flags) {
  const sub = flags._sub;
  const vault = await openWithFlags(flags);
  try {
    if (sub === "add-passphrase") {
      let passphrase = await resolvePassphrase(
        {
          ...flags,
          "passphrase-file": flags["new-passphrase-file"],
          "passphrase-env": flags["new-passphrase-env"],
          passphrase: flags["new-passphrase"],
        },
        { allowPrompt: false }
      );
      if (!passphrase) {
        if (!hasTty()) return outputError("New passphrase required");
        passphrase = promptNewPassphrase({
          prompt: "New passphrase: ",
          confirm: "Confirm: ",
        });
      }
      const slot = vault.addPassphraseSlot(passphrase);
      await vault.save();
      stderr(`Added passphrase slot ${slot.id}.`);
      outputJson({ ok: true, slot: { id: slot.id, type: slot.type } });
    } else if (sub === "add-agent-key") {
      const stateDir = resolveStateDir(flags);
      const privateKeyPem = await loadAgentPrivateKey(stateDir);
      if (!privateKeyPem) return outputError("No agent key found. Run agent-id-core bootstrap first.");
      const agentId =
        (await readJsonFile(statePaths(stateDir).mainKey, null))?.agentId || null;
      const slot = vault.addAgentKeySlot(privateKeyPem, agentId);
      await vault.save();
      stderr(`Added agent-key slot ${slot.id} for agent ${agentId || "(unknown)"}.`);
      outputJson({ ok: true, slot: { id: slot.id, type: slot.type, agentId } });
    } else if (sub === "add-passkey") {
      let passkey;
      try {
        passkey = await registerPasskey({
          deviceLabel: flags["device-label"] || null,
        });
      } catch (err) {
        return outputError(`passkey registration failed: ${err.message}`);
      }
      const slot = vault.addPasskeySlot(passkey.prfSecret, {
        credentialId: passkey.credentialId,
        rpId: passkey.rpId,
        prfSalt: passkey.prfSalt,
        deviceLabel: passkey.deviceLabel,
      });
      await vault.save();
      stderr(
        `Added passkey slot ${slot.id}${
          passkey.deviceLabel ? ` (${passkey.deviceLabel})` : ""
        }.`
      );
      outputJson({
        ok: true,
        slot: {
          id: slot.id,
          type: slot.type,
          credentialId: passkey.credentialId,
        },
      });
    } else if (sub === "add-mobile") {
      const devicePubKey = flags["device-pubkey"];
      if (!devicePubKey) {
        return outputError(
          "--device-pubkey <hex> required (P-256 enclave public key, X9.63 uncompressed: 04||X||Y)"
        );
      }
      if (!/^04[0-9a-fA-F]{128}$/.test(devicePubKey)) {
        return outputError(
          "--device-pubkey must be 130 hex chars starting with 04 (uncompressed P-256 point)"
        );
      }
      const deviceId = flags["device-id"] || null;
      const slot = vault.addMobileSlot(devicePubKey, deviceId);
      await vault.save();
      stderr(
        `Added mobile slot ${slot.id}${
          deviceId ? ` for device ${deviceId}` : ""
        }.`
      );
      outputJson({
        ok: true,
        slot: { id: slot.id, type: slot.type, deviceId },
      });
    } else if (sub === "add-owner-approval") {
      const stateDir = resolveStateDir(flags);
      const engine = new SignatureEngine({ baseDir: stateDir });
      const main = await engine.ensureMainKey();
      const session = await engine.ensureValidSession();
      if (!session?.accessToken) {
        return outputError(
          "No valid owner session. Run `agent-id-core auth` to bind an owner first."
        );
      }
      const ssoBaseUrl = flags["sso-url"] || session.ssoBaseUrl || session.issuer;
      if (!ssoBaseUrl) {
        return outputError("Could not determine SSO base URL — pass --sso-url <URL>.");
      }
      const providerAddress = flags["provider-address"] || session.providerAddress || null;

      // The KEK lives only long enough to wrap the master key and hand a copy to
      // the SSO; it is zeroed below so neither the vault file nor this process
      // retains it. Recovery requires an owner-approved release from the SSO.
      const kek = ownerApprovalKekBytes();
      try {
        const { keyRef } = await enrollOwnerApproval({
          ssoBaseUrl,
          accessToken: session.accessToken,
          agentPrivateKeyPem: main.privateKeyPem,
          secret: kek,
        });
        const slot = vault.addOwnerApprovalSlot(kek, {
          keyRef,
          ssoBaseUrl,
          providerAddress,
        });
        await vault.save();
        stderr(`Added owner-approval slot ${slot.id} (key_ref ${keyRef}).`);
        outputJson({
          ok: true,
          slot: { id: slot.id, type: slot.type, keyRef },
        });
      } finally {
        kek.fill(0);
      }
    } else if (sub === "remove-slot") {
      const id = Number(flags.id);
      if (!Number.isFinite(id)) return outputError("--id <N> required");
      const ok = vault.removeSlot(id);
      if (!ok) return outputError(`No slot with id ${id}`);
      await vault.save();
      stderr(`Removed slot ${id}.`);
      outputJson({ ok: true, removed: id });
    } else {
      return outputError(
        `rekey subcommand required: add-passphrase | add-passkey | add-agent-key | add-mobile | add-owner-approval | remove-slot`
      );
    }
  } finally {
    vault.lock();
  }
}

async function cmdExport(flags) {
  const out = flags.out;
  if (!out) return outputError("--out <PATH> is required");
  const stateDir = resolveStateDir(flags);
  if (!(await vaultFileExists(stateDir))) {
    return outputError("No vault to export");
  }
  const written = await exportVault({ stateDir, outPath: out });
  stderr(`Exported encrypted vault to ${written}`);
  outputJson({ ok: true, path: written });
}

async function cmdImport(flags) {
  const inPath = flags.in;
  if (!inPath) return outputError("--in <PATH> is required");
  const stateDir = resolveStateDir(flags);
  const written = await importVault({
    stateDir,
    inPath,
    overwrite: Boolean(flags.overwrite),
  });
  stderr(`Imported encrypted vault to ${written}`);
  outputJson({ ok: true, path: written });
}

async function cmdMigrate(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  if (await vaultFileExists(stateDir)) {
    if (!flags["force"]) {
      return outputError(
        `Portable vault already exists at ${paths.vaultFile}. ` +
          "Pass --force to re-run migration (will not overwrite existing slots)."
      );
    }
  }

  const privateKeyPem = await loadAgentPrivateKey(stateDir);
  if (!privateKeyPem) return outputError("No agent key — cannot decrypt legacy vault.");

  const legacy = await readLegacyVault(paths.vaultDir, privateKeyPem);
  if (legacy.length === 0) {
    stderr("No legacy credentials found — nothing to migrate.");
    outputJson({ ok: true, migrated: 0 });
    return;
  }

  let passphrase = await resolvePassphrase(flags, { allowPrompt: false });
  if (!passphrase) {
    if (!hasTty()) return outputError("Migration requires a passphrase for slot 0");
    passphrase = promptNewPassphrase({
      prompt: "New vault passphrase (for portability): ",
      confirm: "Confirm: ",
    });
  }
  const agentId =
    (await readJsonFile(paths.mainKey, null))?.agentId || null;

  await initVault({ stateDir, passphrase, privateKeyPem, agentId });
  const vault = await openVault({ stateDir, privateKeyPem });
  try {
    for (const old of legacy) {
      // Legacy v4 records had no host allowlist; require migrate caller to
      // supply --default-domains, otherwise we tag them as "unrestricted"
      // so the proxy refuses to use them until the user attaches a domain.
      const domains =
        parseDomains({ domains: flags["default-domains"] }) || [];
      vault.add({
        name: old.service,
        type: "bearer",
        domains: domains.length > 0 ? domains : ["UNCONFIGURED.invalid"],
        description: `migrated from v4 (${old.type})`,
        value: old.credential,
      });
    }
    await vault.save();
    stderr(`Migrated ${legacy.length} legacy credentials.`);
    if (!flags["default-domains"]) {
      stderr(
        "WARNING: legacy records have no host allowlist. " +
          "Update each with `agent-id-vault add --name <N> --type bearer --domains <H> --value-env <V>` " +
          "before the proxy will inject them."
      );
    }
    // Rename old dir so a re-run notices it's done.
    try {
      await fs.rename(paths.vaultDir, `${paths.vaultDir}.bak`);
    } catch {
      // not fatal
    }
    outputJson({ ok: true, migrated: legacy.length, vault: paths.vaultFile });
  } finally {
    vault.lock();
  }
}

// ─── exec: run a command with vault credentials injected into its env / a file ──
//
// Two materialization modes, both keeping the secret out of the agent's
// stdin/stdout/argv/transcript (only the variable names + sources are logged):
//
//   --env  VAR=cred.field   inject the value into the child's environment.
//   --file VAR=cred.field   write the value to a temp 0600 file and set VAR to its
//                           PATH — for tools that want a key FILE (ssh -i, an RSA
//                           PEM, a service-account JSON). The agent gets the path,
//                           never the contents; the file is shredded + removed when
//                           the command exits.
//
//   agent-id-vault exec [--env … | --file …] [unlock flags] -- <cmd> [args…]
//
// Examples:
//   exec --env MODAL_TOKEN_ID=modal-token.username --env MODAL_TOKEN_SECRET=modal-token.password -- modal run job.py
//   exec --file GIT_SSH_KEY=deploy-key.value -- sh -c 'GIT_SSH_COMMAND="ssh -i $GIT_SSH_KEY" git fetch'
//
// `field` is the record field to read (bearer/header/query/cookie → value, basic →
// username/password, totp → secret, oauth2 → refreshToken, secret → value, …).
// Sealed in-vault-generated keys (solana/evm) refuse to leave the vault.
async function cmdExec() {
  const rest = process.argv.slice(3); // drop ["exec"]; argv[2] === "exec"
  const sepIdx = rest.indexOf("--");
  if (sepIdx === -1) {
    return outputError(
      "exec needs a `--` separator before the command. " +
        "Usage: exec --env VAR=cred.field | --file VAR=cred.field [more] -- <command> [args…]"
    );
  }
  const pre = rest.slice(0, sepIdx);
  const cmdArgv = rest.slice(sepIdx + 1);
  if (cmdArgv.length === 0) return outputError("No command given after `--`.");

  // --env / --file are repeatable (parseFlags would keep only the last); collect
  // them by hand and leave the rest as unlock/common flags.
  const mappings = [];
  const flagArgs = [];
  for (let i = 0; i < pre.length; i++) {
    if (pre[i] === "--env" || pre[i] === "--file") {
      const v = pre[i + 1];
      if (!v || v.startsWith("--")) {
        return outputError(`${pre[i]} needs a VAR=cred.field argument`);
      }
      mappings.push({ kind: pre[i] === "--file" ? "file" : "env", ref: v });
      i++;
    } else {
      flagArgs.push(pre[i]);
    }
  }
  if (mappings.length === 0) {
    return outputError("exec needs at least one --env or --file VAR=cred.field mapping");
  }

  const specs = [];
  for (const m of mappings) {
    const eq = m.ref.indexOf("=");
    if (eq <= 0) return outputError(`Bad --${m.kind} "${m.ref}" — expected VAR=cred.field`);
    const varName = m.ref.slice(0, eq);
    const ref = m.ref.slice(eq + 1);
    const dot = ref.lastIndexOf(".");
    if (dot <= 0 || dot === ref.length - 1) {
      return outputError(
        `Bad --${m.kind} "${m.ref}" — expected VAR=cred.field (e.g. GIT_SSH_KEY=deploy-key.value)`
      );
    }
    specs.push({
      kind: m.kind,
      varName,
      credName: ref.slice(0, dot),
      field: ref.slice(dot + 1),
    });
  }

  const flags = parseFlags(flagArgs);
  const vault = await openWithFlags(flags);
  const childEnv = { ...process.env };
  const injected = [];
  let tmpDir = null;
  const files = [];
  try {
    for (const s of specs) {
      const rec = vault.get(s.credName);
      if (!rec) return outputError(`No credential named '${s.credName}'`);
      if (rec.exportable === false && SECRET_FIELDS.includes(s.field)) {
        return outputError(
          `Credential '${s.credName}' is sealed (generated in-vault); field ` +
            `'${s.field}' cannot leave the vault. Use the proxy to exercise it.`
        );
      }
      // An access-restricted credential (ro, OR rw with deny rules) handed raw
      // to a child process would bypass the proxy/browser gate — refuse, same
      // as sealed. Rule-only restrictions count: the rules are enforced at the
      // proxy, so leaking the plaintext would make them theater.
      if (isAccessRestricted(rec) && SECRET_FIELDS.includes(s.field)) {
        return outputError(
          `Credential '${s.credName}' is access-restricted (${describeAccess(rec)}); field ` +
            `'${s.field}' cannot be exported to a child process (that would bypass enforcement). ` +
            "Use the proxy/browser, or ask the owner to run `set-access --access rw` (and clear rules)."
        );
      }
      const value = rec[s.field];
      if (typeof value !== "string" || value.length === 0) {
        return outputError(`Credential '${s.credName}' has no usable string field '${s.field}'`);
      }
      if (s.kind === "file") {
        // mkdtemp makes a 0700 dir; the file is 0600. Same-uid isn't a boundary
        // (the agent could read the vault anyway) — this keeps the value out of
        // the transcript/argv and bounds its on-disk lifetime to the command.
        if (!tmpDir) tmpDir = mkdtempSync(path.join(os.tmpdir(), "agent-id-exec-"));
        const safe = s.varName.replace(/[^A-Za-z0-9._-]/g, "_") || "secret";
        const fp = path.join(tmpDir, safe);
        writeFileSync(fp, value, { mode: 0o600 });
        chmodSync(fp, 0o600); // enforce 0600 regardless of umask
        childEnv[s.varName] = fp;
        files.push(fp);
        injected.push(`${s.varName}=${s.credName}.${s.field} (file)`);
      } else {
        childEnv[s.varName] = value;
        injected.push(`${s.varName}=${s.credName}.${s.field}`);
      }
    }
  } finally {
    vault.lock(); // values already copied; zero the master key
  }

  // Best-effort shred of any materialized files: overwrite with zeros, unlink,
  // remove the dir. Sync so it completes inside the exit handlers.
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    for (const fp of files) {
      try { writeFileSync(fp, Buffer.alloc(statSync(fp).size, 0)); } catch {}
      try { unlinkSync(fp); } catch {}
    }
    if (tmpDir) {
      try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
    }
  };

  // Names + sources only — never the values.
  stderr(`Injecting ${injected.join(", ")} → ${cmdArgv.join(" ")}`);

  const child = spawn(cmdArgv[0], cmdArgv.slice(1), {
    stdio: "inherit",
    env: childEnv,
  });
  const forward = (sig) => {
    try {
      child.kill(sig);
    } catch {
      /* child already exited */
    }
  };
  process.on("SIGINT", forward);
  process.on("SIGTERM", forward);
  process.on("exit", cleanup); // last-resort sync cleanup of temp files
  child.on("error", (err) => {
    process.off("SIGINT", forward);
    process.off("SIGTERM", forward);
    cleanup();
    outputError(`Failed to run '${cmdArgv[0]}': ${err.message}`);
  });
  child.on("exit", (code, signal) => {
    process.off("SIGINT", forward);
    process.off("SIGTERM", forward);
    cleanup();
    process.exitCode = signal ? 1 : code ?? 0;
  });
}

// ─── Dispatch ───────────────────────────────────────────────────────────────────

function printHelp() {
  stderr(
    [
      "agent-id-vault — portable encrypted credential vault",
      "",
      "Subcommands:",
      "  init [--unlock passkey|passphrase|agent-key] [--dev] [--no-agent-key] [--agent-key]",
      "       --unlock passkey     Touch ID / Face ID / security key (recommended; agent can't self-unlock)",
      "       --unlock passphrase  typed into the secure form (dev mode)",
      "       default (no --unlock) = USER mode, agent-key auto-unlock.",
      "       passkey/passphrase default to NO agent-key slot; add --agent-key to keep one.",
      "  add --name N --type T --domains H[,H…] [--access ro|rw] [type-specific value flags]",
      "      --form   enter the secret out-of-band via the secure prompt (browser",
      "               form → /dev/tty → hosted harness); else --<field>-file/-env/stdin",
      "      --access ro   read-only: the proxy/browser allow only read-shaped",
      "               requests (GET/HEAD/OPTIONS + POST-tunneled reads: GraphQL",
      "               query, JMAP get/query, JSON-RPC non-submitting); show/exec",
      "               refuse the plaintext. Default rw (unrestricted).",
      "      oauth2: --token-endpoint URL --client-id ID [--client-secret-env V]",
      "              --refresh-token-file F [--scope S]   (auto-refreshes access tokens)",
      "      login:  --login-url URL [--otp none|totp|interactive] [--profile NAME]",
      "              [--passwordless] [--recipe '<JSON steps>']",
      "              --form captures username/password (+ TOTP seed when --otp totp);",
      "              --passwordless drops the password field: the site has none and",
      "              mails/SMSes a code at sign-in (needs --otp interactive|totp)",
      "              driven by `agent-id-browser auto-login`, not the HTTP proxy",
      "  set-domains --name N --domains H[,H…]   replace the host allowlist",
      "              a sign-in that redirects between subdomains needs them all",
      "  set-login-url --name N --login-url URL   move a login's sign-in address",
      "              for a page that moved or an address that never loaded; asks the",
      "              owner for nothing",
      "  set-otp --name N --otp none|totp|interactive   fix how a code is answered",
      "              for a login whose stored mode turned out to be wrong; asks the",
      "              owner for nothing. A mailed/texted code is `interactive`.",
      "  set-recipe --name N (--recipe '<JSON steps>' | --clear)",
      "              attach/replace the auto-login recipe on a login cred; steps are",
      "              navigate|fill|type|click|press|wait with {username}/{password}/{otp}",
      "  set-totp --name N [--form]   attach/update a 2FA seed on a login|totp cred",
      "              accepts a base32 secret or an otpauth:// URI (use when 2FA is",
      "              enabled after the login was stored); else --seed-file/-env/stdin",
      "  set-access --name N [--access ro|rw] [--rules '<JSON>' | --clear-rules]",
      "              change a credential's access level. Tightening applies at",
      "              once; WIDENING requires the owner to confirm via the secure",
      "              prompt (the agent cannot self-upgrade). Rules: JSON array of",
      '              {"effect":"allow|deny","methods":[..],"hosts":[..],"path":"/glob*"}',
      "  generate --name N --type solana-keypair|evm-keypair --domains H[,H…] [--overwrite]",
      "      creates the keypair inside the vault; prints ONLY the public address",
      "      evm:    [--chain-id-allowlist 1,137] [--to-allowlist 0x..,0x..]",
      "      solana: [--program-allowlist <base58>,..]   (default-allow when omitted)",
      "  show --name N    (sealed/generated secrets are redacted)",
      "  read-card --name N",
      "      the card's four values, for the process that types them into a page",
      "  card-fields --name N",
      "      which of the card's fields have a value — the names, not the values",
      "  read-address --card N",
      "      the address that card is billed to, without the card",
      "  set-address --card N --form [--replace]",
      "      ask the owner for the address that card is billed to, once a checkout",
      "      needs it; an address the vault already holds is linked without asking",
      "  list",
      "  remove --name N",
      "  exec [--env VAR=cred.field | --file VAR=cred.field] … -- <cmd> [args…]",
      "      run <cmd> with credentials injected; the agent never sees the value.",
      "      --env  → into the child's environment (MODAL_TOKEN_ID=modal-token.username)",
      "      --file → written to a temp 0600 file, VAR=its path, shredded on exit",
      "               (for key files: GIT_SSH_KEY=deploy-key.value)",
      "  rekey add-passkey [--device-label NAME]   add a passkey (Touch ID) unlock",
      "        | add-passphrase | add-agent-key | remove-slot --id N",
      "        | add-mobile --device-pubkey HEX [--device-id NAME]",
      "        | add-owner-approval [--sso-url URL] [--provider-address ADDR]",
      "  export --out PATH",
      "  import --in PATH [--overwrite]",
      "  migrate [--default-domains H[,H…]] [--force]",
      "",
      "Types: " + CREDENTIAL_TYPES.join(", "),
      "Unlock: --passphrase-file F | --passphrase-env V | auto via agent-key | /dev/tty prompt",
      "Common: --state-dir <path>  (defaults to AGENT_ID_STATE_DIR or ~/.agent-id)",
    ].join("\n")
  );
}

// `rekey` takes a sub-verb as its first positional arg; wrap dispatch.
function makeRekeyHandler() {
  return async (flags) => {
    const argv = process.argv.slice(2);
    const idx = argv.indexOf("rekey");
    const sub = idx >= 0 ? argv[idx + 1] : null;
    await cmdRekey({ ...flags, _sub: sub });
  };
}

const commands = {
  init: cmdInit,
  add: cmdAdd,
  "set-totp": cmdSetTotp,
  "set-recipe": cmdSetRecipe,
  "set-domains": cmdSetDomains,
  "set-login-url": cmdSetLoginUrl,
  "set-otp": cmdSetOtp,
  "set-access": cmdSetAccess,
  generate: cmdGenerate,
  show: cmdShow,
  "read-card": cmdReadCard,
  "card-fields": cmdCardFields,
  "read-address": cmdReadAddress,
  "set-address": cmdSetAddress,
  list: cmdList,
  remove: cmdRemove,
  exec: cmdExec,
  rekey: makeRekeyHandler(),
  export: cmdExport,
  import: cmdImport,
  migrate: cmdMigrate,
};

// Wrap runCli to catch trusted-input + vault-not-found errors with friendlier
// messages.
const originalCommands = { ...commands };
for (const k of Object.keys(commands)) {
  commands[k] = async (flags) => {
    try {
      await originalCommands[k](flags);
    } catch (err) {
      if (err instanceof TrustedInputUnavailable) {
        outputError(err.message);
      } else if (err.code === "VAULT_NOT_FOUND") {
        outputError(err.message);
      } else if (err.code === "VAULT_UNLOCK_FAILED") {
        outputError(err.message);
      } else if (err.code === "VAULT_EXISTS") {
        outputError(err.message);
      } else {
        throw err;
      }
    }
  };
}

runCli({ commands, printHelp });
