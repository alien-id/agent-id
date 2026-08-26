// The MCP tool surface, each mapped to an agent-id-* CLI subcommand. Mirrors the
// surface Lethe exposes (src/tools/agent_id.rs). Increment 1: identity + vault.
// Browser tools (browser_open/act/close/…) are added in increment 2 once the
// server-side sealed-browser daemon relay is wired (see docs/COWORK-MCP.md).
//
// Each tool: { name, description, inputSchema (JSON Schema), kind, argv(args) }.
// `kind` selects the CLI ("core" | "vault" | "browser"); `argv` builds its args.
// Secret VALUES are never MCP inputs — `vault_add`/`set_totp` collect them out of
// band via the CLI's `--form` (the hosted secure-input card channel), exactly as
// the CLI plugins do; the model only ever names a credential.

const str = (description) => ({ type: "string", description });
const strArr = (description) => ({ type: "array", items: { type: "string" }, description });

export const TOOLS = [
  {
    name: "agent_id_status",
    description:
      "Report this agent's Alien identity: whether an identity exists, its assurance level (L0/L1/L2), and owner-binding state. Read-only.",
    kind: "core",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    argv: () => ["status"],
  },
  {
    name: "agent_id_sign",
    description:
      "Sign an arbitrary operation with the agent's key, producing a verifiable, hash-chained attestation. Returns the signed bundle.",
    kind: "core",
    inputSchema: {
      type: "object",
      properties: {
        type: str("Operation type (short label, e.g. 'commit', 'payment', 'email')."),
        action: str("Action verb (e.g. 'create', 'send', 'approve')."),
        payload: str("JSON string describing what was done."),
        meta: str("Optional JSON string of extra metadata."),
      },
      required: ["type", "action", "payload"],
      additionalProperties: false,
    },
    argv: (a) => [
      "sign",
      "--type", String(a.type ?? ""),
      "--action", String(a.action ?? ""),
      "--payload", String(a.payload ?? ""),
      ...(a.meta ? ["--meta", String(a.meta)] : []),
    ],
  },
  {
    name: "vault_list",
    description:
      "List credentials in the Alien vault — names, types, domains, and access level only (never secret values). A listed credential HAS its secret fields stored.",
    kind: "vault",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    argv: () => ["list"],
  },
  {
    name: "vault_add",
    description:
      "Store a credential in the Alien vault. You supply only name/type/domains/access (and login_url for logins); the owner types the secret values into a secure card — they never reach you. If the site has NO password — it asks for an e-mail/phone and sends a code — pass passwordless=true with otp=\"interactive\": the card then has a single identifier field, and the code is asked for separately at sign-in time. Never invent a password for such a site and never ask the owner for one. Types: bearer, basic, header, query, cookie, oauth2, login, totp.",
    kind: "vault",
    inputSchema: {
      type: "object",
      properties: {
        name: str("Credential name (letters, digits, dot/dash/underscore)."),
        type: {
          type: "string",
          enum: ["bearer", "basic", "header", "query", "cookie", "oauth2", "login", "totp"],
          description: "Credential type.",
        },
        domains: strArr("Host allowlist this credential may be used on (e.g. api.github.com)."),
        access: { type: "string", enum: ["ro", "rw"], description: "Access level (default rw)." },
        description: str("Optional human-readable description."),
        login_url: str("For type=login only: the sign-in page URL (required for browser auto-login)."),
        otp: {
          type: "string",
          enum: ["none", "totp", "interactive"],
          description:
            "For type=login: how a one-time code is answered. `interactive` asks the owner for the code at sign-in time.",
        },
        passwordless: {
          type: "boolean",
          description:
            "For type=login: the site has no password — an identifier is submitted and a code arrives by mail/SMS. Requires otp=interactive. The owner's card then has a single field.",
        },
        recipe: str("For type=login: JSON array of sign-in steps (navigate|fill|type|click|press|wait) with {username}/{password}/{otp}."),
      },
      required: ["name", "type"],
      additionalProperties: false,
    },
    argv: (a) => [
      "add",
      "--name", String(a.name ?? ""),
      "--type", String(a.type ?? ""),
      "--form", // secrets collected out of band (hosted card), never argv
      ...(Array.isArray(a.domains) && a.domains.length ? ["--domains", a.domains.join(",")] : []),
      ...(a.access === "ro" || a.access === "rw" ? ["--access", a.access] : []),
      ...(a.description ? ["--description", String(a.description)] : []),
      ...(a.login_url ? ["--login-url", String(a.login_url)] : []),
      ...(a.otp ? ["--otp", String(a.otp)] : []),
      ...(a.passwordless ? ["--passwordless"] : []),
      ...(a.recipe ? ["--recipe", String(a.recipe)] : []),
    ],
  },
  {
    name: "vault_remove",
    description: "Delete a credential from the Alien vault by name.",
    kind: "vault",
    inputSchema: {
      type: "object",
      properties: { name: str("Credential name to remove.") },
      required: ["name"],
      additionalProperties: false,
    },
    argv: (a) => ["remove", "--name", String(a.name ?? "")],
  },
  {
    name: "vault_set_totp",
    description:
      "Attach a 2FA/TOTP seed to a login or totp credential so logins can generate codes. The owner types the seed into a secure card; it never reaches you.",
    kind: "vault",
    inputSchema: {
      type: "object",
      properties: { name: str("Credential name to attach the TOTP seed to.") },
      required: ["name"],
      additionalProperties: false,
    },
    argv: (a) => ["set-totp", "--name", String(a.name ?? ""), "--form"],
  },
];
