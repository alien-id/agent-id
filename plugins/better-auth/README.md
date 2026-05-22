# @alien-id/better-auth-plugin

**Sign in with Alien** for [Better Auth](https://better-auth.com).

Thin wrapper around Better Auth's `genericOAuth` plugin with Alien SSO discovery
and PKCE pre-wired. ~10 lines in your `auth.ts`; no other Alien-specific code.

## What you get

Authenticated users arrive with an `alien.sub` that is:

- **biometrically attested** — the human passed liveness + biometry in the Alien App
- **stable across relying parties** — same human → same `sub` across every RP
- **one-tap revocable everywhere** — the human revokes in-app, every session collapses

Passkeys, OAuth, and your auth platform's `sub` claim do not give you this.

## Install

```bash
npm i better-auth @alien-id/better-auth-plugin
```

## Wire it up

```ts
// auth.ts
import { betterAuth } from "better-auth";
import { alienBetterAuth } from "@alien-id/better-auth-plugin";

export const auth = betterAuth({
  baseURL: process.env.BETTER_AUTH_URL,        // e.g. http://localhost:3000
  secret: process.env.BETTER_AUTH_SECRET!,
  plugins: [
    alienBetterAuth({
      clientId: process.env.ALIEN_CLIENT_ID!,  // your registered provider address
      // baseUrl defaults to https://sso.alien-api.com
    }),
  ],
});
```

Trigger the flow client-side:

```ts
import { authClient } from "./auth-client";

await authClient.signIn.oauth2({
  providerId: "alien",
  callbackURL: "/dashboard",
});
```

## Local development (no DevPortal trip)

For end-to-end testing without registering a provider, run the dev SSO from the
`alien-agent-id` repo:

```bash
git clone https://github.com/alien-id/agent-id
cd agent-id
node examples/dev-sso.mjs --port 5050
```

Then point the plugin at it:

```ts
alienBetterAuth({
  clientId: "dev-fixture-provider",
  baseUrl: "http://localhost:5050",
})
```

The dev SSO auto-approves every authorize request and issues a fixture identity.
No QR scan, no Alien App. **Production gives you real biometric attestation;
local dev does not.**

## Options

| Option | Type | Default | Notes |
|---|---|---|---|
| `clientId` | `string` | required | Registered provider address (prod) or any non-empty string (dev) |
| `baseUrl` | `string` | `https://sso.alien-api.com` | Override for local dev SSO |
| `providerId` | `string` | `"alien"` | Better Auth provider id |
| `scopes` | `string[]` | `["openid"]` | Alien v1 only advertises `openid` |
| `redirectURI` | `string` | derived | Override the callback URL |

## Notes on the Alien SSO contract

- **Public client (PKCE-only).** The token endpoint advertises
  `token_endpoint_auth_methods_supported: ["none"]`. Better Auth's `genericOAuth`
  types mark `clientSecret` as required, so the plugin passes a literal
  `"public"` placeholder; the SSO server never reads it.
- **DPoP is optional.** Better Auth does not speak DPoP; when no `dpop_jkt` is
  sent at `/authorize`, the SSO server falls back to standard Bearer tokens.
- **`openid` is the only Wave-1 scope.** Verified-name and selective-disclosure
  claims arrive in later phases.

## License

MIT
