import { genericOAuth } from "better-auth/plugins";

export const ALIEN_PROD_SSO_BASE_URL = "https://sso.alien-api.com";

export function alienBetterAuth(options = {}) {
  const {
    clientId,
    baseUrl = ALIEN_PROD_SSO_BASE_URL,
    providerId = "alien",
    scopes = ["openid"],
    redirectURI,
    mapProfileToUser,
  } = options;

  if (!clientId) {
    throw new Error(
      "@alien-id/better-auth-plugin: `clientId` is required. " +
      "For prod, register a provider in the Alien Developer Portal. " +
      "For local dev-sso, any non-empty string works."
    );
  }

  const trimmedBase = baseUrl.replace(/\/+$/, "");

  return genericOAuth({
    config: [{
      providerId,
      clientId,
      // Alien SSO is a public OAuth client (token_endpoint_auth_methods_supported: ["none"]).
      // Better Auth's genericOAuth types mark clientSecret as required, so we pass a
      // placeholder; the SSO server does not read it.
      clientSecret: "public",
      discoveryUrl: `${trimmedBase}/.well-known/openid-configuration`,
      pkce: true,
      scopes,
      ...(redirectURI ? { redirectURI } : {}),
      // Alien SSO returns only `sub` — no email, no display name. Better Auth's
      // user model insists on email, so we synthesize a stable, recognizably
      // fake one from the verified sub. Consumers can override.
      mapProfileToUser: mapProfileToUser ?? defaultMapProfileToUser,
    }],
  });
}

function defaultMapProfileToUser(profile) {
  const sub = profile?.sub ?? profile?.id;
  if (!sub) throw new Error("@alien-id/better-auth-plugin: Alien userinfo lacked `sub`");
  return {
    id: sub,
    email: `${sub}@alien.local`,
    emailVerified: false,
    name: `Alien · ${String(sub).slice(0, 12)}…`,
  };
}
