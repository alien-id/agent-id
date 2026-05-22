import type { genericOAuth } from "better-auth/plugins";

export declare const ALIEN_PROD_SSO_BASE_URL: "https://sso.alien-api.com";

export interface AlienBetterAuthOptions {
  /**
   * The Alien provider address (acts as OAuth `client_id`). Required.
   *
   * Production: register a provider in the Alien Developer Portal and use the
   * returned account address. Local development (`examples/dev-sso.mjs`):
   * any non-empty string is accepted.
   */
  clientId: string;

  /**
   * Base URL of the Alien SSO server. Defaults to the production endpoint
   * `https://sso.alien-api.com`. Override to `http://localhost:5050`
   * (or similar) when running against the local dev-sso.
   */
  baseUrl?: string;

  /**
   * Provider id used by Better Auth to identify this provider in user
   * sessions and `signIn.oauth2({ providerId })` calls. Defaults to `"alien"`.
   */
  providerId?: string;

  /**
   * OAuth scopes to request. Defaults to `["openid"]`. The Alien SSO
   * v1 server advertises only `openid` in `scopes_supported`.
   */
  scopes?: string[];

  /**
   * Explicit callback URL. Most apps do not need to set this — Better Auth
   * derives it from `baseURL` + `/api/auth/callback/<providerId>`.
   */
  redirectURI?: string;

  /**
   * Map the raw Alien userinfo profile onto a Better Auth user record.
   * Defaults to synthesizing `{ id: sub, email: "${sub}@alien.local",
   * emailVerified: false, name: "Alien · ${sub.slice(0,12)}…" }` because
   * the Alien SSO v1 profile only carries `sub` and Better Auth's user
   * model requires `email`.
   *
   * Override when you want to surface a different display name or wire
   * the synthetic email to your own domain.
   */
  mapProfileToUser?: (profile: Record<string, unknown>) => {
    id?: string;
    email?: string;
    emailVerified?: boolean;
    name?: string;
    image?: string;
    [key: string]: unknown;
  };
}

export declare function alienBetterAuth(
  options: AlienBetterAuthOptions,
): ReturnType<typeof genericOAuth>;
