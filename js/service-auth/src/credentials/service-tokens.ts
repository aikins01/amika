/**
 * Service tokens: how a caller that is not a browser reaches an amika-hostd
 * rig's service.
 *
 * hostd routes `/v0beta1/rigs/<rig>/services/<name>/...` for callers that
 * present the host's secret key in a header. A service token lets `curl` and
 * scripts use the same route without that key:
 *
 *   curl -H "X-Amika-Authorization: Bearer <token>" \
 *     https://<host>/v0beta1/rigs/<rig>/services/<name>/
 *
 * The token is `<expiry>.<signature>`. `<expiry>` is a Unix time in seconds
 * and `<signature>` is the base64url HMAC-SHA256 of
 * `v1\n<rig>\n<name>\n<expiry>` under a token key derived from the host's
 * secret key. The control plane signs tokens and hostd verifies them, each
 * deriving the key itself, so nothing new is shared and no request reaches
 * the control plane. Regenerating the host's secret key invalidates every
 * token. A token lives at most `MAX_SERVICE_TOKEN_TTL_S`, which hostd
 * enforces too.
 *
 * The signed text is unambiguous: a rig name has no newline and an expiry is
 * digits only, so a service name containing newlines cannot be read as a
 * different rig, name or expiry.
 *
 * Browsers reach a service through a preview instead, behind a login through
 * Amika (`./browser-login.ts`).
 *
 * Only Web Crypto is used, so this runs wherever the provider does.
 */

import { signText, verifyText } from "./signing";

/** Separates a service-token key from any other use of the host's secret key. */
const TOKEN_KEY_LABEL = "amika-hostd service tokens v1";

/**
 * Carries a service token on a service route. hostd removes it before
 * forwarding, so the guest's own `Authorization` stays its own.
 */
export const SERVICE_TOKEN_HEADER = "X-Amika-Authorization";

/** How long a service token lives when the caller does not say. */
export const DEFAULT_SERVICE_TOKEN_TTL_S = 60 * 60;

/** The longest a service token may live: a day, as a browser session does. */
export const MAX_SERVICE_TOKEN_TTL_S = 24 * 60 * 60;

/**
 * How far ahead of hostd's clock a token's issuer may be. A token that claims
 * to live longer than `MAX_SERVICE_TOKEN_TTL_S` plus this is refused.
 */
const CLOCK_SKEW_S = 5 * 60;

/** Unix seconds, at most 12 digits: a millisecond time is refused. */
const EXPIRY_PATTERN = /^[1-9][0-9]{0,11}$/;
const MAX_EXPIRY = 10 ** 12 - 1;

/** What a service token grants: one service of one rig, until `expiresAt`. */
interface ServiceTokenClaim {
  rig: string;
  service: string;
  /** Unix time in seconds after which the token is refused. */
  expiresAt: number;
}

/**
 * A service token granting `rig`'s `service` until `nowS + ttlS`, for the
 * `X-Amika-Authorization` header. Throws for a lifetime that is not a whole
 * number of seconds between 1 and `MAX_SERVICE_TOKEN_TTL_S`.
 */
export async function signServiceToken(
  secretKey: string,
  { rig, service }: { rig: string; service: string },
  {
    ttlS = DEFAULT_SERVICE_TOKEN_TTL_S,
    nowS = Math.floor(Date.now() / 1000),
  }: { ttlS?: number; nowS?: number } = {},
): Promise<string> {
  if (
    !Number.isSafeInteger(ttlS) ||
    ttlS <= 0 ||
    ttlS > MAX_SERVICE_TOKEN_TTL_S
  ) {
    throw new Error(
      `A service token's lifetime must be 1 to ${MAX_SERVICE_TOKEN_TTL_S} seconds`,
    );
  }
  return sign(TOKEN_KEY_LABEL, secretKey, {
    rig,
    service,
    expiresAt: nowS + ttlS,
  });
}

/**
 * Why `token` does not grant `rig`'s `service` at `nowS` (Unix seconds), or
 * null when it does. The signature is checked in constant time before the
 * expiry, so a forged token is told nothing about its expiry. A token that
 * claims to live longer than `MAX_SERVICE_TOKEN_TTL_S` (give or take clock
 * skew) is refused too: only a buggy or compromised issuer mints one.
 */
export async function verifyServiceToken(
  secretKey: string,
  token: { rig: string; service: string; token: string },
  nowS: number,
): Promise<"malformed" | "invalid" | "expired" | null> {
  const problem = await verify(TOKEN_KEY_LABEL, secretKey, token, nowS);
  if (problem) return problem;
  const expiresAt = Number(token.token.slice(0, token.token.indexOf(".")));
  return expiresAt - nowS > MAX_SERVICE_TOKEN_TTL_S + CLOCK_SKEW_S
    ? "invalid"
    : null;
}

async function sign(
  label: string,
  secretKey: string,
  claim: ServiceTokenClaim,
): Promise<string> {
  if (
    !Number.isSafeInteger(claim.expiresAt) ||
    claim.expiresAt <= 0 ||
    claim.expiresAt > MAX_EXPIRY
  ) {
    throw new Error(
      "A service token's expiry must be a positive Unix time in seconds",
    );
  }
  return `${claim.expiresAt}.${await signText(label, secretKey, signedText(claim))}`;
}

async function verify(
  label: string,
  secretKey: string,
  { rig, service, token }: { rig: string; service: string; token: string },
  nowS: number,
): Promise<"malformed" | "invalid" | "expired" | null> {
  const dot = token.indexOf(".");
  const expiry = token.slice(0, dot);
  if (dot < 0 || !EXPIRY_PATTERN.test(expiry)) return "malformed";
  const expiresAt = Number(expiry);
  const problem = await verifyText(
    label,
    secretKey,
    signedText({ rig, service, expiresAt }),
    token.slice(dot + 1),
  );
  if (problem) return problem;
  return expiresAt > nowS ? null : "expired";
}

function signedText({ rig, service, expiresAt }: ServiceTokenClaim): string {
  return `v1\n${rig}\n${service}\n${expiresAt}`;
}
