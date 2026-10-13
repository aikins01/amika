/**
 * Signed service links: browser-usable URLs for an amika-hostd rig's services.
 *
 * hostd routes `/v0beta1/rigs/<rig>/services/<name>/...` only for callers that
 * present the host's secret key in a header, which a browser navigation cannot
 * send and which must never reach a browser anyway. A service link carries a
 * credential in its path instead:
 *
 *   /v0beta1/rigs/<rig>/service-links/<name>/<expiry>.<signature>/<guest path>
 *
 * `<expiry>` is a Unix time in seconds and `<signature>` is the base64url
 * HMAC-SHA256 of `v1\n<rig>\n<name>\n<expiry>` under a link key derived from
 * the host's secret key. The provider (which holds the secret key on the
 * control plane) signs links and hostd verifies them, each deriving the link
 * key itself, so nothing new is shared and no request reaches the control
 * plane. Regenerating the host's secret key invalidates every link.
 *
 * The signed text is unambiguous: a rig name has no newline and an expiry is
 * digits only, so a service name containing newlines cannot be read as a
 * different rig, name or expiry.
 *
 * Every link on a host shares the host's one origin, so links isolate
 * services only as far as paths can: cookies and storage are shared, and a
 * service's root-relative URLs (`/assets/app.js`) leave its link. hostd sends
 * those to the link the browser opened last, which it records in a cookie
 * (amika-hostd's `link-cookie.ts`). hostd strips `Service-Worker-Allowed`
 * from link responses, so a service worker a page registers is confined to
 * its own link. One origin per service would need wildcard DNS for each host.
 *
 * Service tokens are the same claim signed under a second derived key, for
 * callers that are not browsers: `curl -H "X-Amika-Authorization: Bearer
 * <token>"` against the service route `/v0beta1/rigs/<rig>/services/<name>/`,
 * whose URL carries no credential. The keys differ so a link's token never
 * works as a header token, nor the other way round. A token lives at most
 * `MAX_SERVICE_TOKEN_TTL_S`, which hostd enforces too.
 *
 * Only Web Crypto is used, so this runs wherever the provider does.
 */

/** The path segment that marks a service-link route. */
export const SERVICE_LINKS_SEGMENT = "service-links";

/** Separates a link key from any other use of the host's secret key. */
const LINK_KEY_LABEL = "amika-hostd service links v1";

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

/** An HMAC-SHA256 digest is 32 bytes: 43 base64url characters, unpadded. */
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
/** Unix seconds, at most 12 digits: a millisecond time is refused. */
const EXPIRY_PATTERN = /^[1-9][0-9]{0,11}$/;
const MAX_EXPIRY = 10 ** 12 - 1;

const encoder = new TextEncoder();

// The lib config has no DOM types, so `CryptoKey` is named through Web Crypto.
type LinkKey = Awaited<ReturnType<typeof crypto.subtle.importKey>>;

/** What a service link grants: one service of one rig, until `expiresAt`. */
export interface ServiceLinkClaim {
  rig: string;
  service: string;
  /** Unix time in seconds after which the link is refused. */
  expiresAt: number;
}

/**
 * The `<expiry>.<signature>` token for `claim`, as it appears in the link's
 * path.
 */
export function signServiceLink(
  secretKey: string,
  claim: ServiceLinkClaim,
): Promise<string> {
  return sign(LINK_KEY_LABEL, secretKey, claim);
}

/**
 * Why `token` does not grant `rig`'s `service` at `nowS` (Unix seconds), or
 * null when it does. The signature is checked in constant time before the
 * expiry, so a forged token is told nothing about its expiry.
 */
export function verifyServiceLink(
  secretKey: string,
  link: { rig: string; service: string; token: string },
  nowS: number,
): Promise<"malformed" | "invalid" | "expired" | null> {
  return verify(LINK_KEY_LABEL, secretKey, link, nowS);
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
 * As `verifyServiceLink`, for a service token, which is also refused when it
 * claims to live longer than `MAX_SERVICE_TOKEN_TTL_S` (give or take clock
 * skew): only a buggy or compromised issuer mints one.
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
  claim: ServiceLinkClaim,
): Promise<string> {
  if (
    !Number.isSafeInteger(claim.expiresAt) ||
    claim.expiresAt <= 0 ||
    claim.expiresAt > MAX_EXPIRY
  ) {
    throw new Error(
      "A service link or token's expiry must be a positive Unix time in seconds",
    );
  }
  const key = await derivedKey(label, secretKey);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(signedText(claim)),
  );
  return `${claim.expiresAt}.${toBase64Url(new Uint8Array(signature))}`;
}

async function verify(
  label: string,
  secretKey: string,
  { rig, service, token }: { rig: string; service: string; token: string },
  nowS: number,
): Promise<"malformed" | "invalid" | "expired" | null> {
  const dot = token.indexOf(".");
  const expiry = token.slice(0, dot);
  const encoded = token.slice(dot + 1);
  if (
    dot < 0 ||
    !EXPIRY_PATTERN.test(expiry) ||
    !SIGNATURE_PATTERN.test(encoded)
  ) {
    return "malformed";
  }
  const signature = fromBase64Url(encoded);
  // 43 characters carry 258 bits, so four spellings decode to one digest;
  // accept only the canonical one.
  if (toBase64Url(signature) !== encoded) return "malformed";
  const expiresAt = Number(expiry);
  const key = await derivedKey(label, secretKey);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    signature,
    encoder.encode(signedText({ rig, service, expiresAt })),
  );
  if (!valid) return "invalid";
  return expiresAt > nowS ? null : "expired";
}

/**
 * The path of a service link, ending in `/` so the service's relative URLs
 * resolve under it. The rig name is a hostd machine name (URL-safe); the
 * service name is percent-encoded as one segment.
 */
export function serviceLinkPath(
  rigsPath: string,
  rig: string,
  service: string,
  token: string,
): string {
  return `${rigsPath}/${rig}/${SERVICE_LINKS_SEGMENT}/${encodeURIComponent(service)}/${token}/`;
}

function signedText({ rig, service, expiresAt }: ServiceLinkClaim): string {
  return `v1\n${rig}\n${service}\n${expiresAt}`;
}

/**
 * Derived keys by label and secret key. hostd verifies every asset request a
 * page makes through a link, so a key is derived once, not per request. A
 * control plane signs for many hosts, so the cache is bounded.
 */
const derivedKeys = new Map<string, Promise<LinkKey>>();
const MAX_CACHED_KEYS = 64;

/** HMAC-SHA256(secretKey, label), imported as an HMAC key. */
function derivedKey(label: string, secretKey: string): Promise<LinkKey> {
  // A label has no newline, so the pair is unambiguous.
  const cacheKey = `${label}\n${secretKey}`;
  let key = derivedKeys.get(cacheKey);
  if (!key) {
    if (derivedKeys.size >= MAX_CACHED_KEYS) derivedKeys.clear();
    key = deriveKey(label, secretKey);
    derivedKeys.set(cacheKey, key);
    key.catch(() => derivedKeys.delete(cacheKey));
  }
  return key;
}

async function deriveKey(label: string, secretKey: string): Promise<LinkKey> {
  const secret = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secretKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const derived = await crypto.subtle.sign(
    "HMAC",
    secret,
    encoder.encode(label),
  );
  return crypto.subtle.importKey(
    "raw",
    derived,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(encoded: string): Uint8Array<ArrayBuffer> {
  const binary = atob(encoded.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
