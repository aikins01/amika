/**
 * The checks behind each way a caller proves itself on a service route: the
 * host's secret key, a service token, or a signed link.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import {
  SERVICE_TOKEN_HEADER,
  verifyServiceLink,
  verifyServiceToken,
} from "../credentials";
import {
  AMIKAD_SERVICE,
  type ServiceLinkRoute,
  type ServiceRoute,
} from "./routes";

/** Carries the host's secret key on service routes; never forwarded. */
export const SERVICE_KEY_HEADER = "x-amika-hostd-key";

/** Carries a service token on service routes; never forwarded. */
export const SERVICE_TOKEN_HEADER_NAME = SERVICE_TOKEN_HEADER.toLowerCase();

/**
 * Why a service request is refused, or null to let it through: 401 without
 * the right key in `X-Amika-Hostd-Key` (unless `requireKey` is false, for
 * amikad's SSH upgrade), 400 when the key is also sent as the
 * `Authorization` the guest would receive.
 */
export function authorizeServiceRequest(
  secretKey: string,
  headers: {
    key?: string | string[] | null;
    authorization?: string | string[] | null;
  },
  { requireKey = true }: { requireKey?: boolean } = {},
): 400 | 401 | null {
  const key = typeof headers.key === "string" ? headers.key.trim() : "";
  if (requireKey && !secretMatches(key, secretKey)) return 401;
  const authorization =
    typeof headers.authorization === "string"
      ? headers.authorization.replace(/^Bearer\s+/i, "").trim()
      : "";
  return authorization && secretMatches(authorization, secretKey) ? 400 : null;
}

/**
 * Why a request on a service route is refused, or null to let it through: as
 * `authorizeServiceRequest`, except that a caller without the key may present
 * a service token for exactly this route's rig and service instead. amikad
 * never takes a token.
 */
export async function authorizeServiceRouteRequest(
  secretKey: string,
  route: Pick<ServiceRoute, "machine" | "service"> | null,
  headers: {
    key?: string | string[] | null;
    token?: string | string[] | null;
    authorization?: string | string[] | null;
  },
  { requireKey = true }: { requireKey?: boolean } = {},
  nowS = Math.floor(Date.now() / 1000),
): Promise<400 | 401 | null> {
  const keyed = authorizeServiceRequest(secretKey, headers, { requireKey });
  if (keyed !== 401) return keyed;
  const token = bearerToken(headers.token);
  if (!token || !route || route.service === AMIKAD_SERVICE) return 401;
  const problem = await verifyServiceToken(
    secretKey,
    { rig: route.machine, service: route.service, token },
    nowS,
  );
  if (problem) return 401;
  return authorizeServiceRequest(secretKey, headers, { requireKey: false });
}

/** The token in `Bearer <token>`, or "" when the header holds none. */
export function bearerToken(header: string | string[] | null | undefined) {
  if (typeof header !== "string") return "";
  const match = /^Bearer\s+(\S+)\s*$/i.exec(header.trim());
  return match ? match[1] : "";
}

/**
 * Why a service-link request is refused, or null to let it through: 401
 * unless the link's token is a signature over its machine and service that
 * has not expired, 400 when the host key is sent as the `Authorization` the
 * guest would receive. The host key header is not needed, nor checked.
 */
export async function authorizeServiceLinkRequest(
  secretKey: string,
  link: ServiceLinkRoute,
  headers: { authorization?: string | string[] | null },
  nowS = Math.floor(Date.now() / 1000),
): Promise<400 | 401 | null> {
  const problem = await verifyServiceLink(
    secretKey,
    { rig: link.machine, service: link.service, token: link.token },
    nowS,
  );
  if (problem) return 401;
  return authorizeServiceRequest(secretKey, headers, { requireKey: false });
}

/**
 * Compare two strings without leaking their length or content: HMAC both with
 * a per-call random key so `timingSafeEqual` always sees 32-byte buffers.
 */
export function secretMatches(a: string, b: string): boolean {
  const key = randomBytes(32);
  const aDigest = createHmac("sha256", key).update(a).digest();
  const bDigest = createHmac("sha256", key).update(b).digest();
  return timingSafeEqual(aDigest, bDigest);
}
