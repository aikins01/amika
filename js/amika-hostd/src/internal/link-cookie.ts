/**
 * The service-link cookie: how a page opened through a service link keeps
 * working once it asks for root-relative URLs.
 *
 * A link serves a service under `/v0beta1/rigs/<rig>/service-links/<name>/
 * <token>/`, but most dev servers (Vite, Next.js) write root-relative URLs
 * into their pages: `/@vite/client`, `/_next/static/...`, `/api/...`. Those
 * reach hostd with no rig, service, or token, so on their own they could only
 * be refused.
 *
 * Opening a link in a browser therefore also sets this cookie, naming the
 * link's rig, service, and token. A request outside hostd's own paths
 * (`isHostdPath`) that carries it is verified exactly as the link would be
 * and forwarded to that service, with its path as the guest path. The cookie
 * grants what the link grants, until the link's own expiry, and is never
 * forwarded to a guest.
 *
 * Only a request the browser marks as the origin's own (`Sec-Fetch-Site:
 * same-origin`, or `none` for one the user started) may use the cookie, and
 * it is never set on a loopback address, whose cookies every local server
 * shares (`linkCookie`, `linkFromCookie`).
 *
 * One host is one origin, so a browser holds one such cookie per host: the
 * link it opened last. A second service opened side by side takes over the
 * root-relative requests of the first. Pages under a link path are
 * unaffected, since their path carries their own token.
 */
import { AMIKAD_SERVICE } from "./services.js";

/**
 * `__Host-` makes the browser insist on `Secure`, `Path=/`, and no `Domain`,
 * so no other host (a sibling subdomain of the tunnel, say) can set or read
 * it.
 */
export const LINK_COOKIE = "__Host-amika-service-link";

/** What the cookie names: a link's rig, service, and token. */
export interface LinkCookieClaim {
  machine: string;
  service: string;
  token: string;
}

/**
 * The `Set-Cookie` value for a link the browser just opened, or null when the
 * request was not a navigation (a script or an image loaded through a link
 * should not change which service owns the root), the link is amikad's, its
 * token carries no usable expiry, or the host was reached on a loopback
 * address: a browser scopes cookies by host, not port, so one set for
 * `localhost:3020` would go to every other server on `localhost` too.
 *
 * `SameSite=Strict` keeps the cookie off requests other sites start, though
 * a site is a registrable domain, so a sibling subdomain still counts as the
 * same one; `linkFromCookie` therefore also requires the browser's
 * same-origin mark. `HttpOnly`: a guest's script cannot read the token.
 */
export function linkCookie(
  request: Request,
  link: LinkCookieClaim,
  nowS = Math.floor(Date.now() / 1000),
): string | null {
  if (request.headers.get("sec-fetch-mode") !== "navigate") return null;
  if (link.service === AMIKAD_SERVICE) return null;
  if (isLoopbackHost(new URL(request.url).hostname)) return null;
  const maxAge = Number(link.token.split(".")[0]) - nowS;
  if (!Number.isSafeInteger(maxAge) || maxAge <= 0) return null;
  const value = `${link.machine}/${encodeURIComponent(link.service)}/${link.token}`;
  return `${LINK_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

/**
 * The link a request's `Cookie` header names, or null when it names none or
 * one that cannot be read, or the request is not the origin's own:
 * `fetchSite` (its `Sec-Fetch-Site`) must be `same-origin`, or `none` for a
 * navigation the user started (an address typed, a bookmark, a reload). A
 * page on another origin, even a sibling subdomain the cookie's `SameSite`
 * lets through, cannot drive a preview's routes. Only parsed here; the
 * caller verifies the token. amikad is never reached this way.
 */
export function linkFromCookie(
  cookieHeader: string | null | undefined,
  fetchSite: string | string[] | null | undefined,
): LinkCookieClaim | null {
  if (fetchSite !== "same-origin" && fetchSite !== "none") return null;
  const value = cookieValues(cookieHeader).get(LINK_COOKIE);
  const match =
    value && /^([a-zA-Z0-9][a-zA-Z0-9_-]*)\/([^/]+)\/([^/]+)$/.exec(value);
  if (!match) return null;
  let service: string;
  try {
    service = decodeURIComponent(match[2]);
  } catch {
    return null;
  }
  if (service === AMIKAD_SERVICE) return null;
  return { machine: match[1], service, token: match[3] };
}

/**
 * `cookieHeader` without the link cookie, or null when nothing else is left:
 * the token is hostd's, so a guest never sees it.
 */
export function withoutLinkCookie(
  cookieHeader: string | null | undefined,
): string | null {
  const kept = (cookieHeader ?? "")
    .split(";")
    .map((pair) => pair.trim())
    .filter((pair) => pair && pair.split("=")[0].trim() !== LINK_COOKIE);
  return kept.length ? kept.join("; ") : null;
}

/**
 * Whether `pathname` is hostd's own, never a guest's through the cookie: the
 * versioned API (`/v0beta1/...`, every rig, service, and link route), the
 * legacy machine API, and `/health`. Everything else on the host belongs to
 * the service the cookie names.
 */
export function isHostdPath(pathname: string): boolean {
  return (
    pathname === "/health" ||
    pathname === "/v0beta1" ||
    pathname.startsWith("/v0beta1/") ||
    pathname === "/api/v1/machines" ||
    pathname.startsWith("/api/v1/machines/")
  );
}

/**
 * Whether `hostname` (as `URL.hostname` spells it) is a loopback address,
 * where every local server shares one cookie jar.
 */
export function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname === "[::1]" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
  );
}

function cookieValues(cookieHeader: string | null | undefined) {
  const values = new Map<string, string>();
  for (const pair of (cookieHeader ?? "").split(";")) {
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    const name = pair.slice(0, eq).trim();
    // The first one wins, as browsers send the most specific first.
    if (!values.has(name)) values.set(name, pair.slice(eq + 1).trim());
  }
  return values;
}
