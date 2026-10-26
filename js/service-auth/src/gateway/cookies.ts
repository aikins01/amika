/**
 * The gateway's cookies, and how they are kept from a guest.
 *
 * Every one is `__Host-`: the browser insists on `Secure`, `Path=/`, and no
 * `Domain`, so no other host (a sibling subdomain of the tunnel, say) can set
 * or read it. None is set on a loopback address or an explicit port
 * (`./browser-login.ts`'s `browserOrigin`), where every other local server
 * would receive it.
 */
import { BlockList, isIP } from "node:net";

/**
 * The gateway's cookies for previews (`./browser-login.ts`): the signed
 * browser session, the preview whose root-relative URLs a page asks for,
 * and a login in progress. None reaches a guest.
 */
export const SESSION_COOKIE = "__Host-amika-session";
export const PREVIEW_COOKIE = "__Host-amika-preview";
export const LOGIN_STATE_COOKIE = "__Host-amika-login";

/**
 * The cookie retired service links set, naming a link's token. Nothing reads
 * it any more, but a browser may hold one until that link's expiry, so it is
 * still kept from guests and ended when a preview opens.
 */
export const LINK_COOKIE = "__Host-amika-service-link";

/** A `Set-Cookie` value that removes the gateway cookie `name`. */
export function expiredCookie(name: string): string {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

/**
 * Whether a guest's `Set-Cookie` would set one of the gateway's cookies, or
 * any cookie under their prefix, so a guest's server cannot log a browser
 * in, out, or into another login. Defence in depth only: a guest's page
 * shares the origin, and its script can still set such a cookie where none
 * is held, as a host is one trusted unit.
 */
export function setsGatewayCookie(setCookie: string): boolean {
  const eq = setCookie.indexOf("=");
  const name = (eq < 0 ? setCookie : setCookie.slice(0, eq)).trim();
  return name.toLowerCase().startsWith(GATEWAY_COOKIE_PREFIX);
}

const GATEWAY_COOKIE_PREFIX = "__host-amika-";

const GATEWAY_COOKIES: ReadonlySet<string> = new Set([
  LINK_COOKIE,
  SESSION_COOKIE,
  PREVIEW_COOKIE,
  LOGIN_STATE_COOKIE,
]);

/**
 * `cookieHeader` without the gateway's cookies, or null when nothing else is
 * left: they are the gateway's credentials and state, so a guest never sees
 * them.
 */
export function withoutGatewayCookies(
  cookieHeader: string | null | undefined,
): string | null {
  const kept = (cookieHeader ?? "")
    .split(";")
    .map((pair) => pair.trim())
    .filter((pair) => pair && !GATEWAY_COOKIES.has(pair.split("=")[0].trim()));
  return kept.length ? kept.join("; ") : null;
}

/** Whether `cookieHeader` may carry one of the gateway's cookies. */
export function carriesGatewayCookie(cookieHeader: string): boolean {
  return cookieHeader.includes("__Host-amika-");
}

/**
 * Whether `hostname` (as `URL.hostname` spells it) reaches this machine,
 * where every local server shares one cookie jar: `localhost` and its
 * subdomains, or an address in `LOCAL_ADDRESSES`. The URL parser already
 * turns odd IPv4 spellings (`0x7f.1`, `2130706433`) into dotted ones, and
 * `BlockList` matches an IPv4-mapped IPv6 address (`[::ffff:7f00:1]`)
 * against the IPv4 rules.
 */
export function isLoopbackHost(hostname: string): boolean {
  // One trailing dot is the same name to a resolver; more make no valid
  // name, so read them the cautious way too.
  const name = hostname.replace(/\.+$/, "").toLowerCase();
  if (name === "localhost" || name.endsWith(".localhost")) return true;
  const address = name.replace(/^\[(.*)\]$/, "$1");
  const family = isIP(address);
  return (
    family !== 0 &&
    LOCAL_ADDRESSES.check(address, family === 6 ? "ipv6" : "ipv4")
  );
}

/**
 * Loopback, and the unspecified addresses, which reach this machine too on
 * Linux and macOS.
 */
const LOCAL_ADDRESSES = new BlockList();
LOCAL_ADDRESSES.addSubnet("127.0.0.0", 8, "ipv4");
LOCAL_ADDRESSES.addAddress("0.0.0.0", "ipv4");
LOCAL_ADDRESSES.addAddress("::1", "ipv6");
LOCAL_ADDRESSES.addAddress("::", "ipv6");

export function cookieValues(cookieHeader: string | null | undefined) {
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
