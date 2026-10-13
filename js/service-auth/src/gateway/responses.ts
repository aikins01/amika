/** What the gateway adds to, or answers instead of, a service's responses. */
import { SERVICE_TOKEN_HEADER } from "../credentials";
import { AMIKAD_SERVICE, type ServiceRoute } from "./routes";

/**
 * What a refused caller on a service route should do next, for the `hint` of
 * its 401: someone running `curl` against a route with no credential is told
 * where a token goes, and one whose token was refused that it needs a new
 * one. Nothing for amikad, which takes only the host key.
 */
export function tokenHint(
  route: ServiceRoute | null,
  token: string | null,
): { hint?: string } {
  if (!route || route.service === AMIKAD_SERVICE) return {};
  return {
    hint: token
      ? `The service token is invalid or expired; get a new one from Amika.`
      : `Send a service token from Amika in ${SERVICE_TOKEN_HEADER}: Bearer <token>.`,
  };
}

/**
 * Narrow where a service link's path can end up. The path carries the
 * signature that authorizes it, so every copy of the URL is a working
 * credential until it expires, and none can be revoked individually.
 *
 * Applied to every response on a link route, not only a proxied one.
 * hostd's own answers carry the same credential-bearing URL, and two are
 * cacheable without asking: a `404` for a service that is gone, and the
 * `308` that adds a missing trailing slash -- the most-travelled response
 * of all, since it catches every pasted link, and one whose `Location`
 * repeats the signature.
 *
 * Each header is `set`, not defaulted, and applied after a guest's own are
 * copied: the credential belongs to hostd, not to the service, so a service
 * must not be able to opt into spreading it. Stopgaps while the link is the
 * credential.
 */
export function hardenServiceLinkResponse(response: Response): Response {
  const headers = response.headers;
  // Every link on the host shares one origin; without this a service worker
  // one link registers would claim the others' paths too.
  headers.delete("service-worker-allowed");
  // Keep the path out of `Referer`. Browsers already withhold it
  // cross-origin by default, but same-origin requests still carry the whole
  // URL and `Referer` is forwarded to the guest, so a co-hosted service
  // would otherwise be handed a working link. Note this is only the fallback
  // in the precedence chain -- `<meta name="referrer">` and a
  // `referrerpolicy` attribute beat it -- so it covers a service that sets no
  // policy, not one that sets out to leak.
  headers.set("referrer-policy", "no-referrer");
  // A cache entry is keyed by its URL, so storing one writes the signature to
  // disk, where it outlives the tab that fetched it. The cost is that a
  // preview re-fetches its assets, which is the right trade for a credential.
  headers.set("cache-control", "private, no-store");
  // And a link that reaches a crawler should not become a search result.
  headers.set("x-robots-tag", "noindex");
  return response;
}
