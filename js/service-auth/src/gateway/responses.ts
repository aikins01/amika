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
 * Drop a guest's cache policy for CDNs. A tunnel's CDN reads these before
 * `Cache-Control`, so a guest's `CDN-Cache-Control: max-age=600` would
 * otherwise have it keep a logged-in answer for everyone.
 */
export function dropCdnCachePolicies(headers: Headers): void {
  for (const name of [
    "cdn-cache-control",
    "cloudflare-cdn-cache-control",
    "surrogate-control",
  ]) {
    headers.delete(name);
  }
}
