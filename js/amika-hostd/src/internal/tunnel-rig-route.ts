/**
 * Reading which rig and service a tunnelled request is for.
 *
 * A browser reaches a rig at `<service>--<rig>.r.<org>.o.<zone>`. The
 * reverse proxy reads the rig and the service out of that name and signs
 * them, and the gateway checks the signature and writes them onto the
 * tunnel stream as two headers, after removing every `x-amika-` header the
 * request arrived with. So on a tunnel stream these two are the gateway's
 * word, and nothing a caller could have written.
 *
 * On a listening socket they are anybody's, which is why only the tunnel's
 * server reads them. Nothing on the listening path does.
 *
 * The request is then sent where a request for that service has always
 * gone: the service route, with the original path after it. It meets the
 * same authorization, the same port lookup and the same forwarding as one
 * that named the rig in its path, and the rig receives the path the
 * browser asked for.
 *
 * The gateway spells these names in `@amika/service-token/hops`
 * (`GATEWAY_TO_HOST`), in the amika-mono repository. Change both or
 * neither.
 */
import type { IncomingMessage } from "node:http";

/** The rig the request is for. */
export const RIG_HEADER = "x-amika-rig";
/** The service on that rig. */
export const SERVICE_HEADER = "x-amika-service";

/** Where a request for `service` on `rig` is served, without a trailing slash. */
export type ServicePath = (rig: string, service: string) => string;

export type RigRouteOutcome =
  /** The request names no rig: it is for this daemon's own API. */
  | { kind: "api" }
  /** The request was rewritten to the service route. */
  | { kind: "service"; rig: string; service: string }
  /** The request names a rig in a way that cannot be served. */
  | { kind: "refuse"; reason: string };

/**
 * Point `request` at the service its rig headers name, or say why not.
 *
 * Rewrites `request.url` in place and removes the two headers, so the
 * service the request reaches does not see them. A request with neither
 * header is left alone: the control plane's calls to this daemon's API
 * name no rig.
 *
 * With no `servicePath`, a request that names a rig is refused rather
 * than served as an API call, so a browser is never answered with this
 * daemon's own routes.
 */
export function routeRigService(
  request: IncomingMessage,
  servicePath: ServicePath | undefined,
): RigRouteOutcome {
  const rig = request.headers[RIG_HEADER];
  const service = request.headers[SERVICE_HEADER];
  if (rig === undefined && service === undefined) return { kind: "api" };
  if (servicePath === undefined) {
    return { kind: "refuse", reason: "this server serves no rig by name" };
  }
  // One without the other is a gateway that does not speak this contract.
  // Serving it as an API call would answer a browser with this daemon's
  // own routes.
  if (typeof rig !== "string" || typeof service !== "string") {
    return { kind: "refuse", reason: "rig and service must come together" };
  }
  if (!NAME.test(rig) || !NAME.test(service)) {
    return { kind: "refuse", reason: "rig or service is not a name" };
  }
  // Origin-form only. The gateway refuses anything else before it opens
  // a stream, so this is the second line, not the first.
  const target = request.url;
  if (
    target === undefined ||
    !target.startsWith("/") ||
    target.startsWith("//")
  ) {
    return { kind: "refuse", reason: "request target is not a path" };
  }
  request.url = `${servicePath(rig, service)}${target}`;
  dropHeaders(request, [RIG_HEADER, SERVICE_HEADER]);
  return { kind: "service", rig, service };
}

/**
 * A rig or service name: one DNS label's worth of letters, digits and
 * hyphens. Both came out of a hostname, and both go into a path, so
 * nothing else may be in them.
 */
const NAME = /^[A-Za-z0-9-]{1,63}$/;

/**
 * Remove `names` from both views of the request's headers.
 *
 * `@hono/node-server` builds its `Request` from `rawHeaders`, and the rest
 * of Node reads `headers`, so a header left in either reaches someone.
 */
function dropHeaders(request: IncomingMessage, names: readonly string[]): void {
  for (const name of names) delete request.headers[name];
  const kept: string[] = [];
  for (let i = 0; i < request.rawHeaders.length; i += 2) {
    const name = request.rawHeaders[i]!;
    if (names.includes(name.toLowerCase())) continue;
    kept.push(name, request.rawHeaders[i + 1]!);
  }
  request.rawHeaders.splice(0, request.rawHeaders.length, ...kept);
}
