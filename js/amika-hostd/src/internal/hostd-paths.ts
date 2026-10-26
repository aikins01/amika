/** hostd's own paths, which the gateway's preview cookie never claims. */

/**
 * Whether `pathname` is hostd's own, never a guest's through the cookie: the
 * versioned API (`/v0beta1/...`, every rig, service, and preview route), the
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
