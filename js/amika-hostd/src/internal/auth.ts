/** Reject requests that do not present the daemon's shared secret key. */
import { secretMatches } from "@amika/service-auth/gateway";
import type { MiddlewareHandler } from "hono";

/**
 * Require `Authorization: Bearer <secret key>`, read the same way as the
 * amika-mono worker's `checkWorkerAuth`: strip a leading `Bearer` scheme,
 * trim, and compare in constant time.
 */
export function requireSecretKey(secretKey: string): MiddlewareHandler {
  return async (c, next) => {
    const provided =
      c.req
        .header("Authorization")
        ?.replace(/^Bearer\s+/i, "")
        .trim() ?? "";
    if (!secretMatches(provided, secretKey)) {
      // Close the connection so Node stops reading an unauthenticated body.
      return c.json({ error: "Unauthorized" }, 401, { Connection: "close" });
    }
    await next();
  };
}
