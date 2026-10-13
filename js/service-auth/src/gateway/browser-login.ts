/**
 * Browser login through Amika (KAPRO-1038), the gateway's side. The flow
 * and the credentials are described in `../credentials/browser-login.ts`.
 *
 * - `GET /__amika/login?return=<path>` (`startLogin`) remembers a random
 *   state and the path to return to in `__Host-amika-login`, then sends the
 *   browser to Amika's authorize page, naming this host's origin.
 * - `POST /__amika/callback` (`finishLogin`) takes the login pass Amika posts
 *   back, checks it against that state, and sets the session cookie,
 *   `__Host-amika-session`, before returning to the path.
 *
 * Previews, which the session opens, come next; for now nothing needs it.
 *
 * Every cookie is `__Host-` (Secure, `Path=/`, no `Domain`) and none is set
 * on a loopback address or an explicit port (`browserOrigin`), where every
 * other local server would receive it. The session is `SameSite=Lax`, so a
 * preview opened from Amika (another site) will carry it; `Strict` would
 * send every such click back to log in. The login state is `SameSite=None`:
 * it has to come back on Amika's cross-site form post, and holds nothing
 * but a random value and a path.
 */
import { randomBytes } from "node:crypto";
import {
  CALLBACK_PATH,
  LOGIN_PASS_REPLAY_WINDOW_S,
  LOGIN_PATH,
  SESSION_TTL_S,
  STATE_PATTERN,
  signSession,
  verifyLoginPass,
} from "../credentials";
import {
  LOGIN_STATE_COOKIE,
  SESSION_COOKIE,
  cookieValues,
  isLoopbackHost,
} from "./link-cookie";

export { CALLBACK_PATH, LOGIN_PATH };

/** How long a login may take, from leaving for Amika to coming back. */
const LOGIN_STATE_TTL_S = 10 * 60;

/** Longer return paths are dropped rather than carried through a cookie. */
const MAX_RETURN_PATH_LENGTH = 2048;

/**
 * The origin a browser reached this host at, as Amika knows it (its
 * registered URL), or null where the gateway sets no cookies: a loopback
 * address or an explicit port. The server listens on plain http behind the
 * tunnel, so the scheme is always https.
 */
export function browserOrigin(url: URL): string | null {
  if (url.port !== "" || isLoopbackHost(url.hostname)) return null;
  return `https://${url.hostname}`;
}

/**
 * `GET /__amika/login`: send the browser to Amika's authorize page for this
 * host, remembering where to return. Amika answers by posting a pass to
 * this host's registered URL, never to a URL the request names.
 */
export function startLogin(request: Request, amikaUrl: string): Response {
  const url = new URL(request.url);
  const origin = browserOrigin(url);
  if (!origin) {
    return noStore(
      Response.json(
        {
          error:
            "Browser login needs the host's own https address, without a port; open the rig's service link instead",
        },
        { status: 400 },
      ),
    );
  }
  const back = returnPath(url.searchParams.get("return"));
  const state = randomBytes(32).toString("base64url");
  const value = `${state}.${Buffer.from(back).toString("base64url")}`;
  const authorize = new URL(
    "hosts/authorize",
    amikaUrl.endsWith("/") ? amikaUrl : `${amikaUrl}/`,
  );
  authorize.search = new URLSearchParams({ origin, state }).toString();
  return noStore(
    new Response(null, {
      status: 302,
      headers: {
        Location: authorize.toString(),
        "Set-Cookie": `${LOGIN_STATE_COOKIE}=${value}; Path=/; Max-Age=${LOGIN_STATE_TTL_S}; HttpOnly; Secure; SameSite=None`,
      },
    }),
  );
}

/**
 * Login states already answered, kept until their passes have expired:
 * a pass verifies for at most `LOGIN_PASS_REPLAY_WINDOW_S` after it is
 * first used. Kept in memory, so a restart forgets them; a replay then
 * still needs both the pass and the browser's state cookie.
 */
export function usedLoginStates(ttlMs = LOGIN_PASS_REPLAY_WINDOW_S * 1000) {
  const used = new Map<string, number>();
  return {
    /** Record `state`; false if it was already used. */
    claim(state: string, nowMs = Date.now()): boolean {
      for (const [seen, until] of used) {
        if (until <= nowMs) used.delete(seen);
      }
      if (used.has(state)) return false;
      used.set(state, nowMs + ttlMs);
      return true;
    },
  };
}

export type UsedLoginStates = ReturnType<typeof usedLoginStates>;

/**
 * `POST /__amika/callback`: check the pass Amika posted against the login
 * this browser started, then set the session and return to the path it
 * wanted. A pass answers one login, once.
 */
export async function finishLogin(
  request: Request,
  secretKey: string,
  used: UsedLoginStates,
  nowS = Math.floor(Date.now() / 1000),
): Promise<Response> {
  const origin = browserOrigin(new URL(request.url));
  const login = parseLoginState(
    cookieValues(request.headers.get("cookie")).get(LOGIN_STATE_COOKIE),
  );
  const form = await request.formData().catch(() => null);
  const pass = form?.get("pass");
  if (!origin || !login || typeof pass !== "string") {
    return loginFailed();
  }
  const vouched = await verifyLoginPass(
    secretKey,
    pass,
    { origin, state: login.state },
    nowS,
  );
  if (typeof vouched === "string" || !used.claim(login.state)) {
    return loginFailed();
  }
  const session = await signSession(
    secretKey,
    { origin, user: vouched.user },
    nowS,
  );
  const headers = new Headers({ Location: login.back });
  headers.append(
    "Set-Cookie",
    `${SESSION_COOKIE}=${session}; Path=/; Max-Age=${SESSION_TTL_S}; HttpOnly; Secure; SameSite=Lax`,
  );
  headers.append(
    "Set-Cookie",
    `${LOGIN_STATE_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None`,
  );
  return noStore(new Response(null, { status: 303, headers }));
}

/**
 * A path on this host to return to after login: never another origin. The
 * value is resolved as a browser would resolve `Location`, which drops tabs
 * and newlines and reads `\` as `/`, so `/\t/evil.example` cannot slip
 * through as `//evil.example`; what comes back is the resolved path and
 * query, percent-encoded.
 */
function returnPath(value: string | null): string {
  if (!value?.startsWith("/") || value.length > MAX_RETURN_PATH_LENGTH) {
    return "/";
  }
  let resolved: URL;
  try {
    resolved = new URL(value, RETURN_BASE);
  } catch {
    return "/";
  }
  if (resolved.origin !== RETURN_BASE) return "/";
  const back = `${resolved.pathname}${resolved.search}`;
  if (back.startsWith(LOGIN_PATH) || back.startsWith(CALLBACK_PATH)) {
    return "/";
  }
  return back;
}

/** Any origin but a real one: only a path resolving within it returns. */
const RETURN_BASE = "https://return.invalid";

function parseLoginState(
  value: string | undefined,
): { state: string; back: string } | null {
  const dot = value?.indexOf(".") ?? -1;
  if (!value || dot < 0) return null;
  const state = value.slice(0, dot);
  if (!STATE_PATTERN.test(state)) return null;
  const back = returnPath(
    Buffer.from(value.slice(dot + 1), "base64url").toString("utf8"),
  );
  return { state, back };
}

function loginFailed(): Response {
  return noStore(
    new Response(
      "Login failed or expired. Open the preview again to retry.\n",
      { status: 401, headers: { "Content-Type": "text/plain; charset=utf-8" } },
    ),
  );
}

function noStore(response: Response): Response {
  response.headers.set("cache-control", "no-store");
  return response;
}
