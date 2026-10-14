/**
 * The gateway: who may reach which rig's service, decided per request, apart
 * from how the request then gets there. A server (amika-hostd) asks
 * `authorize` and acts on the decision: it forwards to the route it names,
 * answers the refusal, or handles the request itself (`not-mine`).
 *
 * Three ways in, each checked here:
 *
 * - `/v0beta1/rigs/<rig>/services/<name>/...` with the host's secret key in
 *   `X-Amika-Hostd-Key`, or a service token in `X-Amika-Authorization`
 *   (`./keys.ts`). On an upgrade only, amikad's SSH WebSocket may come with
 *   neither: `keyless`, which the server must still pin to amikad's port.
 * - `/v0beta1/rigs/<rig>/service-links/<name>/<token>/...`, a signed link.
 * - Any path outside the server's own (`isOwnPath`) with the link cookie a
 *   link set (`./link-cookie.ts`): a page's root-relative URLs.
 *
 * With `amikaUrl`, the gateway also logs browsers in through Amika
 * (`./browser-login.ts`), on two endpoints the server mounts: `startLogin`
 * and `finishLogin`. The session it sets opens previews, which come next.
 *
 * Every credential is the gateway's: the server forwards none of them
 * (`isCredentialHeader`, `guestCookies`), it drops a guest's `Set-Cookie`
 * for any of the gateway's cookies (`finish`, `finishUpgrade`), and
 * responses on a link are hardened (`harden`), since their URL is a
 * credential.
 */
import {
  SERVICE_KEY_HEADER,
  SERVICE_TOKEN_HEADER_NAME,
  authorizeServiceLinkRequest,
  authorizeServiceRequest,
  authorizeServiceRouteRequest,
} from "./keys";
import {
  carriesGatewayCookie,
  linkCookie,
  linkFromCookie,
  setsGatewayCookie,
  withoutGatewayCookies,
} from "./link-cookie";
import {
  CALLBACK_PATH,
  LOGIN_PATH,
  finishLogin,
  startLogin,
  usedLoginStates,
} from "./browser-login";
import { hardenServiceLinkResponse, tokenHint } from "./responses";
import {
  isAmikadSshUpgrade,
  parseServiceLinkPath,
  parseServicePath,
  type GatewayRequest,
  type ServiceRoute,
} from "./routes";

export interface GatewayOptions {
  /** The host's secret key, from which every credential is derived. */
  secretKey: string;
  /**
   * The server's own paths, which the link cookie never claims: its API,
   * every service and link route, its health check.
   */
  isOwnPath: (pathname: string) => boolean;
  /**
   * Amika's URL, where a browser is sent to log in. Without it the gateway
   * logs no browser in, and serves no previews.
   */
  amikaUrl?: string;
}

/**
 * Where a request came in: a keyed or token service route, or a link (its
 * path, or the cookie it set). A link's responses are hardened.
 */
export type GatewaySurface = "service" | "link";

/** Forward the request to `route`'s service. */
export interface ForwardDecision {
  kind: "forward";
  surface: GatewaySurface;
  route: ServiceRoute;
  /**
   * amikad's SSH upgrade, let through without the key: the server must
   * forward it only to amikad on the port Amika registers it at.
   */
  keyless: boolean;
  /** To add to the response: a link opened in a browser sets its cookie. */
  setCookie: string | null;
}

/** Refuse the request with `status`. */
export interface RefuseDecision {
  kind: "refuse";
  surface: GatewaySurface;
  status: 400 | 401 | 404;
  /** What a refused `curl` should do next, for a 401's body. */
  hint?: string;
}

export type GatewayDecision =
  | ForwardDecision
  | RefuseDecision
  /** Not a service request: the server handles it under its own rules. */
  | { kind: "not-mine" };

export type Gateway = ReturnType<typeof createGateway>;

export function createGateway({
  secretKey,
  isOwnPath,
  amikaUrl,
}: GatewayOptions) {
  const previews = amikaUrl !== undefined;
  const loginStates = usedLoginStates();
  const cookieClaim = ({ url, headers }: GatewayRequest) =>
    isOwnPath(url.pathname)
      ? null
      : linkFromCookie(headers.get("cookie"), headers.get("sec-fetch-site"));

  return {
    /**
     * Whether `authorize` decides this request, cheaply and without its
     * body, so the server can skip its own key check for it.
     */
    claims(request: GatewayRequest): boolean {
      const { pathname } = request.url;
      return Boolean(
        parseServicePath(pathname) ||
        parseServiceLinkPath(pathname) ||
        cookieClaim(request) ||
        (previews && (pathname === LOGIN_PATH || pathname === CALLBACK_PATH)),
      );
    },

    /**
     * Who may have this request, and where it goes. `upgrade` for a
     * protocol upgrade (a WebSocket), which alone may be amikad's keyless
     * SSH upgrade and never sets a cookie.
     */
    async authorize(
      request: GatewayRequest,
      { upgrade = false }: { upgrade?: boolean } = {},
    ): Promise<GatewayDecision> {
      const { url, headers } = request;
      const credentials = {
        key: headers.get(SERVICE_KEY_HEADER),
        token: headers.get(SERVICE_TOKEN_HEADER_NAME),
        authorization: headers.get("authorization"),
      };

      // A root-relative URL a page opened through a link asks for.
      const claim = cookieClaim(request);
      if (claim) {
        // A worker script served from the root would claim every link on
        // the host, not just this one's (`hardenServiceLinkResponse`).
        if (!upgrade && headers.get("service-worker") === "script") {
          return { kind: "refuse", surface: "link", status: 404 };
        }
        const link = { ...claim, path: url.pathname };
        const refusal = await authorizeServiceLinkRequest(
          secretKey,
          link,
          credentials,
        );
        if (refusal)
          return { kind: "refuse", surface: "link", status: refusal };
        return forward("link", link, { setCookie: null });
      }

      const link = parseServiceLinkPath(url.pathname);
      if (link) {
        const refusal = await authorizeServiceLinkRequest(
          secretKey,
          link,
          credentials,
        );
        if (refusal)
          return { kind: "refuse", surface: "link", status: refusal };
        // Opening a link hands its root-relative URLs to this service.
        return forward("link", link, {
          setCookie: upgrade ? null : linkCookie(request, link),
        });
      }

      const route = parseServicePath(url.pathname);
      if (!route) return { kind: "not-mine" };
      // amikad's SSH upgrade may skip the key; a keyed request is the
      // control plane's and routes like any other.
      const keyless =
        upgrade &&
        isAmikadSshUpgrade(request) &&
        authorizeServiceRequest(secretKey, credentials) === 401;
      const refusal = await authorizeServiceRouteRequest(
        secretKey,
        route,
        credentials,
        { requireKey: !keyless },
      );
      if (refusal) {
        return {
          kind: "refuse",
          surface: "service",
          status: refusal,
          ...(refusal === 401 ? tokenHint(route, credentials.token) : {}),
        };
      }
      return forward("service", route, { keyless, setCookie: null });
    },

    /** The HTTP answer to a refusal. */
    refusal(decision: RefuseDecision): Response {
      const response =
        decision.status === 401
          ? // Close the connection so Node stops reading an unauthenticated
            // body.
            Response.json(
              {
                error: "Unauthorized",
                ...(decision.hint ? { hint: decision.hint } : {}),
              },
              { status: 401, headers: { Connection: "close" } },
            )
          : decision.status === 400
            ? Response.json(
                {
                  error: `Send the host key in ${SERVICE_KEY_HEADER}, not Authorization, which is forwarded to the guest`,
                },
                { status: 400 },
              )
            : Response.json({ error: "Not found" }, { status: 404 });
      return harden(decision, response);
    },

    harden,

    /**
     * A forwarded service's response, without any cookie of ours the guest
     * tried to set, and with the decision's.
     */
    finish(decision: ForwardDecision, response: Response): Response {
      const headers = response.headers;
      const guest = headers.getSetCookie();
      if (guest.some(setsGatewayCookie)) {
        headers.delete("set-cookie");
        for (const cookie of guest) {
          if (!setsGatewayCookie(cookie)) headers.append("set-cookie", cookie);
        }
      }
      if (decision.setCookie) {
        response.headers.append("set-cookie", decision.setCookie);
      }
      return harden(decision, response);
    },

    /**
     * `finish` for an upgrade, which the server tunnels as bytes: the
     * guest's raw answer to the handshake (its status line and header
     * lines, without the blank line that ends them), less any cookie of
     * ours it tries to set. A folded header line goes with the one it
     * continues.
     */
    finishUpgrade(head: string): string {
      const fields: string[][] = [];
      for (const line of head.split("\r\n")) {
        const last = fields.at(-1);
        if (last && fields.length > 1 && /^[ \t]/.test(line)) last.push(line);
        else fields.push([line]);
      }
      return fields
        .filter(([first, ...folded], i) => {
          if (i === 0) return true; // The status line.
          const colon = first.indexOf(":");
          if (
            colon < 0 ||
            first.slice(0, colon).trim().toLowerCase() !== "set-cookie"
          ) {
            return true;
          }
          const value = [first.slice(colon + 1), ...folded].join(" ");
          return !setsGatewayCookie(value);
        })
        .flat()
        .join("\r\n");
    },

    /**
     * Whether this gateway logs browsers in, for the previews their session
     * opens.
     */
    servesPreviews: previews,

    /**
     * `GET /__amika/login`: send the browser to Amika's authorize page for
     * this host. Only with `amikaUrl`.
     */
    startLogin(request: Request): Response {
      if (amikaUrl === undefined) throw new Error("No previews to log in to");
      return startLogin(request, amikaUrl);
    },

    /**
     * `POST /__amika/callback`: check the pass Amika posted and set the
     * session.
     */
    finishLogin(request: Request): Promise<Response> {
      return finishLogin(request, secretKey, loginStates);
    },

    /** Whether a request header (lowercased) is a credential of ours. */
    isCredentialHeader(name: string): boolean {
      return name === SERVICE_KEY_HEADER || name === SERVICE_TOKEN_HEADER_NAME;
    },

    /** Whether a `Cookie` header may carry a cookie of ours. */
    carriesCredentialCookie(cookieHeader: string): boolean {
      return carriesGatewayCookie(cookieHeader);
    },

    /** A `Cookie` header without our cookies, or null when nothing is left. */
    guestCookies(cookieHeader: string | null | undefined): string | null {
      return withoutGatewayCookies(cookieHeader);
    },

    /**
     * The host key check alone, for a request no route claims: 401 without
     * the key in `X-Amika-Hostd-Key`, 400 with it also in `Authorization`.
     */
    checkHostKey(headers: Headers): 400 | 401 | null {
      return authorizeServiceRequest(secretKey, {
        key: headers.get(SERVICE_KEY_HEADER),
        authorization: headers.get("authorization"),
      });
    },
  };

  /**
   * `response` as a link's must be: hardened on the link surface, as is
   * every answer there, the server's own `404`s and `502`s included.
   */
  function harden(
    decision: ForwardDecision | RefuseDecision,
    response: Response,
  ): Response {
    return decision.surface === "link"
      ? hardenServiceLinkResponse(response)
      : response;
  }

  function forward(
    surface: GatewaySurface,
    route: ServiceRoute,
    {
      keyless = false,
      setCookie,
    }: { keyless?: boolean; setCookie: string | null },
  ): ForwardDecision {
    return {
      kind: "forward",
      surface,
      route: {
        machine: route.machine,
        service: route.service,
        path: route.path,
      },
      keyless,
      setCookie,
    };
  }
}
