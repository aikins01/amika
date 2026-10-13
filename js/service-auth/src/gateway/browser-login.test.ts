/**
 * Cover the gateway's login pieces below the server (what it stores and
 * claims), its preview decisions, and its cache-control rule.
 */
import { describe, expect, it } from "vitest";
import { signServiceLink, signSession } from "../credentials";
import {
  browserOrigin,
  hardenPreviewResponse,
  privateCacheControl,
  startLogin,
  usedLoginStates,
} from "./browser-login";
import { createGateway } from "./gateway";
import type { GatewayRequest } from "./routes";

const SECRET = "0123456789abcdef0123456789abcdef";
const ORIGIN = "https://preview.example";
const AMIKA = "https://app.amika.test";
const gateway = createGateway({
  secretKey: SECRET,
  isOwnPath: (pathname) => pathname.startsWith("/v0beta1/"),
  amikaUrl: AMIKA,
});

function request(
  path: string,
  headers: Record<string, string> = {},
  { origin = ORIGIN, method = "GET" } = {},
): GatewayRequest {
  return {
    method,
    url: new URL(`${origin}${path}`),
    headers: new Headers(headers),
  };
}

const session = async (origin = ORIGIN, nowS?: number) =>
  `__Host-amika-session=${await signSession(SECRET, { origin, user: "u" }, nowS)}`;
const PAGE_LOAD = { "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none" };

describe("previews", () => {
  it("forwards a preview with a session, setting its cookie on a page load", async () => {
    const decision = await gateway.authorize(
      request("/v0beta1/rigs/demo/previews/web/docs", {
        ...PAGE_LOAD,
        Cookie: await session(),
      }),
    );
    expect(decision).toMatchObject({
      kind: "forward",
      surface: "preview",
      route: { machine: "demo", service: "web", path: "/docs" },
      // And ends any link cookie, so the preview opened last owns the root.
      setCookies: [
        expect.stringMatching(/^__Host-amika-preview=demo\/web; /),
        expect.stringMatching(/^__Host-amika-service-link=; .*Max-Age=0/),
      ],
    });
  });

  it("ends the preview cookie when a link is opened after it", async () => {
    const token = await signServiceLink(SECRET, {
      rig: "demo",
      service: "api",
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const decision = await gateway.authorize(
      request(`/v0beta1/rigs/demo/service-links/api/${token}/`, PAGE_LOAD),
    );
    expect(decision).toMatchObject({
      kind: "forward",
      surface: "link",
      setCookies: [
        expect.stringMatching(/^__Host-amika-service-link=demo\/api\//),
        expect.stringMatching(/^__Host-amika-preview=; .*Max-Age=0/),
      ],
    });
  });

  // The session is Lax, which a sibling subdomain counts as the same site.
  it.each([
    ["a sibling subdomain's post", { "Sec-Fetch-Site": "same-site" }, "POST"],
    ["another site's fetch", { "Sec-Fetch-Site": "cross-site" }, "GET"],
    ["a request with no fetch metadata", {}, "GET"],
  ])("refuses %s, session or not", async (_label, headers, method) => {
    expect(
      await gateway.authorize(
        request(
          "/v0beta1/rigs/demo/previews/web/api/delete",
          { ...headers, Cookie: await session() },
          { method },
        ),
      ),
    ).toEqual({ kind: "refuse", surface: "preview", status: 403 });
  });

  it("serves a page load another site starts, as Amika opens a preview", async () => {
    expect(
      await gateway.authorize(
        request("/v0beta1/rigs/demo/previews/web/", {
          "Sec-Fetch-Mode": "navigate",
          "Sec-Fetch-Site": "cross-site",
          Cookie: await session(),
        }),
      ),
    ).toMatchObject({ kind: "forward", surface: "preview" });
  });

  it("lets an upgrade through only from this origin's own page", async () => {
    const upgrade = async (origin?: string) =>
      gateway.authorize(
        request("/v0beta1/rigs/demo/previews/web/hmr", {
          Cookie: await session(),
          "Sec-Fetch-Site": "same-origin",
          ...(origin ? { Origin: origin } : {}),
        }),
        { upgrade: true },
      );
    expect(await upgrade(ORIGIN)).toMatchObject({
      kind: "forward",
      setCookies: [],
    });
    expect(await upgrade("https://evil.preview.example")).toMatchObject({
      kind: "refuse",
      status: 403,
    });
    expect(await upgrade()).toMatchObject({ kind: "refuse", status: 403 });
  });

  it("sends a page load without a session to log in and back", async () => {
    expect(
      await gateway.authorize(
        request("/v0beta1/rigs/demo/previews/web/docs?x=1", PAGE_LOAD),
      ),
    ).toEqual({
      kind: "login",
      location: `/__amika/login?return=${encodeURIComponent("/v0beta1/rigs/demo/previews/web/docs?x=1")}`,
    });
  });

  // Once a session expires, a reload of a root-relative page must not get
  // stuck on 401: it logs in again and returns to the same path.
  it("sends a cookie-routed page load whose session expired to log in", async () => {
    const expired = await session(ORIGIN, 1_000_000);
    expect(
      await gateway.authorize(
        request("/docs", {
          ...PAGE_LOAD,
          Cookie: `${expired}; __Host-amika-preview=demo/web`,
          "Sec-Fetch-Site": "same-origin",
        }),
      ),
    ).toEqual({
      kind: "login",
      location: `/__amika/login?return=${encodeURIComponent("/docs")}`,
    });
  });

  it("refuses anything but a page load without a session, upgrades included", async () => {
    const path = "/v0beta1/rigs/demo/previews/web/api";
    expect(await gateway.authorize(request(path))).toMatchObject({
      kind: "refuse",
      surface: "preview",
      status: 401,
    });
    expect(
      await gateway.authorize(request(path, PAGE_LOAD), { upgrade: true }),
    ).toMatchObject({ kind: "refuse", status: 401 });
  });

  it("routes a root-relative URL by the preview cookie, with the session", async () => {
    const decision = await gateway.authorize(
      request("/@vite/client", {
        Cookie: `${await session()}; __Host-amika-preview=demo/web`,
        "Sec-Fetch-Site": "same-origin",
      }),
    );
    expect(decision).toMatchObject({
      kind: "forward",
      surface: "preview",
      route: { path: "/@vite/client" },
      setCookies: [],
    });
  });

  // Opening either ends the other's cookie; this is only the tiebreak.
  it("lets a link cookie win when a browser holds both", async () => {
    const token = await signServiceLink(SECRET, {
      rig: "demo",
      service: "api",
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const decision = await gateway.authorize(
      request("/x", {
        Cookie: `__Host-amika-service-link=demo/api/${token}; ${await session()}; __Host-amika-preview=demo/web`,
        "Sec-Fetch-Site": "same-origin",
      }),
    );
    expect(decision).toMatchObject({
      kind: "forward",
      surface: "link",
      route: { service: "api" },
    });
  });

  it("refuses a session from another origin", async () => {
    expect(
      await gateway.authorize(
        request("/v0beta1/rigs/demo/previews/web/", {
          Cookie: await session("https://other.example"),
        }),
      ),
    ).toMatchObject({ kind: "refuse", status: 401 });
  });

  it("has no preview of amikad", async () => {
    expect(
      await gateway.authorize(
        request("/v0beta1/rigs/demo/previews/amikad/", {
          Cookie: await session(),
        }),
      ),
    ).toEqual({ kind: "not-mine" });
  });

  it("serves no previews without Amika's URL", async () => {
    const plain = createGateway({
      secretKey: SECRET,
      isOwnPath: () => false,
    });
    expect(plain.servesPreviews).toBe(false);
    expect(
      plain.claims(request("/v0beta1/rigs/demo/previews/web/", PAGE_LOAD)),
    ).toBe(false);
  });

  it("strips every gateway cookie from what the guest gets", () => {
    expect(
      gateway.guestCookies(
        "a=1; __Host-amika-session=s; __Host-amika-preview=p; __Host-amika-login=l; b=2",
      ),
    ).toBe("a=1; b=2");
  });
});

describe("hardenPreviewResponse", () => {
  // A tunnel's CDN reads these before Cache-Control.
  it("drops a guest's cache policy for CDNs", () => {
    const response = hardenPreviewResponse(
      new Response(null, {
        headers: {
          "CDN-Cache-Control": "max-age=600",
          "Cloudflare-CDN-Cache-Control": "max-age=600",
          "Surrogate-Control": "max-age=600",
        },
      }),
    );
    expect([...response.headers.keys()].sort()).toEqual([
      "cache-control",
      "x-robots-tag",
    ]);
  });
});

describe("privateCacheControl", () => {
  it.each([
    [null, "private"],
    ["", "private"],
    ["max-age=60", "private, max-age=60"],
    ["public, max-age=60", "private, max-age=60"],
    ["private, max-age=60", "private, max-age=60"],
    ["no-store", "no-store"],
  ])("makes %j %j", (value, expected) => {
    expect(privateCacheControl(value)).toBe(expected);
  });
});

/** The return path `startLogin` keeps in the state cookie for `back`. */
function storedReturn(back: string): string {
  const response = startLogin(
    new Request(
      `${ORIGIN}/__amika/login?${new URLSearchParams({ return: back })}`,
    ),
    AMIKA,
  );
  const value = response.headers.getSetCookie()[0].split(";")[0].split("=")[1];
  return Buffer.from(value.split(".")[1], "base64url").toString("utf8");
}

describe("startLogin", () => {
  it("keeps the path and query to return to", () => {
    expect(storedReturn("/docs?tab=2")).toBe("/docs?tab=2");
  });

  // Checked where it is stored, not only where it is read back.
  it.each([
    "//evil.example/x",
    "/\t/evil.example",
    "/\\evil.example",
    // Dot segments collapse only once resolved, into `//evil.example`.
    "/..//evil.example/x",
    "/.//evil.example",
    "/%2e%2e//evil.example",
    "/a/..//evil.example",
    "/__amika/callback",
  ])("stores / for %j", (back) => {
    expect(storedReturn(back)).toBe("/");
  });

  // A browser drops a cookie over 4 KB, which would fail the login.
  it("stores / for a path too long once encoded", () => {
    expect(storedReturn(`/${'"'.repeat(1500)}`)).toBe("/");
    expect(storedReturn(`/${"a".repeat(1500)}`)).toBe(`/${"a".repeat(1500)}`);
  });
});

describe("usedLoginStates", () => {
  it("answers a state once, until its passes have expired", () => {
    const used = usedLoginStates(1000);
    expect(used.claim("s", 0)).toBe(true);
    expect(used.claim("s", 999)).toBe(false);
    expect(used.claim("s", 1000)).toBe(true);
  });
});

describe("browserOrigin", () => {
  it.each([
    ["https://preview.example/x", ORIGIN],
    ["http://preview.example/x", ORIGIN],
    ["https://preview.example:8443/x", null],
    ["http://localhost/x", null],
    ["http://127.0.0.1/x", null],
  ])("makes %s %j", (url, origin) => {
    expect(browserOrigin(new URL(url))).toBe(origin);
  });
});

describe("the login endpoints", () => {
  const get = (path: string): GatewayRequest => ({
    method: "GET",
    url: new URL(`${ORIGIN}${path}`),
    headers: new Headers(),
  });
  const isOwnPath = () => false;

  it("are the gateway's only with Amika's URL", () => {
    const gateway = createGateway({
      secretKey: "k",
      isOwnPath,
      amikaUrl: AMIKA,
    });
    expect(gateway.claims(get("/__amika/login"))).toBe(true);
    expect(gateway.claims(get("/__amika/callback"))).toBe(true);
    const plain = createGateway({ secretKey: "k", isOwnPath });
    expect(plain.claims(get("/__amika/login"))).toBe(false);
    expect(plain.claims(get("/__amika/callback"))).toBe(false);
  });
});
