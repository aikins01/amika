/** Exercise browser login through the daemon's HTTP boundary. */
import { signLoginPass } from "@amika/service-auth/credentials";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "./app.js";
import type { MachineRuntime } from "./internal/machine-runtime.js";
import { memoryServiceRegistry } from "./internal/service-registry.js";

const SECRET = "test-secret";
const AMIKA = "https://app.amika.test";
const HOST = "https://preview.example";

/** A host whose `demo` rig serves `web` and amikad; the guest answers `ok`. */
function host({ amikaUrl = AMIKA as string | null } = {}) {
  const runtime = {
    hostPort: vi.fn(async () => 41001),
  } as unknown as MachineRuntime;
  const registry = memoryServiceRegistry();
  registry.set("demo", { amikad: 60999, web: 3000 });
  const guest = vi.fn<typeof fetch>(
    async () =>
      new Response("ok", {
        headers: { "Cache-Control": "public, max-age=60" },
      }),
  );
  const app = createApp(
    { secretKey: SECRET, amikaUrl: amikaUrl ?? undefined },
    runtime,
    {
      registry,
      fetch: guest,
    },
  );
  return { app, guest };
}

/** The `name=value` of the cookie `name` among a response's `Set-Cookie`s. */
function setCookie(response: Response, name: string): string | undefined {
  return response.headers
    .getSetCookie()
    .find((cookie) => cookie.startsWith(`${name}=`));
}

/** Log in as a browser would: login, Amika's pass, callback. */
async function logIn(
  app: ReturnType<typeof createApp>,
  back = "/v0beta1/rigs/demo/previews/web/",
) {
  const start = await app.request(
    `${HOST}/__amika/login?${new URLSearchParams({ return: back })}`,
  );
  const stateCookie = setCookie(start, "__Host-amika-login")!.split(";")[0];
  const state = new URL(start.headers.get("location")!).searchParams.get(
    "state",
  )!;
  const pass = await signLoginPass(SECRET, {
    origin: HOST,
    state,
    user: "user_1",
  });
  const callback = await app.request(`${HOST}/__amika/callback`, {
    method: "POST",
    headers: { Cookie: stateCookie },
    body: new URLSearchParams({ pass }),
  });
  const session = setCookie(callback, "__Host-amika-session")?.split(";")[0];
  return { start, callback, session, stateCookie, pass };
}

describe("browser login", () => {
  it("starts a login at Amika, naming this host's origin", async () => {
    const { start } = await logIn(host().app);
    expect(start.status).toBe(302);
    const location = new URL(start.headers.get("location")!);
    expect(`${location.origin}${location.pathname}`).toBe(
      `${AMIKA}/hosts/authorize`,
    );
    expect(location.searchParams.get("origin")).toBe(HOST);
    expect(location.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // The state has to come back on Amika's cross-site form post.
    expect(setCookie(start, "__Host-amika-login")).toMatch(
      /; Max-Age=600; HttpOnly; Secure; SameSite=None$/,
    );
    expect(start.headers.get("cache-control")).toBe("no-store");
  });

  it.each([
    ["a loopback address", "http://localhost:3020"],
    ["an explicit port", "https://preview.example:8443"],
  ])("refuses to start a login on %s", async (_label, origin) => {
    const response = await host().app.request(`${origin}/__amika/login`);
    expect(response.status).toBe(400);
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it("sets a session on a valid pass and returns to the preview", async () => {
    const { callback, session } = await logIn(host().app);
    expect(callback.status).toBe(303);
    expect(callback.headers.get("location")).toBe(
      "/v0beta1/rigs/demo/previews/web/",
    );
    // Lax: a preview opened from Amika, another site, still carries it.
    expect(setCookie(callback, "__Host-amika-session")).toMatch(
      /; Path=\/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax$/,
    );
    expect(setCookie(callback, "__Host-amika-login")).toMatch(/Max-Age=0/);
    expect(session).toBeDefined();
  });

  it("answers a pass once", async () => {
    const { app } = host();
    const { stateCookie, pass } = await logIn(app);
    const replay = await app.request(`${HOST}/__amika/callback`, {
      method: "POST",
      headers: { Cookie: stateCookie },
      body: new URLSearchParams({ pass }),
    });
    expect(replay.status).toBe(401);
    expect(replay.headers.getSetCookie()).toEqual([]);
  });

  it("refuses a pass for another browser's login", async () => {
    const { app } = host();
    const { pass } = await logIn(app);
    // A login this browser started, but not the one the pass answers.
    const other = await app.request(`${HOST}/__amika/login`);
    const response = await app.request(`${HOST}/__amika/callback`, {
      method: "POST",
      headers: {
        Cookie: setCookie(other, "__Host-amika-login")!.split(";")[0],
      },
      body: new URLSearchParams({ pass }),
    });
    expect(response.status).toBe(401);
  });

  // The pass and the session are for the origin the login started at.
  it("refuses a callback at another origin than the login's", async () => {
    const { app } = host();
    const { stateCookie, pass } = await logIn(app);
    const response = await app.request(
      "https://preview.example:8443/__amika/callback",
      {
        method: "POST",
        headers: { Cookie: stateCookie },
        body: new URLSearchParams({ pass }),
      },
    );
    expect(response.status).toBe(401);
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it("refuses a callback body over its limit before reading it", async () => {
    const body = new URLSearchParams({ pass: "x".repeat(32 * 1024) });
    const response = await host().app.request(`${HOST}/__amika/callback`, {
      method: "POST",
      headers: { "Content-Length": String(body.toString().length) },
      body,
    });
    expect(response.status).toBe(413);
  });

  it("refuses a pass with no login state at all", async () => {
    const { app } = host();
    const { pass } = await logIn(app);
    const response = await app.request(`${HOST}/__amika/callback`, {
      method: "POST",
      body: new URLSearchParams({ pass }),
    });
    expect(response.status).toBe(401);
  });

  // Each one a browser would resolve to another origin: tabs and newlines
  // are dropped, and `\` reads as `/`.
  it.each([
    "//evil.example/x",
    "/\t/evil.example",
    "/\n/evil.example",
    "/\\evil.example",
    "https://evil.example/",
  ])("never returns to another origin after login, given %j", async (back) => {
    const { callback } = await logIn(host().app, back);
    expect(callback.status).toBe(303);
    expect(callback.headers.get("location")).toBe("/");
  });

  it("returns to a path as the browser would resolve it", async () => {
    const { callback } = await logIn(host().app, "/a/../docs?q=1 2#top");
    expect(callback.headers.get("location")).toBe("/docs?q=1%202");
  });

  it("does not let a session open the keyed service route", async () => {
    const { app } = host();
    const { session } = await logIn(app);
    const response = await app.request(
      `${HOST}/v0beta1/rigs/demo/services/web/`,
      { headers: { Cookie: session! } },
    );
    expect(response.status).toBe(401);
  });

  it("serves no login without Amika's URL", async () => {
    const { app } = host({ amikaUrl: null });
    expect((await app.request(`${HOST}/__amika/login`)).status).toBe(401);
  });
});
