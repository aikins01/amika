/**
 * A rig's service reached at its own hostname, through the tunnel's server,
 * the real app and the real gateway: the browser login end to end.
 *
 * Sockets are fed to `virtualServer` exactly as the tunnel feeds it, with
 * the two headers the gateway writes, so what is under test is the path a
 * browser at `web--demo.r.acme.o.amika.test` takes.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { request as httpRequest } from "node:http";
import { createServer, type AddressInfo, type Server } from "node:net";
import { signLoginPass } from "@amika/service-auth/credentials";
import { createApp } from "./app.js";
import type { MachineRuntime } from "./internal/machine-runtime.js";
import { memoryServiceRegistry } from "./internal/service-registry.js";
import { virtualServer } from "./internal/tunnel-serving.js";

const SECRET = "test-secret";
const AMIKA = "https://app.amika.test";
const NAME = "web--demo.r.acme.o.amika.test";
const ORIGIN = `https://${NAME}`;
const NAMED = { "x-amika-rig": "demo", "x-amika-service": "web" };
const NAVIGATE = { "sec-fetch-mode": "navigate", "sec-fetch-site": "none" };

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((s) => new Promise((done) => s.close(done))),
  );
});

/** A host whose `demo` rig serves `web`, reached as the tunnel reaches it. */
async function tunnelledHost() {
  const runtime = {
    hostPort: vi.fn(async () => 41001),
    list: vi.fn(async () => []),
  } as unknown as MachineRuntime;
  const registry = memoryServiceRegistry();
  registry.set("demo", { web: 3000 });
  const guest = vi.fn<typeof fetch>(
    async (url) => new Response(`guest ${url}`),
  );
  const app = createApp({ secretKey: SECRET, amikaUrl: AMIKA }, runtime, {
    registry,
    fetch: guest,
  });
  const tunnel = virtualServer({ fetch: app.fetch });
  const server = createServer((socket) => tunnel.accept(socket));
  servers.push(server);
  await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
  const { port } = server.address() as AddressInfo;

  /** One request down the "tunnel", with the gateway's headers. */
  function send(
    path: string,
    headers: Record<string, string> = {},
    { method = "GET", body }: { method?: string; body?: string } = {},
  ) {
    return new Promise<{
      status: number;
      location?: string;
      cookies: string[];
      body: string;
    }>((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port,
          method,
          path,
          headers: { host: NAME, ...NAMED, ...headers },
        },
        (res) => {
          let text = "";
          res.on("data", (chunk: Buffer) => (text += chunk.toString()));
          res.on("end", () =>
            resolve({
              status: res.statusCode ?? 0,
              location: res.headers.location,
              cookies: res.headers["set-cookie"] ?? [],
              body: text,
            }),
          );
        },
      );
      req.on("error", reject);
      if (body !== undefined) req.write(body);
      req.end();
    });
  }
  return { app, guest, send };
}

/** `name=value` of the cookie `name` in `cookies`. */
function cookie(cookies: string[], name: string): string {
  const found = cookies.find((c) => c.startsWith(`${name}=`));
  if (!found) throw new Error(`no ${name} cookie`);
  return found.split(";")[0]!;
}

describe("a rig's service at its own hostname", () => {
  it("logs a browser in at that origin and serves the page it asked for", async () => {
    const { guest, send } = await tunnelledHost();

    // 1. The page, with no session: off to log in, coming back here.
    const page = await send("/app?q=1", NAVIGATE);
    expect(page.status).toBe(302);
    expect(page.location).toBe(
      `/__amika/login?${new URLSearchParams({ return: "/app?q=1" })}`,
    );

    // 2. The login, on the same origin: to Amika, naming this origin.
    const start = await send(page.location!, NAVIGATE);
    expect(start.status).toBe(302);
    const authorize = new URL(start.location!);
    expect(`${authorize.origin}${authorize.pathname}`).toBe(
      `${AMIKA}/hosts/authorize`,
    );
    expect(authorize.searchParams.get("origin")).toBe(ORIGIN);
    const state = authorize.searchParams.get("state")!;

    // 3. Amika's pass, posted back to this origin's callback.
    const pass = await signLoginPass(SECRET, {
      origin: ORIGIN,
      state,
      user: "user_1",
    });
    const callback = await send(
      "/__amika/callback",
      {
        cookie: cookie(start.cookies, "__Host-amika-login"),
        "content-type": "application/x-www-form-urlencoded",
      },
      { method: "POST", body: new URLSearchParams({ pass }).toString() },
    );
    expect(callback.status).toBe(303);
    expect(callback.location).toBe("/app?q=1");
    const session = cookie(callback.cookies, "__Host-amika-session");

    // 4. The page again, now with a session: the guest's, path untouched.
    const served = await send("/app?q=1", { ...NAVIGATE, cookie: session });
    expect(served.status).toBe(200);
    expect(served.body).toBe("guest http://127.0.0.1:41001/app?q=1");
    // The session is the gateway's, never the guest's.
    const [, init] = guest.mock.calls.at(-1)!;
    expect(new Headers(init?.headers).get("cookie")).toBeNull();
  });

  it("gives the service every path, this daemon's API paths included", async () => {
    const { guest, send } = await tunnelledHost();

    // No session and no key: refused, and never the machine list.
    const api = await send("/v0beta1/rigs", {
      authorization: `Bearer ${SECRET}`,
    });
    expect(api.status).toBe(401);
    expect(guest).not.toHaveBeenCalled();
  });

  it("serves a caller holding the host key at the service's name", async () => {
    const { send } = await tunnelledHost();

    const answer = await send("/v0beta1/rigs", {
      "x-amika-hostd-key": SECRET,
    });

    expect(answer.status).toBe(200);
    expect(answer.body).toBe("guest http://127.0.0.1:41001/v0beta1/rigs");
  });

  it("does not name a request that reached a listener with the same headers", async () => {
    // On a listening socket the headers are anybody's. The app must treat
    // the request as one for its own API, and want the key for it.
    const { app, guest } = await tunnelledHost();

    const answer = await app.request(`https://${NAME}/app`, {
      headers: { ...NAMED, ...NAVIGATE },
    });

    expect(answer.status).toBe(401);
    expect(guest).not.toHaveBeenCalled();
  });
});
