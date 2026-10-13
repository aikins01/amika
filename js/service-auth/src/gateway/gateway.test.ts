/** Cover the gateway's decision for each way in, without a server. */
import { describe, expect, it } from "vitest";
import { signServiceLink, signServiceToken } from "../credentials";
import { createGateway } from "./gateway";
import type { GatewayRequest } from "./routes";

const SECRET = "0123456789abcdef0123456789abcdef";
const gateway = createGateway({
  secretKey: SECRET,
  isOwnPath: (pathname) => pathname.startsWith("/v0beta1/"),
});

function request(
  path: string,
  headers: Record<string, string> = {},
  method = "GET",
): GatewayRequest {
  return {
    method,
    url: new URL(`https://preview.example${path}`),
    headers: new Headers(headers),
  };
}

const inAMinute = () => Math.floor(Date.now() / 1000) + 60;

describe("createGateway", () => {
  it("forwards a keyed service request to its guest path", async () => {
    const decision = await gateway.authorize(
      request("/v0beta1/rigs/demo/services/web/api", {
        "X-Amika-Hostd-Key": SECRET,
      }),
    );
    expect(decision).toEqual({
      kind: "forward",
      surface: "service",
      route: { machine: "demo", service: "web", path: "/api" },
      keyless: false,
      setCookie: null,
    });
  });

  it("forwards a service token for its service, and hints when refused", async () => {
    const token = await signServiceToken(SECRET, {
      rig: "demo",
      service: "web",
    });
    const ok = await gateway.authorize(
      request("/v0beta1/rigs/demo/services/web/", {
        "X-Amika-Authorization": `Bearer ${token}`,
      }),
    );
    expect(ok.kind).toBe("forward");

    const refused = await gateway.authorize(
      request("/v0beta1/rigs/demo/services/web/"),
    );
    expect(refused).toMatchObject({
      kind: "refuse",
      surface: "service",
      status: 401,
      hint: expect.stringContaining("X-Amika-Authorization"),
    });
  });

  it("forwards a link, setting its cookie only on a page load", async () => {
    const token = await signServiceLink(SECRET, {
      rig: "demo",
      service: "web",
      expiresAt: inAMinute(),
    });
    const path = `/v0beta1/rigs/demo/service-links/web/${token}/app.js`;
    const asset = await gateway.authorize(request(path));
    expect(asset).toMatchObject({
      kind: "forward",
      surface: "link",
      route: { path: "/app.js" },
      setCookie: null,
    });
    const page = await gateway.authorize(
      request(path, { "Sec-Fetch-Mode": "navigate" }),
    );
    expect(page).toMatchObject({ kind: "forward", surface: "link" });
    expect(page.kind === "forward" && page.setCookie).toMatch(
      /^__Host-amika-service-link=demo\/web\//,
    );
  });

  it("routes a root-relative URL by the link cookie, outside its own paths", async () => {
    const token = await signServiceLink(SECRET, {
      rig: "demo",
      service: "web",
      expiresAt: inAMinute(),
    });
    const headers = {
      Cookie: `__Host-amika-service-link=demo/web/${token}`,
      "Sec-Fetch-Site": "same-origin",
    };
    expect(await gateway.authorize(request("/@vite/client", headers))).toEqual({
      kind: "forward",
      surface: "link",
      route: { machine: "demo", service: "web", path: "/@vite/client" },
      keyless: false,
      setCookie: null,
    });
    // A service worker from the root would claim every link on the host.
    expect(
      await gateway.authorize(
        request("/sw.js", { ...headers, "Service-Worker": "script" }),
      ),
    ).toEqual({ kind: "refuse", surface: "link", status: 404 });
    // The server's own paths are never the cookie's.
    expect(await gateway.authorize(request("/v0beta1/rigs", headers))).toEqual({
      kind: "not-mine",
    });
  });

  it("leaves anything else to the server", async () => {
    expect(await gateway.authorize(request("/health"))).toEqual({
      kind: "not-mine",
    });
    expect(gateway.claims(request("/health"))).toBe(false);
    expect(gateway.claims(request("/v0beta1/rigs/demo/services/web/"))).toBe(
      true,
    );
  });

  // Only an upgrade may be amikad's SSH WebSocket, never a plain request.
  it("lets amikad's SSH upgrade through without the key only as an upgrade", async () => {
    const ssh = request("/v0beta1/rigs/demo/services/amikad/v1/ssh-sessions", {
      Connection: "Upgrade",
      Upgrade: "websocket",
    });
    expect(await gateway.authorize(ssh, { upgrade: true })).toMatchObject({
      kind: "forward",
      keyless: true,
    });
    expect(await gateway.authorize(ssh)).toMatchObject({
      kind: "refuse",
      status: 401,
    });
  });

  it("keeps its credentials from the guest", () => {
    expect(gateway.isCredentialHeader("x-amika-hostd-key")).toBe(true);
    expect(gateway.isCredentialHeader("x-amika-authorization")).toBe(true);
    expect(gateway.isCredentialHeader("authorization")).toBe(false);
    expect(
      gateway.guestCookies("theme=dark; __Host-amika-service-link=a/b/c"),
    ).toBe("theme=dark");
  });

  it("hardens every answer on a link, and only there", async () => {
    const link = gateway.refusal({
      kind: "refuse",
      surface: "link",
      status: 401,
    });
    expect(link.headers.get("cache-control")).toBe("private, no-store");
    const service = gateway.refusal({
      kind: "refuse",
      surface: "service",
      status: 401,
      hint: "send a token",
    });
    expect(service.headers.get("cache-control")).toBeNull();
    expect(await service.json()).toEqual({
      error: "Unauthorized",
      hint: "send a token",
    });
  });
});
