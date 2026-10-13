/** Cover the gateway's login pieces below the server: what it stores and claims. */
import { describe, expect, it } from "vitest";
import { browserOrigin, startLogin, usedLoginStates } from "./browser-login";
import { createGateway } from "./gateway";
import type { GatewayRequest } from "./routes";

const ORIGIN = "https://preview.example";
const AMIKA = "https://app.amika.test";

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
  const request = (path: string): GatewayRequest => ({
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
    expect(gateway.claims(request("/__amika/login"))).toBe(true);
    expect(gateway.claims(request("/__amika/callback"))).toBe(true);
    const plain = createGateway({ secretKey: "k", isOwnPath });
    expect(plain.claims(request("/__amika/login"))).toBe(false);
    expect(plain.claims(request("/__amika/callback"))).toBe(false);
  });
});
