/** Cover the route parsing and credential checks behind the gateway. */
import { describe, expect, it } from "vitest";
import { authorizeServiceRequest } from "./keys";
import { parseServicePath } from "./routes";

const SECRET = "0123456789abcdef0123456789abcdef";

describe("parseServicePath", () => {
  it("splits the route and keeps the encoded guest path", () => {
    expect(
      parseServicePath("/v0beta1/rigs/demo-1/services/pi_web/v1/a%2Fb"),
    ).toEqual({
      machine: "demo-1",
      service: "pi_web",
      path: "/v1/a%2Fb",
    });
    expect(parseServicePath("/v0beta1/rigs/demo/services/web")?.path).toBe("/");
    // Amika service names are free text, carried percent-encoded.
    expect(
      parseServicePath("/v0beta1/rigs/demo/services/Coding%20Agent%2Fv2/x"),
    ).toEqual({ machine: "demo", service: "Coding Agent/v2", path: "/x" });
    expect(parseServicePath("/v0beta1/rigs/demo/services/web/")?.path).toBe(
      "/",
    );
  });

  it.each([
    "/api/v1/machines/demo",
    "/v0beta1/rigs/demo",
    "/v0beta1/rigs/demo/services",
    "/v0beta1/rigs/demo/services/",
    "/v0beta1/rigs/-demo/services/web",
    "/v0beta1/rigs/de.mo/services/web",
    "/v0beta1/rigs/demo/services/%E0%A4%A",
    "/v0beta1/rigs/demo/other/web",
    "/v0beta1/rigs/demo/service-links/web/1.sig",
  ])("rejects %s", (path) => {
    expect(parseServicePath(path)).toBeNull();
  });
});

describe("authorizeServiceRequest", () => {
  it("accepts the key in its header, trimmed, and leaves Authorization to the guest", () => {
    expect(authorizeServiceRequest(SECRET, { key: SECRET })).toBeNull();
    expect(authorizeServiceRequest(SECRET, { key: ` ${SECRET} ` })).toBeNull();
    expect(
      authorizeServiceRequest(SECRET, {
        key: SECRET,
        authorization: "Bearer connect-token",
      }),
    ).toBeNull();
  });

  it.each([
    ["no key", {}],
    ["an empty key", { key: "" }],
    ["a prefix of the key", { key: SECRET.slice(0, -1) }],
    ["the key repeated", { key: [SECRET, SECRET] }],
    ["the key only in Authorization", { authorization: `Bearer ${SECRET}` }],
  ])("refuses %s with 401", (_label, headers) => {
    expect(authorizeServiceRequest(SECRET, headers)).toBe(401);
  });

  it.each([`Bearer ${SECRET}`, `bearer  ${SECRET}`, SECRET])(
    "refuses to pass the key on as the guest's Authorization (%s)",
    (authorization) => {
      expect(
        authorizeServiceRequest(SECRET, { key: SECRET, authorization }),
      ).toBe(400);
    },
  );
});
