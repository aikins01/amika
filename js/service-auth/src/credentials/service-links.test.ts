/** Cover signing and verifying service links, including every refusal. */
import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_SERVICE_TOKEN_TTL_S,
  MAX_SERVICE_TOKEN_TTL_S,
  serviceLinkPath,
  signServiceLink,
  signServiceToken,
  verifyServiceLink,
  verifyServiceToken,
} from "./service-links";

const SECRET = "0123456789abcdef0123456789abcdef";
const NOW = 1_791_417_600;
const CLAIM = { rig: "demo", service: "frontend", expiresAt: NOW + 86_400 };

const verify = (
  token: string,
  { rig = CLAIM.rig, service = CLAIM.service, now = NOW, secret = SECRET } = {},
) => verifyServiceLink(secret, { rig, service, token }, now);

describe("service links", () => {
  it("signs the documented text under the derived link key", async () => {
    // Independent of the module: hostd and the provider must agree on this.
    const linkKey = createHmac("sha256", SECRET)
      .update("amika-hostd service links v1")
      .digest();
    const signature = createHmac("sha256", linkKey)
      .update(`v1\ndemo\nfrontend\n${CLAIM.expiresAt}`)
      .digest("base64url");
    expect(await signServiceLink(SECRET, CLAIM)).toBe(
      `${CLAIM.expiresAt}.${signature}`,
    );
  });

  it("verifies its own token until the expiry", async () => {
    const token = await signServiceLink(SECRET, CLAIM);
    expect(await verify(token)).toBeNull();
    expect(await verify(token, { now: CLAIM.expiresAt - 1 })).toBeNull();
    expect(await verify(token, { now: CLAIM.expiresAt })).toBe("expired");
  });

  it("covers free-text service names", async () => {
    const service = "Coding Agent/v2\nx";
    const token = await signServiceLink(SECRET, { ...CLAIM, service });
    expect(await verify(token, { service })).toBeNull();
    expect(await verify(token, { service: "Coding Agent/v2" })).toBe("invalid");
  });

  it.each([
    ["another rig", { rig: "other" }],
    ["another service", { service: "backend" }],
    ["another host's secret key", { secret: `${SECRET}x` }],
  ])("refuses a token for %s", async (_label, options) => {
    const token = await signServiceLink(SECRET, CLAIM);
    expect(await verify(token, options)).toBe("invalid");
  });

  it("refuses a token whose expiry was moved", async () => {
    const [, signature] = (await signServiceLink(SECRET, CLAIM)).split(".");
    expect(await verify(`${CLAIM.expiresAt + 1}.${signature}`)).toBe("invalid");
  });

  it("refuses an expired token even when it is otherwise valid", async () => {
    const token = await signServiceLink(SECRET, {
      ...CLAIM,
      expiresAt: NOW - 1,
    });
    expect(await verify(token)).toBe("expired");
  });

  it("accepts only the canonical spelling of a signature", async () => {
    const token = await signServiceLink(SECRET, CLAIM);
    const last = token.at(-1)!;
    // The final character carries two unused bits; flipping one of them
    // decodes to the same digest.
    const alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const variant = alphabet[alphabet.indexOf(last) ^ 1];
    expect(await verify(`${token.slice(0, -1)}${variant}`)).toBe("malformed");
  });

  it.each([
    "",
    "abc",
    "1791504000",
    "1791504000.",
    ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "01791504000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "-1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "1791504000.AAAA",
    "1791504000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
    "1791504000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.x",
  ])("treats %j as malformed", async (token) => {
    expect(await verify(token)).toBe("malformed");
  });

  it.each([0, -1, 1.5, 1_791_504_000_000, Number.MAX_SAFE_INTEGER + 1])(
    "refuses to sign an expiry of %d",
    async (expiresAt) => {
      await expect(
        signServiceLink(SECRET, { ...CLAIM, expiresAt }),
      ).rejects.toThrow("positive Unix time");
    },
  );

  it("builds the link path with the service name as one segment", () => {
    expect(
      serviceLinkPath("/v0beta1/rigs", "demo", "Coding Agent/v2", "1.sig"),
    ).toBe("/v0beta1/rigs/demo/service-links/Coding%20Agent%2Fv2/1.sig/");
  });
});

describe("service tokens", () => {
  const TARGET = { rig: "demo", service: "frontend" };
  const verifyToken = (
    token: string,
    { rig = TARGET.rig, service = TARGET.service, now = NOW } = {},
  ) => verifyServiceToken(SECRET, { rig, service, token }, now);

  it("signs the documented text under its own derived key", async () => {
    // Independent of the module: hostd and the provider must agree on this.
    const tokenKey = createHmac("sha256", SECRET)
      .update("amika-hostd service tokens v1")
      .digest();
    const expiresAt = NOW + DEFAULT_SERVICE_TOKEN_TTL_S;
    const signature = createHmac("sha256", tokenKey)
      .update(`v1\ndemo\nfrontend\n${expiresAt}`)
      .digest("base64url");
    expect(await signServiceToken(SECRET, TARGET, { nowS: NOW })).toBe(
      `${expiresAt}.${signature}`,
    );
  });

  it("verifies its own token until the expiry", async () => {
    const token = await signServiceToken(SECRET, TARGET, {
      nowS: NOW,
      ttlS: 600,
    });
    expect(await verifyToken(token)).toBeNull();
    expect(await verifyToken(token, { now: NOW + 599 })).toBeNull();
    expect(await verifyToken(token, { now: NOW + 600 })).toBe("expired");
  });

  it.each([
    ["another rig", { rig: "other" }],
    ["another service", { service: "backend" }],
  ])("refuses a token for %s", async (_label, options) => {
    const token = await signServiceToken(SECRET, TARGET, { nowS: NOW });
    expect(await verifyToken(token, options)).toBe("invalid");
  });

  // The two keys differ, so neither credential stands in for the other.
  it("refuses a link's token as a service token, and the reverse", async () => {
    const claim = { ...TARGET, expiresAt: NOW + 600 };
    const linkToken = await signServiceLink(SECRET, claim);
    expect(await verifyToken(linkToken)).toBe("invalid");

    const serviceToken = await signServiceToken(SECRET, TARGET, {
      nowS: NOW,
      ttlS: 600,
    });
    expect(await verify(serviceToken)).toBe("invalid");
  });

  it("refuses a token that claims to outlive the maximum", async () => {
    // As only an issuer that ignores the cap could mint one.
    const token = await signServiceToken(SECRET, TARGET, {
      nowS: NOW + 3600,
      ttlS: MAX_SERVICE_TOKEN_TTL_S,
    });
    expect(await verifyToken(token)).toBe("invalid");
    // Within the allowed clock skew, it is accepted.
    expect(await verifyToken(token, { now: NOW + 3600 - 60 })).toBeNull();
  });

  it.each([0, -1, 1.5, MAX_SERVICE_TOKEN_TTL_S + 1])(
    "refuses to sign a lifetime of %d seconds",
    async (ttlS) => {
      await expect(
        signServiceToken(SECRET, TARGET, { nowS: NOW, ttlS }),
      ).rejects.toThrow("lifetime");
    },
  );
});
