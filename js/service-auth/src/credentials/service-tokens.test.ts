/** Cover signing and verifying service tokens, including every refusal. */
import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_SERVICE_TOKEN_TTL_S,
  MAX_SERVICE_TOKEN_TTL_S,
  signServiceToken,
  verifyServiceToken,
} from "./service-tokens";

const SECRET = "0123456789abcdef0123456789abcdef";
const NOW = 1_791_417_600;

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

  it("refuses a token signed under another key", async () => {
    // As a retired service link's was: one label per use, so a credential
    // minted for one never stands in for another.
    const expiresAt = NOW + 600;
    const linkKey = createHmac("sha256", SECRET)
      .update("amika-hostd service links v1")
      .digest();
    const signature = createHmac("sha256", linkKey)
      .update(`v1\ndemo\nfrontend\n${expiresAt}`)
      .digest("base64url");
    expect(await verifyToken(`${expiresAt}.${signature}`)).toBe("invalid");
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
