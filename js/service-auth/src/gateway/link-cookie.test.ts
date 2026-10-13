/** Cover which hosts count as loopback, where hostd sets no link cookie. */
import { describe, expect, it } from "vitest";
import { isLoopbackHost } from "./link-cookie";

/** A host as `URL.hostname` spells it, which is what hostd checks. */
const hostname = (host: string) => new URL(`https://${host}:3020/`).hostname;

describe("isLoopbackHost", () => {
  it.each([
    "localhost",
    "LOCALHOST",
    "localhost.",
    "localhost..",
    "app.localhost..",
    "app.localhost",
    "127.0.0.1",
    "127.1.2.3",
    // Spellings the URL parser turns into 127.0.0.1.
    "0x7f.1",
    "2130706433",
    "[::1]",
    "[0:0:0:0:0:0:0:1]",
    // IPv4-mapped IPv6, canonicalized to [::ffff:7f00:1].
    "[::ffff:127.0.0.1]",
    "0.0.0.0",
    "[::]",
  ])("treats %s as loopback", (host) => {
    expect(isLoopbackHost(hostname(host))).toBe(true);
  });

  it.each([
    "abc.ngrok-free.dev",
    "example.com",
    "localhost.example.com",
    "10.0.0.1",
    "128.0.0.1",
    "[::ffff:10.0.0.1]",
    "[2001:db8::1]",
  ])("treats %s as reachable from elsewhere", (host) => {
    expect(isLoopbackHost(hostname(host))).toBe(false);
  });
});
