import { describe, expect, it } from "vitest";
import type { IncomingMessage } from "node:http";
import { routeRigService } from "./tunnel-rig-route.js";

const servicePath = (rig: string, service: string) =>
  `/v0beta1/rigs/${rig}/services/${service}`;

/** A request as Node presents one, with both views of its headers. */
function incoming(
  url: string,
  lines: Array<[string, string]>,
): IncomingMessage {
  const headers: Record<string, string> = {};
  for (const [name, value] of lines) headers[name.toLowerCase()] = value;
  return {
    url,
    headers,
    rawHeaders: lines.flat(),
  } as unknown as IncomingMessage;
}

describe("routeRigService", () => {
  it("points a named request at the service route, path and query kept", () => {
    const request = incoming("/a/b?q=1", [
      ["Host", "web--hacks.r.acme.o.amika.run"],
      ["X-Amika-Rig", "hacks"],
      ["x-amika-service", "web"],
    ]);

    expect(routeRigService(request, servicePath)).toEqual({
      kind: "service",
      rig: "hacks",
      service: "web",
    });
    expect(request.url).toBe("/v0beta1/rigs/hacks/services/web/a/b?q=1");
  });

  it("removes both headers from both views of the request", () => {
    const request = incoming("/", [
      ["Host", "web--hacks.r.acme.o.amika.run"],
      ["X-Amika-Rig", "hacks"],
      ["x-amika-service", "web"],
      ["Accept", "text/html"],
    ]);

    routeRigService(request, servicePath);

    expect(request.headers).toEqual({
      host: "web--hacks.r.acme.o.amika.run",
      accept: "text/html",
    });
    expect(request.rawHeaders).toEqual([
      "Host",
      "web--hacks.r.acme.o.amika.run",
      "Accept",
      "text/html",
    ]);
  });

  it("leaves a request that names no rig alone", () => {
    const request = incoming("/v0beta1/rigs", [["Host", "container"]]);

    expect(routeRigService(request, servicePath)).toEqual({ kind: "api" });
    expect(request.url).toBe("/v0beta1/rigs");
  });

  it.each([
    ["only a rig", "/", [["x-amika-rig", "hacks"]]],
    ["only a service", "/", [["x-amika-service", "web"]]],
    [
      "a rig with a slash",
      "/",
      [
        ["x-amika-rig", "a/b"],
        ["x-amika-service", "web"],
      ],
    ],
    [
      "a service with a dot",
      "/",
      [
        ["x-amika-rig", "a"],
        ["x-amika-service", ".."],
      ],
    ],
    [
      "an empty rig",
      "/",
      [
        ["x-amika-rig", ""],
        ["x-amika-service", "web"],
      ],
    ],
    [
      "an absolute target",
      "http://evil.example/",
      [
        ["x-amika-rig", "a"],
        ["x-amika-service", "web"],
      ],
    ],
    [
      "a protocol-relative target",
      "//evil.example/",
      [
        ["x-amika-rig", "a"],
        ["x-amika-service", "web"],
      ],
    ],
  ] as Array<[string, string, Array<[string, string]>]>)(
    "refuses %s, and leaves the target alone",
    (_case, url, lines) => {
      const request = incoming(url, lines);

      expect(routeRigService(request, servicePath)).toMatchObject({
        kind: "refuse",
      });
      expect(request.url).toBe(url);
    },
  );

  it("refuses a named rig when there is nowhere to serve one", () => {
    const request = incoming("/", [
      ["x-amika-rig", "hacks"],
      ["x-amika-service", "web"],
    ]);

    expect(routeRigService(request, undefined)).toMatchObject({
      kind: "refuse",
    });
  });
});
