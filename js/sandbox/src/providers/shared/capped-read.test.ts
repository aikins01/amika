import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import { SandboxFileTooLargeError } from "../provider";
import { readCapped } from "./capped-read";

function webStream(chunks: Uint8Array[]): {
  stream: ReadableStream<Uint8Array>;
  pulled: () => number;
  cancelled: () => boolean;
} {
  let index = 0;
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index < chunks.length) controller.enqueue(chunks[index++]);
      else controller.close();
    },
    cancel() {
      cancelled = true;
    },
  });
  return { stream, pulled: () => index, cancelled: () => cancelled };
}

describe("readCapped", () => {
  it("joins every chunk when there is no cap", async () => {
    const { stream } = webStream([Uint8Array.of(1, 2), Uint8Array.of(3)]);
    await expect(readCapped(stream, "/f")).resolves.toEqual(
      Uint8Array.of(1, 2, 3),
    );
  });

  it("accepts a file exactly at the cap", async () => {
    const { stream } = webStream([Uint8Array.of(1, 2), Uint8Array.of(3)]);
    await expect(readCapped(stream, "/f", 3)).resolves.toEqual(
      Uint8Array.of(1, 2, 3),
    );
  });

  it("returns an empty buffer for an empty file", async () => {
    const { stream } = webStream([]);
    await expect(readCapped(stream, "/f", 3)).resolves.toEqual(
      new Uint8Array(),
    );
  });

  it("stops reading and cancels the stream once past the cap", async () => {
    const chunk = new Uint8Array(4);
    const { stream, pulled, cancelled } = webStream(
      Array.from({ length: 100 }, () => chunk),
    );
    const read = readCapped(stream, "/dev/zero", 6);
    await expect(read).rejects.toBeInstanceOf(SandboxFileTooLargeError);
    await expect(read).rejects.toMatchObject({
      path: "/dev/zero",
      maxBytes: 6,
    });
    expect(cancelled()).toBe(true);
    expect(pulled()).toBeLessThan(10);
  });

  it("destroys a Node stream once past the cap", async () => {
    const stream = Readable.from(
      (function* () {
        for (;;) yield Buffer.alloc(1024);
      })(),
    );
    await expect(readCapped(stream, "/f", 4096)).rejects.toBeInstanceOf(
      SandboxFileTooLargeError,
    );
    expect(stream.destroyed).toBe(true);
  });
});
