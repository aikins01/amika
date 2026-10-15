/**
 * Collect a provider's file stream into one buffer, stopping at a byte cap.
 */
import { SandboxFileTooLargeError } from "../provider";

/**
 * Buffer a web `ReadableStream` or a Node `Readable`, throwing
 * {@link SandboxFileTooLargeError} as soon as it passes `maxBytes`. Leaving
 * early cancels the web stream or destroys the Node one, so the rest of the
 * file is never downloaded. With no cap, the whole stream is read.
 */
export async function readCapped(
  source: ReadableStream<Uint8Array> | AsyncIterable<Uint8Array>,
  path: string,
  maxBytes?: number,
): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of chunksOf(source)) {
    total += chunk.byteLength;
    if (maxBytes !== undefined && total > maxBytes) {
      throw new SandboxFileTooLargeError(path, maxBytes);
    }
    parts.push(chunk);
  }
  return concatBytes(parts, total);
}

/**
 * The DOM typings do not declare `ReadableStream` async-iterable, so a web
 * stream goes through its reader. Leaving the loop early runs `finally`,
 * which cancels it; a Node `Readable` is destroyed by its own iterator.
 */
async function* chunksOf(
  source: ReadableStream<Uint8Array> | AsyncIterable<Uint8Array>,
): AsyncGenerator<Uint8Array> {
  if (!("getReader" in source)) {
    yield* source;
    return;
  }
  const reader = source.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      yield value;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
}

function concatBytes(parts: Uint8Array[], total: number): Uint8Array {
  if (parts.length === 1) return parts[0];
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}
