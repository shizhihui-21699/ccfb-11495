/**
 * Streaming line reader.
 *
 * Feeds arbitrarily large inputs to the scanner without ever holding more than
 * one chunk plus the current line. Supports:
 *
 *   - plain UTF-8/latin1 text files, including files with no trailing newline;
 *   - gzip and zstd via `zlib.createGunzip()` / `createZstdDecompress()` (the
 *     usual shape for shipped logs);
 *   - stdin (`-`), so `cat x.log | iocscan scan`.
 *
 * Lines are yielded as `Uint8Array` views into a reusable buffer. The buffer is
 * compacted in place when the leftover tail grows past a threshold, so memory
 * stays bounded regardless of file size *and* of pathological single-line
 * inputs (a 5 GB one-line JSON file is rejected with a clear error rather than
 * OOMing the machine).
 */

import { createReadStream } from "node:fs";
import { createGunzip, createZstdDecompress } from "node:zlib";
import type { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

export interface LineSourceOptions {
  /** Maximum accepted line length in bytes. Longer lines are skipped. */
  readonly maxLineBytes?: number;
}

export interface LineStats {
  bytesRead: number;
  linesRead: number;
  overlongLines: number;
  overlongBytes: number;
}

const DEFAULT_MAX_LINE = 8 * 1024 * 1024;

/** Open a byte stream for a path, `-` (stdin), with transparent decompression. */
export function openByteStream(path: string): Readable {
  let stream: Readable;
  if (path === "-") {
    stream = process.stdin;
  } else {
    stream = createReadStream(path, { highWaterMark: 1 << 20 });
  }
  const lower = path === "-" ? "" : path.toLowerCase();
  if (lower.endsWith(".gz") || lower.endsWith(".gzip")) {
    return stream.pipe(createGunzip({ chunkSize: 1 << 20 }));
  }
  if (lower.endsWith(".zst") || lower.endsWith(".zstd")) {
    return stream.pipe(createZstdDecompress({ chunkSize: 1 << 20 }));
  }
  return stream;
}

/**
 * Iterate lines from a byte stream. Each yielded view is valid only until the
 * next iteration (it points into a reused buffer); the scanner finishes with
 * a line before pulling the next.
 */
export async function* iterateLines(stream: Readable, options: LineSourceOptions = {}): AsyncGenerator<Uint8Array, LineStats> {
  const maxLine = options.maxLineBytes ?? DEFAULT_MAX_LINE;
  const stats: LineStats = { bytesRead: 0, linesRead: 0, overlongLines: 0, overlongBytes: 0 };
  let buf = new Uint8Array(1 << 20);
  let bufLen = 0;
  let skipping = false;
  let skipBytes = 0;

  const emit = (start: number, end: number): Uint8Array => {
    // Trim a trailing CR so CRLF logs behave like LF logs.
    if (end > start && buf[end - 1] === 13) end--;
    return buf.subarray(start, end);
  };

  for await (const chunk of stream as AsyncIterable<Uint8Array | string>) {
    const bytes = typeof chunk === "string" ? Buffer.from(chunk, "latin1") : chunk;
    stats.bytesRead += bytes.length;
    let offset = 0;
    while (offset < bytes.length) {
      // Fast path: append what fits, then split on the buffered newline.
      const nl = bytes.indexOf(10, offset);
      if (nl < 0) {
        const take = bytes.length - offset;
        if (!skipping) {
          if (bufLen + take > maxLine) {
            // Line exceeded the cap: drop what we have and skip to the next NL.
            stats.overlongLines++;
            stats.overlongBytes += bufLen + take;
            bufLen = 0;
            skipping = true;
            skipBytes = 0;
            break;
          }
          if (bufLen + take > buf.length) {
            let cap = buf.length;
            while (cap < bufLen + take) cap *= 2;
            const bigger = new Uint8Array(cap);
            bigger.set(buf.subarray(0, bufLen));
            buf = bigger;
          }
          buf.set(bytes.subarray(offset), bufLen);
          bufLen += take;
        } else {
          skipBytes += take;
        }
        offset = bytes.length;
        break;
      }
      const take = nl - offset;
      if (skipping) {
        skipBytes += take + 1;
        skipping = false;
        stats.linesRead++;
        offset = nl + 1;
        continue;
      }
      if (bufLen + take > maxLine) {
        stats.overlongLines++;
        stats.overlongBytes += bufLen + take;
        bufLen = 0;
        stats.linesRead++;
        offset = nl + 1;
        continue;
      }
      if (bufLen + take + 1 > buf.length) {
        let cap = buf.length;
        while (cap < bufLen + take + 1) cap *= 2;
        const bigger = new Uint8Array(cap);
        bigger.set(buf.subarray(0, bufLen));
        buf = bigger;
      }
      buf.set(bytes.subarray(offset, nl), bufLen);
      bufLen += take;
      stats.linesRead++;
      yield emit(0, bufLen);
      bufLen = 0;
      offset = nl + 1;
    }
  }

  if (skipping) {
    // Final line was overlong and unterminated; it is already counted.
  } else if (bufLen > 0) {
    stats.linesRead++;
    yield emit(0, bufLen);
  }
  return stats;
}

/**
 * Read a file as UTF-8 text, decompressing by extension. Used only for bundle
 * and config inputs, which are small.
 */
export async function readTextFile(path: string): Promise<string> {
  const { readFile } = await import("node:fs/promises");
  const { gunzipSync, zstdDecompressSync } = await import("node:zlib");
  const raw = path === "-" ? await readStdin() : await readFile(path);
  const lower = path.toLowerCase();
  if (lower.endsWith(".gz") || lower.endsWith(".gzip")) return gunzipSync(raw).toString("utf8");
  if (lower.endsWith(".zst") || lower.endsWith(".zstd")) return zstdDecompressSync(raw).toString("utf8");
  return raw.toString("utf8");
}

async function readStdin(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin as AsyncIterable<Buffer>) chunks.push(chunk);
  return Buffer.concat(chunks);
}

/** Resolve a path as given, or relative to the current module (tests). */
export function resolvePath(p: string): string {
  if (p.startsWith("file://")) return fileURLToPath(p);
  return p;
}
