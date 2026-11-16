import * as fs from 'node:fs';

export interface ScanStats {
  lines: number;
  bytes: number;
}

/** Extra bytes read past a range end so the line straddling the boundary can be finished. */
const MAX_LINE_SLOP = 4 * 1024 * 1024;

/**
 * Stream the byte range [start, end) of `file`, invoking onLine for every
 * line whose first byte lies inside the range (a line straddling `end` is
 * finished; the next worker discards it as a partial first line, so each
 * line is processed exactly once). Memory stays bounded regardless of file
 * size: one 1 MiB read buffer plus the current line.
 */
export async function scanRange(
  file: string,
  start: number,
  end: number,
  onLine: (line: string, offset: number) => void,
): Promise<ScanStats> {
  const size = fs.statSync(file).size;
  const readEnd = Math.min(size - 1, end + MAX_LINE_SLOP); // fs end is inclusive
  if (start >= size || start >= end) return { lines: 0, bytes: 0 };

  // If the byte before our range is not a newline, our first line is a
  // fragment owned by the previous worker: discard it.
  let skipFirst = false;
  if (start > 0) {
    const fd = fs.openSync(file, 'r');
    try {
      const b = Buffer.alloc(1);
      fs.readSync(fd, b, 0, 1, start - 1);
      skipFirst = b[0] !== 0x0a;
    } finally {
      fs.closeSync(fd);
    }
  }

  const stream = fs.createReadStream(file, { start, end: readEnd, highWaterMark: 1 << 20 });
  let stats: ScanStats = { lines: 0, bytes: 0 };
  let pending: Buffer | null = null;
  let base = start; // absolute file offset of pending[0]
  let first = skipFirst;
  let done = false;

  const handle = (buf: Buffer, lineStart: number): void => {
    if (first) { first = false; return; }
    if (lineStart >= end) { done = true; return; }
    stats.lines++;
    stats.bytes += buf.length + 1;
    onLine(buf.toString('utf8'), lineStart);
  };

  for await (const chunk of stream) {
    let buf: Buffer = pending ? Buffer.concat([pending, chunk as Buffer]) : (chunk as Buffer);
    pending = null;
    let idx = 0;
    for (;;) {
      const nl = buf.indexOf(0x0a, idx);
      if (nl === -1) break;
      const hasCR = nl > idx && buf[nl - 1] === 0x0d;
      handle(buf.subarray(idx, hasCR ? nl - 1 : nl), base + idx);
      idx = nl + 1;
      if (done) break;
    }
    pending = buf.subarray(idx);
    base += idx;
    if (done) break;
  }
  if (!done && pending && pending.length > 0) {
    handle(pending[pending.length - 1] === 0x0d ? pending.subarray(0, -1) : pending, base);
  }
  return stats;
}
