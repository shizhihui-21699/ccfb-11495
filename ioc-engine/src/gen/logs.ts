import * as fs from 'node:fs';
import { once } from 'node:events';
import { mulberry32, pick, randInt, randHex } from '../random';
import { buildEngineFromFile } from '../engineBuilder';
import { parseCidr, randomIpInCidr } from '../ipaddr';
import { Atom, CompiledIndicator } from '../types';

const BENIGN_DOMAINS = [
  'www.example.com', 'mail.google.com', 'cdn.jsdelivr.net', 'api.github.com',
  'fonts.gstatic.com', 'login.microsoftonline.com', 'updates.apple.com',
  'pypi.org', 'registry.npmjs.org', 'news.ycombinator.com', 'stackoverflow.com',
];
const BENIGN_PATHS = ['/index.html', '/api/users', '/static/app.js', '/health', '/login', '/img/logo.png'];
const METHODS = ['GET', 'POST', 'HEAD'];
const STATUS = [200, 200, 200, 301, 404, 500];

export interface GenLogsOptions {
  intelPath: string;
  outPath: string;
  targetBytes: number;
  seed: number;
  /** probability that a generated line carries planted IOC(s) */
  hitRate: number;
}

export interface GenLogsResult {
  lines: number;
  bytes: number;
  plantedHits: number;
  plantedIndicators: number;
}

function benignIp(rand: () => number): string {
  if (rand() < 0.5) return `10.${randInt(rand, 0, 255)}.${randInt(rand, 0, 255)}.${randInt(rand, 1, 254)}`;
  return `${randInt(rand, 11, 223)}.${randInt(rand, 0, 255)}.${randInt(rand, 0, 255)}.${randInt(rand, 1, 254)}`;
}

function benignLine(rand: () => number, ts: string): string {
  const pid = randInt(rand, 100, 30000);
  switch (randInt(rand, 0, 4)) {
    case 0:
      return `${ts} nginx[${pid}]: ${benignIp(rand)} - - "${pick(rand, METHODS)} ${pick(rand, BENIGN_PATHS)} HTTP/1.1" ${pick(rand, STATUS)} ${randInt(rand, 100, 90000)} "-" "Mozilla/5.0"`;
    case 1:
      return `${ts} dnsmasq[${pid}]: query[A] ${pick(rand, BENIGN_DOMAINS)} from ${benignIp(rand)}`;
    case 2:
      return `${ts} fw[${pid}]: DENY src=${benignIp(rand)} dst=${benignIp(rand)} spt=${randInt(rand, 1024, 65000)} dpt=${pick(rand, [22, 53, 80, 443, 8080])} proto=tcp`;
    case 3:
      return `${ts} av[${pid}]: scan result=clean path=/home/user/${randHex(rand, 8)}.bin sha256=${randHex(rand, 64)}`;
    default:
      return `${ts} proxy[${pid}]: CONNECT ${pick(rand, BENIGN_DOMAINS)}:443 ${benignIp(rand)} tunneled ${randInt(rand, 100, 99999)} bytes`;
  }
}

/** A line guaranteed to contain every atom of the indicator (satisfies AND semantics). */
function plantLine(rand: () => number, ts: string, values: string[]): string {
  const pid = randInt(rand, 100, 30000);
  const noise = randHex(rand, 6);
  return `${ts} edr[${pid}]: alert event=${noise} ${values.join(' ')} action=allowed`;
}

/**
 * Generate a synthetic log file of ~targetBytes, planting IOCs taken from the
 * *active, supported* indicators of the intel bundle (so every planted IOC
 * must produce a hit). Writes <outPath>.planted.json: {indicatorId: count}.
 */
export async function generateLogs(opts: GenLogsOptions): Promise<GenLogsResult> {
  const rand = mulberry32(opts.seed);
  const { engine } = buildEngineFromFile(opts.intelPath);

  // Plantable value lists per indicator. CIDR atoms contribute a random
  // address inside the prefix.
  const plantable: { ind: CompiledIndicator; values: string[] }[] = [];
  for (const ind of engine.indicators) {
    const values: string[] = [];
    for (const atomId of ind.atomIds) {
      const atom: Atom = engine.atoms[atomId];
      if (atom.kind === 'cidr') {
        values.push(randomIpInCidr(parseCidr(atom.value)!, rand));
      } else {
        values.push(atom.value);
      }
    }
    if (values.length > 0) plantable.push({ ind, values });
  }
  if (plantable.length === 0) throw new Error('no plantable indicators in intel bundle');

  const planted = new Map<string, number>();
  const out = fs.createWriteStream(opts.outPath);
  let bytes = 0;
  let lines = 0;
  let plantedHits = 0;
  const baseTs = Date.now() - 3600_000;

  while (bytes < opts.targetBytes) {
    const batch: string[] = [];
    for (let i = 0; i < 2000; i++) {
      const ts = new Date(baseTs + lines * 137).toISOString();
      let line: string;
      if (rand() < opts.hitRate) {
        const p = plantable[Math.floor(rand() * plantable.length)];
        line = plantLine(rand, ts, p.values);
        planted.set(p.ind.id, (planted.get(p.ind.id) ?? 0) + 1);
        plantedHits++;
      } else {
        line = benignLine(rand, ts);
      }
      batch.push(line);
      lines++;
    }
    const chunk = batch.join('\n') + '\n';
    bytes += Buffer.byteLength(chunk);
    if (!out.write(chunk)) await once(out, 'drain');
  }
  await new Promise<void>((res, rej) => out.end((e: Error | null | undefined) => (e ? rej(e) : res())));

  fs.writeFileSync(
    opts.outPath + '.planted.json',
    JSON.stringify({ plantedIndicators: planted.size, plantedHits, byIndicator: Object.fromEntries(planted) }, null, 2),
  );
  return { lines, bytes, plantedHits, plantedIndicators: planted.size };
}
