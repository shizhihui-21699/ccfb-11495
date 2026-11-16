#!/usr/bin/env node
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Worker } from 'node:worker_threads';
import { once } from 'node:events';
import { buildEngineFromFile } from './engineBuilder';
import { generateIntel } from './gen/intel';
import { generateLogs } from './gen/logs';
import { Hit } from './types';

const USAGE = `ioc-engine — STIX 2.1 IOC matching engine for large logs

Usage:
  ioc-engine scan --intel <bundle.json> --log <file> [--log <file2> ...]
                  [--out hits.ndjson] [--workers N]
  ioc-engine gen-intel --out <bundle.json> [--count 30000] [--seed 42]
  ioc-engine gen-logs --intel <bundle.json> --out <log> [--size-mb 256]
                      [--hit-rate 0.002] [--seed 7]

Hits are written as NDJSON: {indicatorId, indicatorName, confidence,
matched, file, offset, snippet}. Skipped indicators (revoked / expired /
unsupported pattern syntax) go to <out>.skipped.json.
`;

interface Args {
  cmd: string;
  intel?: string;
  logs: string[];
  out?: string;
  workers: number;
  count: number;
  seed: number;
  sizeMb: number;
  hitRate: number;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    cmd: argv[0] ?? '',
    logs: [],
    workers: Math.max(1, os.cpus().length - 1),
    count: 30000,
    seed: 42,
    sizeMb: 256,
    hitRate: 0.002,
  };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    const val = () => {
      if (i + 1 >= argv.length) throw new Error(`missing value for ${a}`);
      return argv[++i];
    };
    switch (a) {
      case '--intel': args.intel = val(); break;
      case '--log': args.logs.push(val()); break;
      case '--out': args.out = val(); break;
      case '--workers': args.workers = Math.max(1, parseInt(val(), 10)); break;
      case '--count': args.count = parseInt(val(), 10); break;
      case '--seed': args.seed = parseInt(val(), 10); break;
      case '--size-mb': args.sizeMb = parseFloat(val()); break;
      case '--hit-rate': args.hitRate = parseFloat(val()); break;
      case '-h': case '--help': args.cmd = 'help'; break;
      default: throw new Error(`unknown argument: ${a}`);
    }
  }
  return args;
}

function fmtBytes(n: number): string {
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(2) + ' GiB';
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(2) + ' MiB';
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + ' KiB';
  return n + ' B';
}

async function scanFile(
  intelPath: string,
  logFile: string,
  workers: number,
  write: (s: string) => Promise<void>,
): Promise<{ lines: number; bytes: number; hits: number; ms: number }> {
  const size = fs.statSync(logFile).size;
  const nWorkers = Math.max(1, Math.min(workers, Math.ceil(size / (4 << 20)) || 1));
  const chunk = Math.ceil(size / nWorkers);
  const t0 = Date.now();

  let total = { lines: 0, bytes: 0, hits: 0 };
  const jobs: Promise<void>[] = [];
  for (let w = 0; w < nWorkers; w++) {
    const start = w * chunk;
    const end = Math.min(size, start + chunk);
    if (start >= end) continue;
    jobs.push(new Promise<void>((resolve, reject) => {
      const worker = new Worker(path.join(__dirname, 'worker.js'), {
        workerData: { intelPath, logFile, start, end },
      });
      let pending = Promise.resolve();
      worker.on('message', (msg) => {
        if (msg.type === 'hits') {
          const lines = (msg.hits as Hit[]).map((h) => JSON.stringify(h) + '\n');
          pending = pending.then(() => write(lines.join('')));
        } else if (msg.type === 'done') {
          total.lines += msg.lines;
          total.bytes += msg.bytes;
          total.hits += msg.hits;
        } else if (msg.type === 'error') {
          reject(new Error(`worker failed on ${logFile}: ${msg.message}`));
        }
      });
      worker.on('error', reject);
      worker.on('exit', (code) => {
        if (code !== 0) reject(new Error(`worker exited with code ${code}`));
        else pending.then(() => resolve(), reject);
      });
    }));
  }
  await Promise.all(jobs);
  return { ...total, ms: Date.now() - t0 };
}

async function cmdScan(args: Args): Promise<void> {
  if (!args.intel) throw new Error('scan requires --intel <bundle.json>');
  if (args.logs.length === 0) throw new Error('scan requires at least one --log <file>');
  const outPath = args.out ?? 'hits.ndjson';

  // Build once in the main process for the intel summary report.
  const tBuild = Date.now();
  const { engine, skipped, nonIndicators } = buildEngineFromFile(args.intel);
  const stats = engine.stats;
  console.log(
    `[intel] indicators compiled: ${stats.indicators}, atoms: ${stats.atoms} ` +
    `(AC nodes: ${stats.acNodes}, trie4: ${stats.trie4Nodes}, trie6: ${stats.trie6Nodes})`,
  );
  console.log(
    `[intel] skipped: ${skipped.length} (revoked/expired/unsupported — see ${outPath}.skipped.json), ` +
    `non-indicator objects ignored: ${nonIndicators}, built in ${Date.now() - tBuild} ms`,
  );
  fs.writeFileSync(outPath + '.skipped.json', JSON.stringify(skipped, null, 2));

  const out = fs.createWriteStream(outPath);
  const write = async (s: string) => {
    if (!out.write(s)) await once(out, 'drain');
  };

  let grand = { lines: 0, bytes: 0, hits: 0, ms: 0 };
  for (const logFile of args.logs) {
    const r = await scanFile(args.intel!, logFile, args.workers, write);
    grand.lines += r.lines; grand.bytes += r.bytes; grand.hits += r.hits; grand.ms += r.ms;
    const mbps = r.ms > 0 ? (r.bytes / (1 << 20) / (r.ms / 1000)).toFixed(1) : '?';
    console.log(
      `[scan] ${logFile}: ${r.lines.toLocaleString()} lines, ${fmtBytes(r.bytes)}, ` +
      `${r.hits} hits, ${r.ms} ms (${mbps} MiB/s)`,
    );
  }
  await new Promise<void>((res) => out.end(res));
  console.log(
    `[done] ${grand.hits} hits in ${grand.lines.toLocaleString()} lines ` +
    `(${fmtBytes(grand.bytes)}) → ${outPath}`,
  );
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  switch (args.cmd) {
    case 'scan':
      await cmdScan(args);
      break;
    case 'gen-intel': {
      if (!args.out) throw new Error('gen-intel requires --out <bundle.json>');
      const bundle = generateIntel(args.count, args.seed);
      fs.writeFileSync(args.out, JSON.stringify(bundle));
      console.log(`[gen-intel] wrote ${(bundle.objects ?? []).length} objects → ${args.out}`);
      break;
    }
    case 'gen-logs': {
      if (!args.intel) throw new Error('gen-logs requires --intel <bundle.json>');
      if (!args.out) throw new Error('gen-logs requires --out <logfile>');
      const r = await generateLogs({
        intelPath: args.intel,
        outPath: args.out,
        targetBytes: Math.floor(args.sizeMb * (1 << 20)),
        seed: args.seed,
        hitRate: args.hitRate,
      });
      console.log(
        `[gen-logs] wrote ${r.lines.toLocaleString()} lines (${fmtBytes(r.bytes)}) → ${args.out}; ` +
        `planted ${r.plantedHits} IOC occurrences from ${r.plantedIndicators} indicators ` +
        `(manifest: ${args.out}.planted.json)`,
      );
      break;
    }
    case 'help':
    case '':
      process.stdout.write(USAGE);
      break;
    default:
      throw new Error(`unknown command '${args.cmd}'\n\n${USAGE}`);
  }
}

main().catch((e) => {
  console.error(`error: ${e.message}`);
  process.exit(1);
});
