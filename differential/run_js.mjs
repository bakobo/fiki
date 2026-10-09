// The JavaScript port's answers to differential/cases.json, as a map from case id to outcome.
//
// `node differential/run_js.mjs [cases.json] [out.json]`, importing the port from this repository.
// The outcome spelling is shared by all six runners and described in differential/README.md.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { FikiError, verifyRequest } from '../js/src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
// How much of a caller error's message an outcome carries; the same in every runner.
const PREFIX = 40;

async function outcome(c) {
  const args = {
    method: c.method,
    url: c.url,
    headers: c.headers,
    body: c.body === null ? null : new TextEncoder().encode(c.body),
    maxAge: c.max_age,
    now: c.now,
    authorities: c.authorities,
    expectedAid: c.expected_aid,
  };
  if (c.minimum !== 'default') args.minimum = c.minimum;
  try {
    const verdict = await verifyRequest(args);
    return `ok:${verdict.aid}`;
  } catch (e) {
    if (e instanceof FikiError) return e.constructor.name;
    // A mistake in the call is a TypeError and never a FikiError (@5zrf8gjk). fiki throws exactly
    // TypeError, so a subclass is somebody else's.
    if (e?.constructor === TypeError) return `caller:${e.message.slice(0, PREFIX)}`;
    return `crash:${e?.constructor?.name ?? typeof e}`;
  }
}

const casesPath = process.argv[2] ?? join(here, 'cases.json');
const outPath = process.argv[3] ?? join(here, 'out', 'js.json');
const { cases } = JSON.parse(readFileSync(casesPath, 'utf8'));
const start = performance.now();
const out = {};
for (const c of cases) out[c.id] = await outcome(c);
mkdirSync(dirname(outPath), { recursive: true });
const sorted = Object.fromEntries(Object.keys(out).sort().map((k) => [k, out[k]]));
writeFileSync(outPath, `${JSON.stringify(sorted, null, 0)}\n`);
console.log(`javascript: ${cases.length} cases in ${((performance.now() - start) / 1000).toFixed(1)}s`);
