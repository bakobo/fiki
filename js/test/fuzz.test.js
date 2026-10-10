// A deterministic, seeded mutation fuzzer over the RFC 8941 parser and verifyRequest (tick 7xbw).
//
// Seeds are every raw value in the httpwg corpus and the Signature-Input and Signature of every
// case in vectors/accepts.json and vectors/refusals.json. Each mutant is made by flipping,
// inserting or deleting UTF-16 code units, truncating, or splicing in a piece of another seed,
// from an alphabet that includes non-ASCII, the C1 controls, U+2028 and U+2029, and lone
// surrogates, which a JavaScript string can hold and no JSON vector can carry.
//
// From the parser the only allowed outcomes are a value or SfvSyntaxError; from verifyRequest,
// which is handed nothing but wire input, a verdict or a FikiError, never a caller error. Anything
// else fails with the iteration, the seed and the input, so a failure reproduces exactly. No
// dependency: JavaScript CI bans devDependencies (review T7), so this is a hand-written xorshift.

import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { describe, it } from 'node:test';

import { DEFAULT_MINIMUM, FikiError, verifyRequest } from '../src/index.js';
import { SfvSyntaxError, parseDictionary, parseItem, parseList } from '../src/sfv.js';

const SEED = 0x7cb5_2025;
const ITERATIONS = 20_000;

const VECTORS = new URL('../../vectors/', import.meta.url);
const CORPUS = new URL('third_party/structured-field-tests/', VECTORS);
const load = (url) => JSON.parse(readFileSync(url, 'utf8'));

/** xorshift32: deterministic, and enough to choose mutations. */
function rng(seed) {
  let state = seed >>> 0 || 1;
  const next = () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state;
  };
  return { below: (n) => next() % n, pick: (list) => list[next() % list.length] };
}

// Printable ASCII with RFC 8941's structural characters weighted in, then everything the brief
// asks for beyond it: controls, DEL, non-ASCII, C1, the line and paragraph separators, and both
// halves of a surrogate pair alone.
const ALPHABET = [
  ...Array.from({ length: 0x5f }, (_, i) => String.fromCharCode(0x20 + i)),
  ...'"():;=,?*-.\\ \t'.split(''),
  '\x00', '\r', '\n', '\x7f',
  'é', ' ', 'K', '﻿', '￿',
  ...Array.from({ length: 0x20 }, (_, i) => String.fromCharCode(0x80 + i)),
  ' ', ' ',
  '\ud800', '\udbff', '\udc00', '\udfff',
];

// Well-formed RFC 8941 pieces, spliced whole, so a mutant often stays parseable and reaches the
// checks behind the parser rather than dying at the first stray character.
const FRAGMENTS = [';a=tok', ';a=1.5', ';a=-0', ';req', ';req=?0', ';a=?1', ';a=:AAAA:', ';a="s"', '"@method"', '"@path";req',
  '"content-digest"', ' "x-a"', 'tok', '1.5', '?1', ':AAAA:', '()', '("a")', ';created=1', ';expires=1', ';keyid="k"',
  ';alg="ed25519"', ';nonce=tok', ', b=1', ', sig2=("@method")', '=', ',', ';', '(', ')'];

const seeds = [];
for (const name of readdirSync(CORPUS).filter((file) => file.endsWith('.json'))) {
  for (const c of load(new URL(name, CORPUS))) if (c.raw) seeds.push(c.raw.join(', '));
}
const contexts = [];
for (const name of ['accepts.json', 'refusals.json']) {
  for (const c of load(new URL(name, VECTORS)).cases) {
    for (const [name, value] of Object.entries(c.headers)) {
      if (['signature-input', 'signature'].includes(name.toLowerCase())) seeds.push(value);
    }
    contexts.push(c);
  }
}

function mutate(text, random) {
  let out = text;
  const rounds = 1 + random.below(4);
  for (let round = 0; round < rounds; round += 1) {
    const at = random.below(out.length + 1);
    switch (random.below(6)) {
      case 0: // flip one code unit
        out = out.slice(0, at) + random.pick(ALPHABET) + out.slice(at + 1);
        break;
      case 1: // insert a run
        out = out.slice(0, at) + Array.from({ length: 1 + random.below(3) }, () => random.pick(ALPHABET)).join('') + out.slice(at);
        break;
      case 2: // delete a run
        out = out.slice(0, at) + out.slice(at + 1 + random.below(4));
        break;
      case 3: // truncate
        out = out.slice(0, at);
        break;
      case 4: // splice in a well-formed piece
        out = out.slice(0, at) + random.pick(FRAGMENTS) + out.slice(at);
        break;
      default: {
        // splice in a piece of another seed
        const other = random.pick(seeds);
        const from = random.below(other.length + 1);
        out = out.slice(0, at) + other.slice(from, from + 1 + random.below(24)) + out.slice(at);
      }
    }
  }
  return out;
}

/** verifyRequest's arguments for a vector case, every decision stated explicitly. */
const argsOf = (c, headers) => ({
  method: c.method,
  url: c.url,
  headers,
  body: c.body === null ? null : new TextEncoder().encode(c.body),
  maxAge: c.max_age,
  now: c.now,
  authorities: c.authorities,
  expectedAid: c.expected_aid,
  minimum: c.minimum === 'default' ? DEFAULT_MINIMUM : c.minimum,
  expectedKeyid: null,
  resolve: null,
  skew: 5,
});

const show = (iteration, input) => `iteration ${iteration} of seed 0x${SEED.toString(16)}, input ${JSON.stringify(input)}`;

describe('the seeded mutation fuzzer', () => {
  it(`feeds ${ITERATIONS} mutants to the parser and to verifyRequest`, async () => {
    const random = rng(SEED);
    const tally = { parsed: 0, refusedByParser: 0, verdicts: 0, refusedByVerifier: 0 };
    for (let iteration = 0; iteration < ITERATIONS; iteration += 1) {
      // Half the mutants start from the very header they replace, so they keep its shape and reach
      // the verifier's checks past the parser; the rest start from any seed.
      const context = random.pick(contexts);
      const header = random.pick(['Signature-Input', 'Signature']);
      const name = Object.keys(context.headers).find((key) => key.toLowerCase() === header.toLowerCase()) ?? header;
      const own = context.headers[name];
      const input = mutate(random.below(2) === 0 && own !== undefined ? own : random.pick(seeds), random);

      for (const parser of [parseDictionary, parseList, parseItem]) {
        try {
          parser(input);
          tally.parsed += 1;
        } catch (err) {
          if (!(err instanceof SfvSyntaxError)) assert.fail(`${parser.name} threw ${err?.stack ?? err} at ${show(iteration, input)}`);
          tally.refusedByParser += 1;
        }
      }

      try {
        // Replaced under whatever case the vector spells the name in, so the mutant is the one value.
        await verifyRequest(argsOf(context, { ...context.headers, [name]: input }));
        tally.verdicts += 1;
      } catch (err) {
        if (!(err instanceof FikiError)) assert.fail(`verifyRequest threw ${err?.stack ?? err} with ${header} at ${show(iteration, input)}`);
        tally.refusedByVerifier += 1;
      }
    }
    assert.equal(tally.parsed + tally.refusedByParser, 3 * ITERATIONS);
    assert.equal(tally.verdicts + tally.refusedByVerifier, ITERATIONS);
    // Both outcomes occur, so the mutants are neither all garbage nor all untouched.
    assert.ok(tally.parsed > 0 && tally.refusedByParser > 0, JSON.stringify(tally));
    assert.ok(tally.verdicts > 0 && tally.refusedByVerifier > 0, JSON.stringify(tally));
  });
});
