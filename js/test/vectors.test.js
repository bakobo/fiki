// The shared conformance vectors (`this.i` @5gf6r08f, @2q9gv70t).
//
// This is the port's first test and its whole reason for being checkable. The vectors live at the
// repository root rather than under js/ so that this implementation and the Python one are held to
// the same bytes — a copy under each language is the drift the polyglot layout exists to prevent.
//
// The driver is deliberately thin. Everything a port needs is in the JSON; a port that has to
// reimplement this file's logic in its own language has reimplemented the conformance suite.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

import { FikiError, Key, VECTORS_FORMAT, signatureBase, verifyRequest, verifyingKey } from '../src/index.js';

const VECTORS = new URL('../../vectors/', import.meta.url);

const load = (name) => JSON.parse(readFileSync(new URL(name, VECTORS), 'utf8'));

const fromHex = (hex) => Uint8Array.from(hex.match(/../g).map((b) => parseInt(b, 16)));
const toBase64 = (bytes) => Buffer.from(bytes).toString('base64');
const toBase64Url = (bytes) => Buffer.from(bytes).toString('base64url');

describe('the vectors format', () => {
  for (const name of ['aid-lens.json', 'signature-base.json', 'accepts.json', 'refusals.json', 'misuse.json']) {
    it(`${name} is the contract this port satisfies`, () => {
      // A port running newer vectors fails here rather than passing a subset and reporting
      // conformance it no longer has: the cases it never implemented would simply not be in the
      // file it last read.
      assert.equal(load(name).vectors_format, VECTORS_FORMAT);
    });
  }
});

// Every field a case may carry, per file. A field this driver does not know fails the case rather
// than being ignored, so a field added to the vectors cannot be silently dropped by a port that
// never learned it (review V-M8).
const VERIFY_FIELDS = new Set([
  'id', 'method', 'url', 'headers', 'body', 'max_age', 'now', 'minimum', 'authorities', 'expected_aid',
  'note', 'error', 'aid', 'keyid', 'covered', 'omit',
]);
const FIELDS = {
  'aid-lens.json': new Set(['id', 'note', 'seed_hex', 'public_key_hex', 'aid', 'keyid']),
  'signature-base.json': new Set([
    'id', 'note', 'method', 'url', 'headers', 'covered', 'created', 'keyid', 'alg', 'seed_hex', 'base', 'signature',
  ]),
  'accepts.json': VERIFY_FIELDS,
  'refusals.json': VERIFY_FIELDS,
  'misuse.json': VERIFY_FIELDS,
};

/** A file's cases, each checked for fields this driver does not know. */
const cases = (name) =>
  load(name).cases.map((c) => {
    const unknown = Object.keys(c).filter((field) => !FIELDS[name].has(field));
    return { ...c, unknown };
  });

const known = (c) => assert.deepEqual(c.unknown, [], `unknown fields ${c.unknown.join(', ')}`);

/** The arguments of a verify case: its message, and the verifier's stated policy (format 3).
 *
 * `minimum` "default" is the port's own default, so it is left out; null is the explicit opt-out;
 * a list is that minimum. authorities is always stated, and a misuse case leaves out every field
 * named in `omit`.
 */
function verifyArgs(c) {
  known(c);
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
  const names = { authorities: 'authorities', expected_aid: 'expectedAid', minimum: 'minimum' };
  for (const field of c.omit ?? []) {
    assert.ok(Object.hasOwn(names, field), `omit names ${field}, which this driver does not pass`);
    delete args[names[field]];
  }
  return args;
}

describe('the verify vectors are not empty', () => {
  for (const name of ['accepts.json', 'refusals.json', 'misuse.json', 'aid-lens.json', 'signature-base.json']) {
    it(name, () => assert.ok(load(name).cases.length > 2));
  }
});

describe('the vectors are reachable', () => {
  it('sits beside the other ports rather than under this one', () => {
    // A port that cannot find these has forked them, which is what the layout exists to prevent.
    assert.equal(fileURLToPath(VECTORS).split('/').at(-2), 'vectors');
    assert.ok(load('aid-lens.json').cases.length > 0);
  });
});

describe('the AID lens', () => {
  for (const c of cases('aid-lens.json')) {
    it(c.id, async () => {
      known(c);
      const key = await Key.fromSeed(fromHex(c.seed_hex));
      assert.equal(await key.aid, c.aid);
      assert.equal(toBase64Url(fromHex(c.public_key_hex)), c.keyid);
      assert.deepEqual(await verifyingKey(c.aid), fromHex(c.public_key_hex));
    });
  }
});

describe('signature bases and the signatures over them', () => {
  for (const c of cases('signature-base.json')) {
    it(`${c.id} — base`, () => {
      known(c);
      const base = signatureBase({
        method: c.method,
        url: c.url,
        headers: c.headers,
        covered: c.covered,
        created: c.created,
        keyid: c.keyid,
        alg: c.alg,
      });
      assert.equal(new TextDecoder().decode(base), c.base);
    });

    it(`${c.id} — signature`, async () => {
      // Ed25519 is deterministic, so a port that builds the right base produces the right bytes.
      const base = signatureBase({
        method: c.method,
        url: c.url,
        headers: c.headers,
        covered: c.covered,
        created: c.created,
        keyid: c.keyid,
        alg: c.alg,
      });
      const key = await Key.fromSeed(fromHex(c.seed_hex));
      assert.equal(toBase64(await key.sign(base)), c.signature);
    });
  }
});

describe('requests every implementation must refuse', () => {
  for (const c of cases('refusals.json')) {
    it(c.id, async () => {
      // Every entry names the class fiki raises, so this port maps its own onto the same
      // condition rather than inventing a taxonomy of its own.
      const args = verifyArgs(c);
      await assert.rejects(
        () => verifyRequest(args),
        (err) => {
          assert.ok(err instanceof FikiError, `expected a FikiError, got ${err}`);
          assert.equal(err.constructor.name, c.error);
          return true;
        },
      );
    });
  }
});

describe('requests every implementation must accept', () => {
  for (const c of cases('accepts.json')) {
    it(c.id, async () => {
      // The positive half. signature-base.json pins what a signer produces and refusals.json what
      // a verifier rejects; without these, a port could pass every vector while returning the
      // wrong AID or the wrong covered set.
      const verdict = await verifyRequest(verifyArgs(c));
      assert.equal(verdict.aid, c.aid);
      // Format 2 (@5zrf8gjk, rule B18): the keyid exactly as it arrived, beside the identity that
      // vouched for the key.
      assert.equal(verdict.keyid, c.keyid);
      assert.deepEqual(verdict.covered, c.covered);
    });
  }
});

describe('calls every implementation must refuse as a mistake in the call', () => {
  for (const c of cases('misuse.json')) {
    it(c.id, async () => {
      // A mistake in the call is a TypeError, never a FikiError (@5zrf8gjk).
      assert.equal(c.error, 'caller');
      const args = verifyArgs(c);
      await assert.rejects(
        () => verifyRequest(args),
        (err) => {
          assert.ok(err instanceof TypeError, `expected a TypeError, got ${err}`);
          assert.ok(!(err instanceof FikiError), `expected no FikiError, got ${err}`);
          return true;
        },
      );
    });
  }
});
