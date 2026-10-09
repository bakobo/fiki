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

import {
  FikiError,
  Key,
  VECTORS_FORMAT,
  signRequest,
  signResponse,
  signatureBase,
  verifyRequest,
  verifyResponse,
  verifyingKey,
} from '../src/index.js';
import { callerError } from './caller.js';

const VECTORS = new URL('../../vectors/', import.meta.url);

const load = (name) => JSON.parse(readFileSync(new URL(name, VECTORS), 'utf8'));

const fromHex = (hex) => Uint8Array.from(hex.match(/../g).map((b) => parseInt(b, 16)));
const toBase64 = (bytes) => Buffer.from(bytes).toString('base64');
const toBase64Url = (bytes) => Buffer.from(bytes).toString('base64url');

describe('the vectors format', () => {
  for (const name of [
    'aid-lens.json',
    'signature-base.json',
    'accepts.json',
    'refusals.json',
    'misuse.json',
    'signs.json',
    'responses.json',
  ]) {
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
  'note', 'error', 'aid', 'keyid', 'covered', 'omit', 'kind', 'status', 'request', 'expected_keyid',
]);
const SIGN_FIELDS = new Set([
  'id', 'kind', 'seed_hex', 'method', 'url', 'headers', 'body', 'covered', 'created', 'expires', 'nonce', 'tag',
  'minimum', 'status', 'request', 'expected_headers', 'error', 'note', 'keyid', 'label',
]);
const FIELDS = {
  'aid-lens.json': new Set(['id', 'note', 'seed_hex', 'public_key_hex', 'aid', 'keyid']),
  'signature-base.json': new Set([
    'id', 'note', 'method', 'url', 'headers', 'covered', 'created', 'keyid', 'alg', 'seed_hex', 'base', 'signature',
  ]),
  'accepts.json': VERIFY_FIELDS,
  'refusals.json': VERIFY_FIELDS,
  'misuse.json': VERIFY_FIELDS,
  'signs.json': SIGN_FIELDS,
  'responses.json': VERIFY_FIELDS,
};

/** A file's cases, each checked for fields this driver does not know. */
const cases = (name) =>
  load(name).cases.map((c) => {
    const unknown = Object.keys(c).filter((field) => !FIELDS[name].has(field));
    return { ...c, unknown };
  });

// How many cases of each file this driver ran, against the number pinned in CASES at the end of
// the file (tick 7xbw, T8): an emptied cases array passed every driver before.
const ran = new Map();
const tally = (name) => ran.set(name, (ran.get(name) ?? 0) + 1);

const known = (c) => assert.deepEqual(c.unknown, [], `unknown fields ${c.unknown.join(', ')}`);

/** The arguments of a verify case: its message, and the verifier's stated policy (format 3).
 *
 * `minimum` "default" is the port's own default, so it is left out; null is the explicit opt-out;
 * a list is that minimum. authorities is always stated, and a misuse case leaves out every field
 * named in `omit`.
 */
function verifyArgs(c) {
  known(c);
  for (const field of ['kind', 'status', 'request', 'expected_keyid']) {
    assert.ok(!(field in c), `a request case carries ${field}, which only a response case has`);
  }
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
  for (const name of [
    'accepts.json',
    'refusals.json',
    'misuse.json',
    'aid-lens.json',
    'signature-base.json',
    'signs.json',
    'responses.json',
  ]) {
    it(name, () => assert.ok(load(name).cases.length > 2));
  }
});

const bytesOf = (text) => (text === null ? null : new TextEncoder().encode(text));

/** The request a response answers, as a case spells it, or null. */
const requestOf = (r) =>
  r === null ? null : { method: r.method, url: r.url, headers: r.headers, body: bytesOf(r.body) };

/** Every refusal's message holds no control character and is at most 1024 characters, so an
 * untrusted value is quoted escaped and cut (@524c8qgv, part-two refinements). */
function wellFormed(err) {
  assert.ok(err.message.length <= 1024, `message of ${err.message.length} characters`);
  assert.ok(!/[\x00-\x1f\x7f]/.test(err.message), JSON.stringify(err.message.slice(0, 200)));
}

/** The arguments of a response case: verifyResponse's own policy (format 3). */
function responseArgs(c) {
  known(c);
  const args = {
    status: c.status,
    headers: c.headers,
    body: bytesOf(c.body),
    request: requestOf(c.request),
    maxAge: c.max_age,
    now: c.now,
    expectedKeyid: c.expected_keyid,
  };
  if (c.minimum !== 'default') args.minimum = c.minimum;
  const names = { expected_keyid: 'expectedKeyid', minimum: 'minimum' };
  for (const field of c.omit ?? []) {
    assert.ok(Object.hasOwn(names, field), `omit names ${field}, which this driver does not pass`);
    delete args[names[field]];
  }
  return args;
}

// The fragment of fiki's own message each caller-error case must carry, so that a TypeError from a
// bug inside fiki cannot pass for the refusal (tick 7xbw, T3). Keyed by case id, across misuse.json
// and signs.json, whose ids are distinct.
const CALLER = {
  'authorities-holds-a-non-string': 'Every authority is a string',
  'authorities-is-a-string': 'authorities is a collection of the hosts',
  'authorities-is-a-string-containing-the-host': 'authorities is a collection of the hosts',
  'authorities-is-empty': 'authorities is empty, which serves no host at all',
  'authorities-omitted': 'verifyRequest requires authorities',
  'minimum-below-the-profiles': "A minimum covered set must include the profile's own",
  'minimum-empty': "A minimum covered set must include the profile's own",
  'response-expected-keyid-empty': "verifyResponse's expectedKeyid is empty",
  'response-expected-keyid-omitted': 'verifyResponse requires expectedKeyid',
  'response-minimum-below-the-profiles': "A minimum covered set must include the profile's own",
  'url-over-8192-bytes': 'cannot be read: it is over 8192 bytes',
};

/** Assert a FikiError of the named class, with a well-formed message. */
const refusedAs = (name) => (err) => {
  assert.ok(err instanceof FikiError, `expected a FikiError, got ${err}`);
  assert.equal(err.constructor.name, name);
  wellFormed(err);
  return true;
};

describe('responses every implementation must verify or refuse', () => {
  for (const c of cases('responses.json')) {
    it(c.id, async () => {
      tally('responses.json');
      // verifyResponse fails closed by default (format 3): RESPONSE_MINIMUM, expectedKeyid stated.
      const args = responseArgs(c);
      if (c.error !== undefined) {
        await assert.rejects(() => verifyResponse(args), refusedAs(c.error));
        return;
      }
      const verdict = await verifyResponse(args);
      assert.equal(verdict.keyid, c.keyid);
      assert.deepEqual(verdict.covered, c.covered);
    });
  }
});

describe('what every signer emits, byte for byte', () => {
  for (const c of cases('signs.json')) {
    it(c.id, async () => {
      tally('signs.json');
      // No shared vector called a signer before format 3, and a port whose default dropped @query
      // passed everything (review V-C4).
      known(c);
      const key = await Key.fromSeed(fromHex(c.seed_hex));
      const args = {
        key,
        headers: c.headers,
        body: bytesOf(c.body),
        covered: c.covered,
        created: c.created,
        expires: c.expires,
        nonce: c.nonce,
        tag: c.tag,
        minimum: c.minimum,
        keyid: c.keyid,
        label: c.label,
      };
      const sign = () =>
        c.kind === 'request'
          ? signRequest({ method: c.method, url: c.url, ...args })
          : signResponse({ status: c.status, request: requestOf(c.request), ...args });
      if (c.error === 'caller') {
        await assert.rejects(sign, callerError(CALLER[c.id]));
      } else if (c.error !== undefined) {
        await assert.rejects(sign, refusedAs(c.error));
      } else {
        assert.deepEqual(await sign(), c.expected_headers);
      }
    });
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
      tally('aid-lens.json');
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
      tally('signature-base.json');
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
      tally('refusals.json');
      // Every entry names the class fiki raises, so this port maps its own onto the same
      // condition rather than inventing a taxonomy of its own.
      const args = verifyArgs(c);
      await assert.rejects(() => verifyRequest(args), refusedAs(c.error));
    });
  }
});

describe('requests every implementation must accept', () => {
  for (const c of cases('accepts.json')) {
    it(c.id, async () => {
      tally('accepts.json');
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
      tally('misuse.json');
      // A mistake in the call is a TypeError, never a FikiError (@5zrf8gjk).
      assert.equal(c.error, 'caller');
      const call = c.kind === 'response' ? () => verifyResponse(responseArgs(c)) : () => verifyRequest(verifyArgs(c));
      await assert.rejects(call, callerError(CALLER[c.id]));
    });
  }
});

// Read once from the files at hardening-a, never at test time, so a file that loses cases fails.
const CASES = {
  'accepts.json': 44,
  'aid-lens.json': 3,
  'misuse.json': 10,
  'refusals.json': 144,
  'responses.json': 13,
  'signature-base.json': 14,
  'signs.json': 16,
};

describe('the driver ran every case', () => {
  for (const [name, count] of Object.entries(CASES)) {
    it(`${name} holds ${count} cases and all of them ran`, () => {
      assert.equal(load(name).cases.length, count);
      assert.equal(ran.get(name), count);
    });
  }
});
