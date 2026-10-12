// The key-spelling vectors, `vectors/keys/keys.json` (`this.i` @0mvgkwnl).
//
// `aidFrom` turns any of the public-key spellings into the canonical AID, and `Key.fromOpenssh`
// loads an unencrypted OpenSSH private key. Neither touches the wire: a fiki-signed request still
// carries the raw key in its keyid (@7xrx5evg), and a verifier still compares AIDs. The file is
// read in place from the repository root, never copied, so this port and fiki-py are held to the
// same bytes.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import { KEY_VECTORS_FORMAT, Key, aidFrom, errors, signRequest, verifyRequest } from '../src/index.js';
import { callerError } from './caller.js';

const VECTORS = JSON.parse(readFileSync(new URL('../../vectors/keys/keys.json', import.meta.url), 'utf8'));

const toBase64Url = (bytes) => Buffer.from(bytes).toString('base64url');

// How many cases of each section this driver ran, against the number pinned in COUNTS at the end
// of the file, so a section emptied or cut short fails rather than passing on what it still holds.
const ran = new Map();
const tally = (section) => ran.set(section, (ran.get(section) ?? 0) + 1);

const find = (section, kind, id) => VECTORS[section][kind].find((c) => c.id === id);

/** A MalformedKey that carries no part of `text`: not in its message, not in its keyid. */
const refusedWithoutEcho = (text, runLength, alphabet) => (err) => {
  assert.ok(err instanceof errors.MalformedKey, `expected MalformedKey, got ${err?.name}: ${err?.message}`);
  assert.equal(err.constructor, errors.MalformedKey);
  // Never echoed, because what a caller hands aidFrom by mistake can be a private key: the .key
  // file instead of the .pub, or a seed in base64url, which is 43 characters like a raw key.
  assert.equal(err.keyid, '');
  assert.equal(err.cause, undefined);
  const runs = text.match(new RegExp(`[${alphabet}]{${runLength},}`, 'g')) ?? [];
  for (const run of runs) assert.ok(!err.message.includes(run), `the message quotes ${run}`);
  assert.ok(text.length < runLength || !err.message.includes(text));
  return true;
};

const PUBLIC_RUNS = [12, 'A-Za-z0-9+/=_\\-'];
const PRIVATE_RUNS = [16, 'A-Za-z0-9+/='];

describe('the key vectors format', () => {
  it('is the one this port satisfies', () => assert.equal(VECTORS.key_vectors_format, KEY_VECTORS_FORMAT));
});

describe('aidFrom', () => {
  for (const c of VECTORS.public.accepts) {
    it(`converts ${c.id} to its AID`, () => {
      tally('public accepts');
      assert.equal(aidFrom(c.input), c.aid);
    });
  }

  for (const c of VECTORS.public.refusals) {
    it(`refuses ${c.id} without echoing it`, () => {
      tally('public refusals');
      assert.equal(c.error, 'MalformedKey');
      assert.throws(() => aidFrom(c.input), refusedWithoutEcho(c.input, ...PUBLIC_RUNS));
    });
  }

  // Not merely refused: refused by the point check, so the spelling parsed and the key reached it
  // (@37wdchu5). A parser bug that refused these earlier would pass the vector alone.
  for (const c of VECTORS.public.refusals.filter((c) => /(small-order|not-on-curve)$/.test(c.id))) {
    it(`refuses ${c.id} for its weakness, whatever its spelling`, () => {
      assert.throws(() => aidFrom(c.input), /small-order|canonical encoding of a point/);
    });
  }

  for (const id of ['aid-transferable', 'aid-digest']) {
    it(`tells a canonical ${id} to resolve it first`, () => {
      assert.throws(() => aidFrom(find('public', 'refusals', id).input), /resolve it/);
    });
  }

  // Shape before meaning: text that merely starts with D is not told it is a transferable AID.
  for (const id of ['aid-transferable-not-base64', 'aid-transferable-misspelled']) {
    it(`does not call ${id} an AID`, () => {
      assert.throws(
        () => aidFrom(find('public', 'refusals', id).input),
        (err) => err instanceof errors.MalformedKey && !err.message.includes('resolve it'),
      );
    });
  }

  it('does not echo a seed mistaken for a raw key and refused by the curve check', () => {
    // About half of all seeds, as 43 characters of base64url, are not a point, and so are refused
    // by the curve check rather than the parser. 32 bytes of 0x02 is one, as the first assertion
    // below checks by the refusal's own wording.
    const text = toBase64Url(new Uint8Array(32).fill(2));
    assert.throws(() => aidFrom(text), /not the canonical encoding of a point/);
    assert.throws(() => aidFrom(text), refusedWithoutEcho(text, ...PUBLIC_RUNS));
  });

  // The guide's "Handling errors": a mistake in the call is a TypeError, so that catching FikiError
  // for a bad registration cannot swallow a bug in the caller's code.
  // Not in the vectors, and refused before base58 sees it: a "z" with nothing after it.
  it('refuses an empty base58btc value', () => {
    for (const text of ['did:key:z', 'did:peer:0z']) assert.throws(() => aidFrom(text), refusedWithoutEcho(text, ...PUBLIC_RUNS));
  });

  for (const value of [null, undefined, 42, new TextEncoder().encode('ssh-ed25519 AAAA'), new String('B'), Object.create(null)]) {
    it(`is a caller error for ${Object.prototype.toString.call(value)}`, () => {
      assert.throws(() => aidFrom(value), callerError('is text'));
    });
  }
});

describe('Key.fromOpenssh', () => {
  const message = new TextEncoder().encode(VECTORS.signed_message);

  for (const c of VECTORS.private.accepts) {
    it(`loads ${c.id} and signs as its seed`, async () => {
      tally('private accepts');
      const key = await Key.fromOpenssh(c.input);
      assert.equal(key.aid, c.aid);
      assert.equal(toBase64Url(await key.sign(message)), c.signature);
    });
  }

  for (const c of VECTORS.private.refusals) {
    it(`refuses ${c.id} without echoing it`, async () => {
      tally('private refusals');
      assert.equal(c.error, 'MalformedKey');
      await assert.rejects(Key.fromOpenssh(c.input), refusedWithoutEcho(c.input, ...PRIVATE_RUNS));
    });
  }

  it('refuses a key whose public half is a small-order point', async () => {
    await assert.rejects(Key.fromOpenssh(find('private', 'refusals', 'public-small-order').input), /does not derive|small-order/);
  });

  it('tells the caller to keep a dedicated key rather than strip a passphrase', async () => {
    await assert.rejects(Key.fromOpenssh(find('private', 'refusals', 'encrypted').input), /dedicated/);
  });

  it('is non-extractable unless asked, like every other constructor', async () => {
    const { input } = find('private', 'accepts', 'ssh-keygen');
    const hidden = await Key.fromOpenssh(input);
    assert.throws(() => hidden.seed, errors.MalformedKey);
    const open = await Key.fromOpenssh(input, { extractable: true });
    assert.equal(open.aid, hidden.aid);
    assert.equal(open.seed.length, 32);
  });

  for (const value of [null, undefined, 42, new TextEncoder().encode('-----BEGIN'), Object.create(null)]) {
    it(`is a caller error for ${Object.prototype.toString.call(value)}`, async () => {
      await assert.rejects(Key.fromOpenssh(value), callerError('is text'));
    });
  }

  it('signs a request that verifies against its registered public line', async () => {
    const key = await Key.fromOpenssh(find('private', 'accepts', 'ssh-keygen').input);
    const registered = aidFrom(find('public', 'accepts', 'ssh-keygen-pub').input);
    const url = 'https://example.com/x';
    const headers = await signRequest({ key, method: 'GET', url });
    const verdict = await verifyRequest({
      method: 'GET', url, headers, maxAge: 60, authorities: null, expectedAid: registered,
    });
    assert.equal(verdict.aid, registered);
  });
});

// Read once from keys.json at key_vectors_format 1, never at test time, so a section that loses
// cases fails here rather than passing on what it still holds.
const COUNTS = {
  'public accepts': 18,
  'public refusals': 72,
  'private accepts': 7,
  'private refusals': 43,
};

describe('the driver ran every case', () => {
  for (const [name, count] of Object.entries(COUNTS)) {
    it(`${name} holds ${count} cases and all of them ran`, () => {
      const [section, kind] = name.split(' ');
      assert.equal(VECTORS[section][kind].length, count);
      assert.equal(ran.get(name), count);
    });
  }
});
