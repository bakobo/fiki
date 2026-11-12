// What KERI profile version 1.2 asks of fiki-js beyond 1.1 (`this.i` @37rktct3, @84nt4je0).
//
// Two rules, each a library behaviour rather than vector data, mirroring fiki-py's
// test_profile_v1_2.py. Under a resolver, where the keyid is an AID, a B keyid's key is the
// prefix's and must lie in the prime-order subgroup, and an AID is any of keripy's PreDex prefix
// codes (@37rktct3). Content no header announced is refused at the body stage, after the signature
// and freshness checks, so a message with two defects gets one code whichever kind of verifier
// reads it (@84nt4je0).
//
// The mixed-order oracle here adds a torsion point in affine coordinates, not the extended ones
// fiki uses, so a wrong check and a wrong oracle cannot agree by sharing a method.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';

import { Key, errors, signRequest, signResponse, verifyRequest, verifyResponse, verifyingKey } from '../src/index.js';
import { wellFormedAid } from '../src/keys.js';

const KEY = await Key.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i));
const URL_ = 'https://keria.example.com/identifiers?type=rot';
const BODY = new TextEncoder().encode('{"hello": "world"}');
const AT = 1700000000;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const PROFILE_MINIMUM = ['@method', '@path', '@query'];

/** CESR's arithmetic: zero bytes in front to a multiple of three, base64url, and the code in place
 * of the characters those bytes became. */
function cesr(code, data) {
  const pad = (3 - (data.length % 3)) % 3;
  return code + Buffer.concat([Buffer.alloc(pad), Buffer.from(data)]).toString('base64url').slice(pad);
}

// --- a mixed-order key, built in affine coordinates ---

const P = 2n ** 255n - 19n;
const mod = (a) => ((a % P) + P) % P;
const power = (b, e) => {
  let r = 1n;
  for (b = mod(b); e > 0n; e >>= 1n, b = mod(b * b)) if (e & 1n) r = mod(r * b);
  return r;
};
const inv = (a) => power(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = power(2n, (P - 1n) / 4n);

function decode(bytes) {
  let y = 0n;
  for (let i = 31; i >= 0; i -= 1) y = (y << 8n) | BigInt(bytes[i]);
  const sign = y >> 255n;
  y &= (1n << 255n) - 1n;
  const x2 = mod((y * y - 1n) * inv(D * y * y + 1n));
  let x = power(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  assert.equal(mod(x * x - x2), 0n);
  if ((x & 1n) !== sign) x = mod(-x);
  return [x, y];
}

function encode([x, y]) {
  const value = y | ((x & 1n) << 255n);
  return Uint8Array.from({ length: 32 }, (_, i) => Number((value >> BigInt(8 * i)) & 0xffn));
}

const add = ([x1, y1], [x2, y2]) => {
  const t = mod(D * x1 * x2 * y1 * y2);
  return [mod((x1 * y2 + x2 * y1) * inv(1n + t)), mod((y1 * y2 + x1 * x2) * inv(1n - t))];
};

function times(point, n) {
  let acc = [0n, 1n];
  for (let step = point; n > 0n; n >>= 1n, step = add(step, step)) if (n & 1n) acc = add(acc, step);
  return acc;
}

// The order-8 point libsodium lists first.
const ORDER_EIGHT = decode(Buffer.from('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', 'hex'));
const MIXED = encode(add(decode(verifyingKey(KEY.aid)), ORDER_EIGHT));
const B_MIXED = cesr('B', MIXED);
const B_WEAK = cesr('B', Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 1 : 0)));
const E_AID = cesr('E', createHash('sha256').update('a transferable AID').digest());

async function sign(keyid, overrides = {}) {
  const args = { key: KEY, method: 'POST', url: URL_, headers: {}, body: BODY, created: AT, keyid, ...overrides };
  const headers = { ...args.headers, ...(await signRequest(args)) };
  return { request: { method: args.method, url: args.url, body: args.body }, headers };
}

const verify = ({ request, headers }, overrides = {}) =>
  verifyRequest({ ...request, headers, maxAge: 300, authorities: null, now: AT, ...overrides });

const never = (keyid) => {
  throw new Error(`the resolver was asked about ${keyid}`);
};

describe('the mixed-order oracle', () => {
  it('is on the curve, not of small order, and outside the prime-order subgroup', () => {
    const point = decode(MIXED);
    assert.notDeepEqual(times(point, 8n), [0n, 1n]);
    assert.notDeepEqual(times(point, L), [0n, 1n]);
    assert.deepEqual(times(times(point, L), 8n), [0n, 1n]);
  });
});

describe("a B keyid under a resolver is the prefix's key, never the resolver's (@37rktct3)", () => {
  it('verifies from its prefix without asking the resolver', async () => {
    const verdict = await verify(await sign(KEY.aid), { resolve: never });
    assert.equal(verdict.keyid, KEY.aid);
    assert.equal(verdict.aid, KEY.aid);
  });

  it('refuses a mixed-order B keyid as malformed', async () => {
    await assert.rejects(
      async () => verify(await sign(B_MIXED), { resolve: never }),
      (e) => e instanceof errors.MalformedKey && e.keyid === B_MIXED,
    );
  });

  it('refuses a mixed-order expected AID as malformed, since it names its key by an AID too', async () => {
    await assert.rejects(
      async () => verify(await sign(B_MIXED), { expectedAid: B_MIXED }),
      (e) => e instanceof errors.MalformedKey && e.keyid === B_MIXED,
    );
  });

  for (const [id, keyid] of [['small-order', B_WEAK], ['mixed-order', B_MIXED]]) {
    it(`refuses a ${id} B keyid as malformed before the expected keyid is compared`, async () => {
      await assert.rejects(async () => verify(await sign(keyid), { resolve: never, expectedKeyid: E_AID }), errors.MalformedKey);
    });
  }

  it('refuses a mixed-order key a resolver returns as malformed', async () => {
    const resolve = (keyid) => (keyid === E_AID ? MIXED : null);
    await assert.rejects(
      async () => verify(await sign(E_AID), { resolve }),
      (e) => e instanceof errors.MalformedKey && e.keyid === E_AID,
    );
  });

  it('keeps a mixed-order raw keyid as fiki\'s own lens, refused only by its signature', async () => {
    // vectors_format 4 pins acceptance of a mixed-order raw keyid (@5r75ff4m); only an AID's key
    // must lie in the subgroup, so this one reaches the signature check.
    const keyid = Buffer.from(MIXED).toString('base64url');
    await assert.rejects(async () => verify(await sign(keyid)), errors.SignatureMismatch);
  });
});

describe("an AID is any of keripy's PreDex codes (@37rktct3)", () => {
  const PREDEX = {
    B: 32, D: 32, E: 32, F: 32, G: 32, H: 32, I: 32,
    '0D': 64, '0E': 64, '0F': 64, '0G': 64,
    '1AAA': 33, '1AAB': 33, '1AAI': 33, '1AAJ': 33,
    '1AAC': 57, '1AAD': 57, '1AAE': 114,
  };
  for (const [code, size] of Object.entries(PREDEX)) {
    it(`spells a well-formed AID with ${code}`, () => {
      const digest = createHash('sha512').update(code).digest();
      const keyid = cesr(code, Buffer.concat([digest, digest]).subarray(0, size));
      assert.ok(wellFormedAid(keyid), keyid);
      assert.ok(!wellFormedAid(keyid.slice(0, -1)));
      assert.ok(!wellFormedAid(keyid + 'A'));
    });
  }

  for (const [id, keyid] of [
    ['code A', 'A' + 'A'.repeat(43)],
    ['code J', 'J' + 'A'.repeat(43)],
    ['code 0A', '0A' + 'A'.repeat(86)],
    ['code 1AAF', '1AAF' + 'A'.repeat(44)],
    ['1AAD short', '1AAD' + 'A'.repeat(75)],
    ['0D, first pad bit', '0D' + 'g' + 'A'.repeat(85)],
    ['0D, second pad bit', '0D' + 'Q' + 'A'.repeat(85)],
    ['1AAB outside the alphabet', '1AAB' + '!'.repeat(44)],
    ['empty', ''],
  ]) {
    it(`refuses ${id} as an AID`, () => assert.ok(!wellFormedAid(keyid)));
  }

  it('refuses an Ed448 transferable keyid with no key state as an unknown key', async () => {
    const keyid = cesr('1AAD', Uint8Array.from({ length: 57 }, (_, i) => i));
    await assert.rejects(async () => verify(await sign(keyid), { resolve: () => null }), errors.UnknownKey);
  });

  for (const [code, size] of [['1AAA', 33], ['1AAC', 57], ['1AAI', 33]]) {
    it(`refuses a non-transferable ${code} keyid as an unsupported algorithm, without a lookup`, async () => {
      const keyid = cesr(code, Uint8Array.from({ length: size }, (_, i) => (i === 0 ? 2 : i - 1)));
      await assert.rejects(async () => verify(await sign(keyid), { resolve: never }), errors.UnsupportedAlgorithm);
    });
  }

  it('refuses a non-transferable keyid other than the expected one as unknown first', async () => {
    const keyid = cesr('1AAA', Uint8Array.from({ length: 33 }, (_, i) => (i === 0 ? 2 : i - 1)));
    await assert.rejects(async () => verify(await sign(keyid), { resolve: never, expectedKeyid: E_AID }), errors.UnknownKey);
  });
});

describe('content no header announced, at the body stage (@84nt4je0)', () => {
  it('refuses an unannounced, uncovered request body at the body stage', async () => {
    const signed = await sign(KEY.aid, { body: null });
    await assert.rejects(
      () => verify({ ...signed, request: { ...signed.request, body: BODY } }, { resolve: never, minimum: PROFILE_MINIMUM }),
      errors.InsufficientCoverage,
    );
  });

  it('puts the body stage after freshness', async () => {
    const signed = await sign(KEY.aid, { body: null });
    await assert.rejects(
      () => verify({ ...signed, request: { ...signed.request, body: BODY } }, { resolve: never, now: AT + 1000, minimum: PROFILE_MINIMUM }),
      errors.SignatureTooOld,
    );
  });

  it('still refuses an announced, uncovered request body at the covered list', async () => {
    const signed = await sign(KEY.aid, { body: null, headers: { 'Content-Length': '18' } });
    await assert.rejects(
      () => verify(signed, { resolve: never, now: AT + 1000, minimum: PROFILE_MINIMUM }),
      errors.InsufficientCoverage,
    );
  });

  it("judges an uncovered response body at the covered list by its content", async () => {
    // A client holds the response's content before verifying it, so the covered-list check judges
    // it there, ahead of the signature (profile section 9, step 12).
    const request = { method: 'GET', url: URL_, headers: {}, body: null };
    const headers = await signResponse({ key: KEY, status: 200, request, headers: {}, body: null, created: AT, keyid: KEY.aid });
    await assert.rejects(
      () =>
        verifyResponse({
          status: 201,
          headers,
          body: new TextEncoder().encode('{"done": true}'),
          request,
          maxAge: 300,
          now: AT,
          resolve: never,
          expectedKeyid: KEY.aid,
        }),
      errors.InsufficientCoverage,
    );
  });
});

describe('a fractional clock', () => {
  it('is rounded down to whole seconds, so half a second past the stale boundary is on it', async () => {
    const signed = await sign(KEY.aid);
    assert.equal((await verify(signed, { resolve: never, skew: 60, now: AT + 360.5 })).keyid, KEY.aid);
    await assert.rejects(
      async () => verify(signed, { resolve: never, skew: 60, now: AT + 361.5 }),
      (e) => e instanceof errors.SignatureTooOld && e.now === AT + 361,
    );
  });
});

describe('a clock that is not a finite number', () => {
  for (const clock of [NaN, Infinity, 'not-a-clock']) {
    it(`is a caller error, not a pass: ${String(clock)}`, async () => {
      const signed = await sign(KEY.aid);
      await assert.rejects(async () => verify(signed, { resolve: never, now: clock }), TypeError);
    });
  }
});
