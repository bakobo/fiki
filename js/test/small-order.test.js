// Small-order Ed25519 public keys are refused, failing closed (tick 27eo, `this.i` @4wcwlqd6).
//
// Under the identity point (01 then 31 zero bytes), the signature 01 then 63 zero bytes verifies
// over ANY message in OpenSSL-backed Ed25519, which is what Node's WebCrypto uses. A key of small
// order binds nothing, so fiki refuses one as MalformedKey before any signature is checked, by
// every path a key reaches the verifier: an AID, a raw keyid, an expectedAid, and a resolver.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { errors, toAid, verifyRequest, verifyingKey } from '../src/index.js';
import { SMALL_ORDER } from '../src/keys.js';

const IDENTITY = new Uint8Array(32);
IDENTITY[0] = 1;
// The order-8 point libsodium lists first, with its sign bit set: a second, independent case.
const ORDER_EIGHT = Uint8Array.from(Buffer.from('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85', 'hex'));
const FORGED = new Uint8Array(64);
FORGED[0] = 1;

const URL_ = 'https://example.com/things?x=1';
const COVERED = '("@method" "@path" "@query")';

function forged(keyid) {
  const params = keyid === null ? ';created=1700000000' : `;created=1700000000;keyid="${keyid}"`;
  return {
    'Signature-Input': `sig=${COVERED}${params}`,
    Signature: `sig=:${Buffer.from(FORGED).toString('base64')}:`,
  };
}

const verify = (headers, overrides = {}) => verifyRequest({ method: 'GET', url: URL_, headers, maxAge: null, ...overrides });

// --- an independent oracle for the blocklist: each entry decodes to a point whose order divides 8 ---

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
  y = mod(y & ((1n << 255n) - 1n));
  const x2 = mod((y * y - 1n) * inv(D * y * y + 1n));
  let x = power(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  assert.equal(mod(x * x - x2), 0n, 'the encoding is not a curve point');
  if ((x & 1n) !== sign) x = mod(-x);
  return [x, y];
}

const add = ([x1, y1], [x2, y2]) => {
  const t = mod(D * x1 * x2 * y1 * y2);
  return [mod((x1 * y2 + x2 * y1) * inv(1n + t)), mod((y1 * y2 + x1 * x2) * inv(1n - t))];
};

describe('small-order Ed25519 keys (tick 27eo)', () => {
  it('lists only encodings of points whose order divides 8, sign bit either way', () => {
    assert.equal(SMALL_ORDER.length, 7);
    for (const entry of SMALL_ORDER) {
      for (const sign of [0, 0x80]) {
        const bytes = Uint8Array.from(entry);
        bytes[31] |= sign;
        let point = decode(bytes);
        for (let i = 0; i < 3; i += 1) point = add(point, point);
        assert.deepEqual(point, [0n, 1n]);
      }
    }
  });

  for (const [id, raw] of [['the identity point', IDENTITY], ['an order-8 point', ORDER_EIGHT]]) {
    it(`refuses ${id} as an AID`, () => {
      assert.throws(() => verifyingKey(toAid(raw)), errors.MalformedKey);
    });

    it(`refuses ${id} through the raw keyid, before the forged signature is checked`, async () => {
      await assert.rejects(() => verify(forged(Buffer.from(raw).toString('base64url'))), errors.MalformedKey);
    });

    it(`refuses ${id} through expectedAid`, async () => {
      await assert.rejects(() => verify(forged(null), { expectedAid: toAid(raw) }), errors.MalformedKey);
    });

    it(`refuses ${id} when a resolver returns it`, async () => {
      const keyid = 'E' + 'A'.repeat(43);
      await assert.rejects(
        () => verify(forged(keyid), { resolve: async () => raw }),
        (e) => e instanceof errors.MalformedKey && e.keyid === keyid,
      );
    });
  }

  // Not on the curve at all, or not the canonical encoding of a point (tick 27eo, extended).
  const OFF_CURVE = new Uint8Array(32);
  OFF_CURVE[0] = 2; // y = 2 has no x on edwards25519
  const BEYOND_P = Uint8Array.from(Buffer.from('f0' + 'ff'.repeat(30) + '7f', 'hex')); // y = p + 3; 3 is on the curve, not small order
  const NEGATIVE_ZERO_X = Uint8Array.from(Buffer.from('01' + '00'.repeat(30) + '80', 'hex')); // y = 1, x = 0 with the sign bit set

  it('takes its non-canonical cases from where they claim to be', () => {
    assert.throws(() => decode(OFF_CURVE), /not a curve point/);
    const beyond = Uint8Array.from(BEYOND_P);
    let y = 0n;
    for (let i = 31; i >= 0; i -= 1) y = (y << 8n) | BigInt(beyond[i]);
    assert.equal(y, P + 3n);
    let point = decode(Uint8Array.from([3, ...new Uint8Array(31)]));
    for (let i = 0; i < 3; i += 1) point = add(point, point);
    assert.notDeepEqual(point, [0n, 1n]);
  });

  for (const [id, raw] of [['an off-curve y', OFF_CURVE], ['a y of p or more', BEYOND_P], ['x = 0 with the sign bit set', NEGATIVE_ZERO_X]]) {
    it(`refuses ${id} as an AID`, () => {
      assert.throws(() => verifyingKey(toAid(raw)), errors.MalformedKey);
    });

    it(`refuses ${id} through the raw keyid`, async () => {
      await assert.rejects(() => verify(forged(Buffer.from(raw).toString('base64url'))), errors.MalformedKey);
    });

    it(`refuses ${id} when a resolver returns it`, async () => {
      await assert.rejects(() => verify(forged('E' + 'A'.repeat(43)), { resolve: () => raw }), errors.MalformedKey);
    });
  }
});
