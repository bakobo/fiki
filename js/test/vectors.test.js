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

import { FikiError, Key, signatureBase, verifyRequest, verifyingKey } from '../src/index.js';

const VECTORS = new URL('../../vectors/', import.meta.url);

const load = (name) => JSON.parse(readFileSync(new URL(name, VECTORS), 'utf8'));

const fromHex = (hex) => Uint8Array.from(hex.match(/../g).map((b) => parseInt(b, 16)));
const toBase64 = (bytes) => Buffer.from(bytes).toString('base64');
const toBase64Url = (bytes) => Buffer.from(bytes).toString('base64url');

describe('the vectors are reachable', () => {
  it('sits beside the other ports rather than under this one', () => {
    // A port that cannot find these has forked them, which is what the layout exists to prevent.
    assert.equal(fileURLToPath(VECTORS).split('/').at(-2), 'vectors');
    assert.ok(load('aid-lens.json').cases.length > 0);
  });
});

describe('the AID lens', () => {
  for (const c of load('aid-lens.json').cases) {
    it(c.id, async () => {
      const key = await Key.fromSeed(fromHex(c.seed_hex));
      assert.equal(await key.aid, c.aid);
      assert.equal(toBase64Url(fromHex(c.public_key_hex)), c.keyid);
      assert.deepEqual(await verifyingKey(c.aid), fromHex(c.public_key_hex));
    });
  }
});

describe('signature bases and the signatures over them', () => {
  for (const c of load('signature-base.json').cases) {
    it(`${c.id} — base`, () => {
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
  for (const c of load('refusals.json').cases) {
    it(c.id, async () => {
      // Every entry names the class fiki raises, so this port maps its own onto the same
      // condition rather than inventing a taxonomy of its own.
      await assert.rejects(
        () =>
          verifyRequest({
            method: c.method,
            url: c.url,
            headers: c.headers,
            body: c.body === null ? null : new TextEncoder().encode(c.body),
            maxAge: c.max_age,
            now: c.now,
          }),
        (err) => {
          assert.ok(err instanceof FikiError, `expected a FikiError, got ${err}`);
          assert.equal(err.constructor.name, c.error);
          return true;
        },
      );
    });
  }
});
