// The samples in `docs/user-guide.md`, run.
//
// A guide whose code does not run is worse than no guide: a reader trusts it, pastes it, and loses
// an hour to an API that moved. These are the same calls the guide shows, so a rename that breaks
// a reader's copy-paste breaks the suite first.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { FikiError, Key, errors, signRequest, verifyRequest } from '../src/index.js';

const url = 'https://api.example.com/things?limit=1';
const body = new TextEncoder().encode(JSON.stringify({ hello: 'world' }));

describe("the user guide's samples", () => {
  it('signs and verifies as shown', async () => {
    const key = await Key.generate();
    assert.equal(key.aid.length, 44);

    const headers = await signRequest({ key, method: 'POST', url, body });
    assert.ok(headers['Signature-Input'] && headers.Signature && headers['Content-Digest']);

    const verdict = await verifyRequest({ method: 'POST', url, headers, body, maxAge: 300 });
    assert.equal(verdict.aid, key.aid);

    await verifyRequest({ method: 'POST', url, headers, body, maxAge: null, expectedAid: key.aid });
    await assert.rejects(
      () => verifyRequest({ method: 'POST', url, headers, body: new TextEncoder().encode('x'), maxAge: null }),
      (e) => e instanceof FikiError && e.constructor.name === 'DigestMismatch',
    );
  });

  it('keeps the browser key promises the guide makes', async () => {
    // Non-extractable by default, and seed throws; extractable on request, and seed is 32 bytes.
    const guarded = await Key.generate();
    assert.throws(() => guarded.seed, errors.MalformedKey);
    const portable = await Key.generate({ extractable: true });
    assert.equal(portable.seed.length, 32);
  });
});
