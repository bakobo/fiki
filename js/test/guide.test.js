// The samples in `docs/user-guide.md`, run.
//
// A guide whose code does not run is worse than no guide: a reader trusts it, pastes it, and loses
// an hour to an API that moved. These are the same calls the guide shows, so a rename that breaks
// a reader's copy-paste breaks the suite first.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  FikiError,
  Key,
  REQUEST_MINIMUM,
  RESPONSE_MINIMUM,
  errors,
  signRequest,
  signResponse,
  verifyRequest,
  verifyResponse,
  verifyingKey,
} from '../src/index.js';

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

// The KERI-profile samples in .ignored/parity/guide-js.md, run in the order the guide shows them.
// A transferable AID does not contain its key, so the verifier's resolver stands in for the key
// state a KERI stack would hold: here, a Map from the AID to its current 32-byte key.
describe("the user guide's KERI-profile samples", async () => {
  const key = await Key.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i));
  const aid = 'EIhwv8kMnCY92GevqHtBlMT8cQD96m3XkNav--Ti-4Q6';
  const keyState = new Map([[aid, verifyingKey(key.aid)]]);
  const resolve = async (keyid) => keyState.get(keyid) ?? null;
  const method = 'POST';
  const requestBody = new TextEncoder().encode('{"name": "alice"}');
  const responseBody = new TextEncoder().encode('{"done": true}');

  // (a) signing a request with a KERI AID as the keyid
  const requestHeaders = await signRequest({
    key, // the AID's current signing key
    keyid: aid,
    method, // exactly as it will go on the wire
    url,
    body: requestBody,
    minimum: REQUEST_MINIMUM,
  });

  it('signs a request with an AID keyid', () => {
    assert.ok(requestHeaders['Signature-Input'].includes(`keyid="${aid}"`));
  });

  it('verifies it with a resolver', async () => {
    // (b) verifying with a resolver
    const verdict = await verifyRequest({
      method, url, headers: requestHeaders, body: requestBody, maxAge: 300,
      minimum: REQUEST_MINIMUM,
      resolve, // keyid -> 32 raw bytes, or null; may be async
    });
    assert.equal(verdict.keyid, aid);
    assert.equal(verdict.aid, aid);
    assert.ok(verdict.covered.includes('content-digest'));
  });

  // (c) signing a response
  const request = { method, url, headers: requestHeaders, body: requestBody };
  const responseHeaders = await signResponse({
    key,
    keyid: aid,
    status: 200,
    request, // the request it answers, which "req" components are read from
    body: responseBody,
    minimum: RESPONSE_MINIMUM,
  });

  it('signs a response bound to its request', () => {
    assert.ok(responseHeaders['Signature-Input'].includes('"@method";req'));
    assert.ok(responseHeaders['Signature-Input'].includes('"content-digest";req'));
  });

  it('verifies the response as a client', async () => {
    // (d) verifying a response
    const verdict = await verifyResponse({
      status: 200, headers: responseHeaders, body: responseBody, request, maxAge: 300,
      minimum: RESPONSE_MINIMUM, resolve,
      expectedKeyid: aid, // the AID this client is talking to
    });
    assert.deepEqual(verdict.covered, [
      '@status', '"@method";req', '"@path";req', '"@query";req', 'content-digest', '"content-digest";req',
    ]);
  });

  it('raises the new error classes as the guide describes', async () => {
    // (e) the new error classes
    async function classify(attempt) {
      try {
        await attempt();
        return 'accepted';
      } catch (e) {
        if (e instanceof errors.UnknownKey) return `no key state for ${e.keyid}`;
        if (e instanceof errors.UnsupportedSigner) return `no single signer for ${e.keyid}`;
        if (e instanceof errors.InsufficientCoverage) return `does not cover ${e.component}`;
        if (e instanceof errors.DuplicateComponent) return `names ${e.component} twice`;
        if (e instanceof errors.Unauthenticated) return 'an unsigned 401';
        if (e instanceof FikiError) return e.constructor.name;
        throw e;
      }
    }
    const verifying = (overrides) => () =>
      verifyRequest({ method, url, headers: requestHeaders, body: requestBody, maxAge: null, resolve, ...overrides });

    assert.equal(await classify(verifying({ resolve: () => null })), `no key state for ${aid}`);
    const group = (keyid) => {
      throw new errors.UnsupportedSigner(`${keyid} is a 2-of-3 group.`, { keyid });
    };
    assert.equal(await classify(verifying({ resolve: group })), `no single signer for ${aid}`);
    assert.equal(await classify(verifying({ minimum: [...REQUEST_MINIMUM, '@authority', 'x-tenant'] })), 'does not cover x-tenant');
    assert.equal(
      await classify(() => signRequest({ key, keyid: aid, method, url, covered: ['@method', '@method'] })),
      'names @method twice',
    );
    assert.equal(
      await classify(() => verifyResponse({ status: 401, headers: {}, request, maxAge: 300, resolve })),
      'an unsigned 401',
    );
  });
});
