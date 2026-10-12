// Two header names equal case-insensitively are refused, never collapsed (ruling D-Q9ZT).
//
// Field names are case-insensitive, so `X-Role` and `x-role` in one header object are two values
// for one field. Keeping either silently lets a signer cover one value while the application reads
// the other, so fiki refuses the input as a caller error, a TypeError, on every path that takes
// headers: signing and verifying, requests and responses, and the request a response answers.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  Key,
  componentLines,
  contentDigest,
  errors,
  responseSignatureBase,
  signRequest,
  signResponse,
  signatureBase,
  verifyRequest,
  verifyResponse,
} from '../src/index.js';
import { callerError } from './caller.js';

// Format 3 made the verifier's default minimum fiki's own signing default and authorities a
// required decision (@524c8qgv). These tests predate both and are about other things, so they
// state the 0.8 policy explicitly — no minimum, no authority check — and a test that wants either
// says so after it.
const POLICY = { minimum: null, authorities: null };

const KEY = await Key.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i));
const URL_ = 'https://keria.example.com/identifiers?type=rot';
const BODY = new TextEncoder().encode('{"hello": "world"}');
const AT = 1700000000;
const DIGEST = await contentDigest(BODY);

const doubled = [
  ['X-Role and x-role', { 'X-Role': 'admin', 'x-role': 'guest' }],
  ['Content-Digest and content-digest', { 'Content-Digest': DIGEST, 'content-digest': DIGEST }],
];

describe('headers holding one field name twice (D-Q9ZT)', () => {
  for (const [id, extra] of doubled) {
    it(`refuses ${id} when signing and building a base`, async () => {
      await assert.rejects(() => signRequest({ key: KEY, method: 'POST', url: URL_, headers: extra, body: BODY, created: AT }), callerError('twice in different case, so it holds two values for one field'));
      const request = { method: 'POST', url: URL_, headers: extra, body: BODY };
      await assert.rejects(() => signResponse({ key: KEY, status: 200, headers: extra, created: AT }), callerError('twice in different case, so it holds two values for one field'));
      await assert.rejects(() => signResponse({ key: KEY, status: 200, request, created: AT }), callerError('twice in different case, so it holds two values for one field'));
      const base = { covered: ['@method'], created: AT, keyid: 'k' };
      assert.throws(() => signatureBase({ method: 'POST', url: URL_, headers: extra, ...base }), callerError('twice in different case, so it holds two values for one field'));
      assert.throws(() => componentLines({ method: 'POST', url: URL_, headers: extra, covered: ['@method'] }), callerError('twice in different case, so it holds two values for one field'));
      assert.throws(() => responseSignatureBase({ status: 200, headers: extra, ...base, covered: ['@status'] }), callerError('twice in different case, so it holds two values for one field'));
      assert.throws(() => responseSignatureBase({ status: 200, headers: {}, request, ...base, covered: ['@status'] }), callerError('twice in different case, so it holds two values for one field'));
    });

    it(`refuses ${id} when verifying`, async () => {
      const signed = await signRequest({ key: KEY, method: 'POST', url: URL_, body: BODY, created: AT });
      await assert.rejects(
        () => verifyRequest({ ...POLICY, method: 'POST', url: URL_, headers: { ...signed, ...extra }, body: BODY, maxAge: null }),
        callerError('twice in different case, so it holds two values for one field'),
      );
      const request = { method: 'POST', url: URL_, headers: { 'Content-Digest': DIGEST }, body: BODY };
      const response = await signResponse({ key: KEY, status: 200, request, created: AT });
      await assert.rejects(() => verifyResponse({ status: 200, headers: { ...response, ...extra }, request, maxAge: null, expectedKeyid: null, minimum: null }), callerError('twice in different case, so it holds two values for one field'));
      await assert.rejects(
        () => verifyResponse({
          status: 200, headers: response, request: { ...request, headers: { ...request.headers, ...extra } }, maxAge: null,
          expectedKeyid: null, minimum: null,
        }),
        callerError('twice in different case, so it holds two values for one field'),
      );
    });
  }

  it('refuses the signature headers doubled in case, even on an unsigned 401', async () => {
    await assert.rejects(() => verifyResponse({ status: 401, headers: { signature: 'a', Signature: 'b' }, maxAge: null, expectedKeyid: null, minimum: null }), callerError('twice in different case, so it holds two values for one field'));
  });

  it('still reads one field of any case the same way everywhere', async () => {
    const headers = { 'CONTENT-DIGEST': DIGEST, 'x-ROLE': 'admin' };
    const signed = await signRequest({
      key: KEY, method: 'POST', url: URL_, headers, body: BODY, created: AT,
      covered: ['@method', '@path', '@query', 'x-role', 'content-digest'],
    });
    assert.equal(signed['Content-Digest'], undefined);
    await verifyRequest({ ...POLICY, method: 'POST', url: URL_, headers: { ...headers, ...signed }, body: BODY, maxAge: null });
  });
});

describe('a header named __proto__ (PR #5 hostile review, H1)', () => {
  it('is refused when doubled in case, rather than vanishing', async () => {
    const headers = JSON.parse('{"__proto__": "admin", "__PROTO__": "guest"}');
    await assert.rejects(() => signRequest({ key: KEY, method: 'GET', url: URL_, headers, created: AT }), callerError('twice in different case, so it holds two values for one field'));
    const signed = await signRequest({ key: KEY, method: 'GET', url: URL_, created: AT });
    await assert.rejects(() => verifyRequest({ ...POLICY, method: 'GET', url: URL_, headers: { ...signed, ...headers }, maxAge: null }), callerError('twice in different case, so it holds two values for one field'));
  });

  it('is an ordinary field when it appears once', async () => {
    const headers = JSON.parse('{"__proto__": "admin"}');
    const covered = ['@method', '@path', '@query', '__proto__'];
    const base = signatureBase({ method: 'GET', url: URL_, headers, covered, created: AT, keyid: 'k' });
    assert.equal(new TextDecoder().decode(base).split('\n')[3], '"__proto__": admin');
    const signed = await signRequest({ key: KEY, method: 'GET', url: URL_, headers, covered, created: AT });
    const both = Object.assign(JSON.parse('{"__proto__": "admin"}'), signed);
    await verifyRequest({ ...POLICY, method: 'GET', url: URL_, headers: both, maxAge: null });
    const swapped = Object.assign(JSON.parse('{"__proto__": "guest"}'), signed);
    await assert.rejects(() => verifyRequest({ ...POLICY, method: 'GET', url: URL_, headers: swapped, maxAge: null }), errors.SignatureMismatch);
  });
});

// Node's IncomingMessage gives set-cookie as an array, and RFC 9421 section 2.1 says a field sent in
// several lines is those lines joined with a comma and one space (@4un2vx4l, tick 7r4c).
describe('a header value given as a list is joined with ", " (@4un2vx4l)', () => {
  const LISTED = ['@method', '@authority', '@path', '@query', 'x-tag', 'set-cookie'];
  const EACH = 'whose field lines must be each a string';
  const sign = (headers) => signRequest({ key: KEY, method: 'GET', url: URL_, headers, covered: LISTED, created: AT });
  const verify = (headers) => verifyRequest({ ...POLICY, method: 'GET', url: URL_, headers, maxAge: null });
  const joined = () => sign({ 'X-Tag': 'a=1, b=2', 'Set-Cookie': 's=1, t=2' });

  it('verifies against the value joined as RFC 9421 joins it', async () => {
    const listed = { ...(await joined()), 'X-Tag': ['a=1', 'b=2'], 'Set-Cookie': ['s=1', 't=2'] };
    assert.deepEqual((await verify(listed)).covered, LISTED);
  });

  it('is signed as its joined value', async () => {
    const listed = await sign({ 'X-Tag': ['a=1', 'b=2'], 'Set-Cookie': ['s=1', 't=2'] });
    assert.equal(listed.Signature, (await joined()).Signature);
    const base = signatureBase({ method: 'GET', url: URL_, headers: { 'X-Tag': ['a=1', 'b=2'] }, covered: ['x-tag'], created: AT, keyid: 'k' });
    assert.equal(new TextDecoder().decode(base).split('\n')[0], '"x-tag": a=1, b=2');
  });

  it('is the string itself when it holds one element', async () => {
    const signed = await sign({ 'X-Tag': 'a=1', 'Set-Cookie': 's=1' });
    assert.deepEqual((await verify({ ...signed, 'X-Tag': ['a=1'], 'Set-Cookie': ['s=1'] })).covered, LISTED);
  });

  it('does not verify against a list a framework joined with a bare comma', async () => {
    const signed = await joined();
    await assert.rejects(() => verify({ ...signed, 'X-Tag': 'a=1,b=2', 'Set-Cookie': ['s=1', 't=2'] }), errors.SignatureMismatch);
  });

  it('is joined in a response and in the request it answers', async () => {
    const request = { method: 'GET', url: URL_, headers: { 'X-Tag': ['a=1', 'b=2'] } };
    const covered = ['@status', 'set-cookie', '"x-tag";req'];
    const signed = await signResponse({ key: KEY, status: 200, request, headers: { 'Set-Cookie': ['s=1', 't=2'] }, covered, created: AT });
    const verdict = await verifyResponse({
      ...POLICY, status: 200, request: { ...request, headers: { 'x-tag': 'a=1, b=2' } }, headers: { ...signed, 'Set-Cookie': 's=1, t=2' }, maxAge: null, expectedKeyid: null,
    });
    assert.deepEqual(verdict.covered, covered);
  });

  for (const value of [['a=1', 2], ['a=1', new TextEncoder().encode('b=2')], [null], ['a=1', ['b=2']], ['a=1', , 'b=2']]) {
    it(`is a caller error when it holds a non-string, as in ${JSON.stringify(value)}`, async () => {
      const signed = await joined();
      await assert.rejects(() => verify({ ...signed, 'X-Tag': value }), callerError(EACH));
      await assert.rejects(() => sign({ 'X-Tag': value }), callerError(EACH));
    });
  }
});
