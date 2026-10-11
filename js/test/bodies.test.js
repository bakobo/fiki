// Every body type fiki accepts is the same bytes, and any other type is refused, never absent.
//
// A body is Uint8Array, any other ArrayBufferView (DataView, Int16Array, a Node Buffer), an
// ArrayBuffer, or a string, which is encoded as UTF-8. null or undefined means no body was handed
// over. Anything else is a TypeError: treating an unknown type as "no body" is exactly how a body
// escapes coverage under a minimum (PR #5 hostile review, finding 1).

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  Key,
  REQUEST_MINIMUM,
  RESPONSE_MINIMUM,
  errors,
  signRequest,
  signResponse,
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
const TEXT = '{"hello": "world"}';
const BYTES = new TextEncoder().encode(TEXT);
const AT = 1700000000;

// The same content in every shape a caller may hand over.
const shapes = (bytes) => [
  ['a Uint8Array', bytes],
  ['an ArrayBuffer', bytes.slice().buffer],
  ['a DataView', new DataView(bytes.slice().buffer)],
  ['a Buffer', Buffer.from(bytes)],
  ['a string', new TextDecoder().decode(bytes)],
];

describe('bodies of every accepted type', () => {
  for (const [id, body] of shapes(BYTES)) {
    it(`signs and verifies ${id} as the same bytes`, async () => {
      const headers = await signRequest({ key: KEY, method: 'POST', url: URL_, body, created: AT });
      for (const [, other] of shapes(BYTES)) {
        await verifyRequest({ ...POLICY, method: 'POST', url: URL_, headers, body: other, maxAge: null, minimum: REQUEST_MINIMUM });
      }
    });

    it(`refuses ${id} arriving under a signature that does not cover it`, async () => {
      const headers = await signRequest({ key: KEY, method: 'POST', url: URL_, created: AT });
      await assert.rejects(
        () => verifyRequest({ ...POLICY, method: 'POST', url: URL_, headers, body, maxAge: null, minimum: REQUEST_MINIMUM }),
        errors.InsufficientCoverage,
      );
    });

    it(`refuses ${id} injected into a bodyless signed response`, async () => {
      const request = { method: 'GET', url: URL_ };
      const headers = await signResponse({ key: KEY, status: 200, request, created: AT });
      await assert.rejects(
        () => verifyResponse({ status: 200, headers, body, request, maxAge: null, minimum: RESPONSE_MINIMUM, expectedKeyid: null }),
        errors.InsufficientCoverage,
      );
    });

    it(`refuses a response checked against a request whose body, ${id}, changed`, async () => {
      const original = await signRequest({ key: KEY, method: 'POST', url: URL_, body: 'original', created: AT });
      const request = { method: 'POST', url: URL_, headers: original, body: 'original' };
      const headers = await signResponse({ key: KEY, status: 200, request, created: AT });
      await assert.rejects(
        () => verifyResponse({ status: 200, headers, request: { ...request, body }, maxAge: null, minimum: RESPONSE_MINIMUM, expectedKeyid: null }),
        errors.DigestMismatch,
      );
    });

    it(`binds a request body given as ${id} into a default response`, async () => {
      const original = await signRequest({ key: KEY, method: 'POST', url: URL_, body, created: AT });
      const request = { method: 'POST', url: URL_, headers: original, body };
      const headers = await signResponse({ key: KEY, status: 200, request, created: AT });
      assert.ok(headers['Signature-Input'].includes('"content-digest";req'));
    });
  }

  it('treats an empty body of any type as no content', async () => {
    const headers = await signRequest({ key: KEY, method: 'GET', url: URL_, created: AT });
    for (const [, body] of shapes(new Uint8Array(0))) {
      await verifyRequest({ ...POLICY, method: 'GET', url: URL_, headers, body, maxAge: null, minimum: REQUEST_MINIMUM });
    }
  });

  for (const [id, body] of [
    ['a number', 42],
    ['a plain object', { length: 3 }],
    ['an array of numbers', [1, 2, 3]],
    ['a Blob', new Blob(['x'])],
  ]) {
    it(`refuses ${id} as a body with a TypeError rather than treating it as absent`, async () => {
      await assert.rejects(() => signRequest({ key: KEY, method: 'POST', url: URL_, body, created: AT }), callerError('must be a Uint8Array, another ArrayBufferView, an ArrayBuffer or a string'));
      const headers = await signRequest({ key: KEY, method: 'GET', url: URL_, created: AT });
      await assert.rejects(() => verifyRequest({ ...POLICY, method: 'GET', url: URL_, headers, body, maxAge: null }), callerError('must be a Uint8Array, another ArrayBufferView, an ArrayBuffer or a string'));
      const request = { method: 'GET', url: URL_ };
      const response = await signResponse({ key: KEY, status: 200, request, created: AT });
      await assert.rejects(() => verifyResponse({ status: 200, headers: response, body, request, maxAge: null, expectedKeyid: null, minimum: null }), callerError('must be a Uint8Array, another ArrayBufferView, an ArrayBuffer or a string'));
      await assert.rejects(
        () => verifyResponse({ status: 200, headers: response, request: { ...request, body }, maxAge: null, expectedKeyid: null, minimum: null }),
        callerError('must be a Uint8Array, another ArrayBufferView, an ArrayBuffer or a string'),
      );
      await assert.rejects(() => signResponse({ key: KEY, status: 200, request: { ...request, body }, created: AT }), callerError('must be a Uint8Array, another ArrayBufferView, an ArrayBuffer or a string'));
      await assert.rejects(() => signResponse({ key: KEY, status: 200, body, created: AT }), callerError('must be a Uint8Array, another ArrayBufferView, an ArrayBuffer or a string'));
    });
  }
});

describe('contentDigest', () => {
  it('digests every accepted body type as the same bytes', async () => {
    const { contentDigest } = await import('../src/index.js');
    const expected = await contentDigest(BYTES);
    for (const [, body] of shapes(BYTES)) assert.equal(await contentDigest(body), expected);
    await assert.rejects(() => contentDigest(42), callerError('must be a Uint8Array, another ArrayBufferView, an ArrayBuffer or a string'));
  });
});
