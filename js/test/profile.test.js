// What the KERI profile of RFC 9421 asks of a verifier (`this.i` @7f28p7xk, @2f227n4r, @7p9s3g9k).
//
// The same requirements fiki-py's test_profile.py pins, in this port: method case (@22g0xkr8),
// every recognized digest, caller-chosen keyids with an authoritative resolver (@6g9zjsv9),
// responses bound to their request with `req`, the wire-side refusals, an optional minimum covered
// set, and the profile's section 9 refusal order. The KERI vectors cover what every implementation
// must agree on; this file covers the rest of the surface, at the port's 100% branch gate.
//
// Every refusal is written as a positive assertion about a refusal, because a negative requirement
// that is quietly dropped leaves no failing test behind.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';

import {
  Key,
  REQUEST_MINIMUM,
  RESPONSE_MINIMUM,
  contentDigest,
  errors,
  req,
  responseSignatureBase,
  signRequest,
  signResponse,
  signatureBase,
  verifyRequest,
  verifyResponse,
  verifyingKey,
} from '../src/index.js';
import { callerError } from './caller.js';

// Format 3 made the verifier's default minimum fiki's own signing default and authorities a
// required decision (@524c8qgv). These tests predate both and are about other things, so they
// state the 0.8 policy explicitly — no minimum, no authority check — and a test that wants either
// says so after it.
const POLICY = { minimum: null, authorities: null };

const KEY = await Key.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i));
const OTHER = await Key.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
const URL_ = 'https://keria.example.com/identifiers?type=rot';
const BODY = new TextEncoder().encode('{"hello": "world"}');
const AT = 1700000000;

const raw = (key) => verifyingKey(key.aid);
/** A 44-character qb64 over 32 raw bytes, the arithmetic fiki's own B lens uses. */
const cesr = (code, bytes) => code + Buffer.concat([Buffer.alloc(1), Buffer.from(bytes)]).toString('base64url').slice(1);
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const paddingBitAlias = (aid) => aid[0] + ALPHABET[ALPHABET.indexOf(aid[1]) ^ 0b010000] + aid.slice(2);
const AID = cesr('E', createHash('sha256').update('a transferable AID').digest());
const table = (entries) => (keyid) => entries[keyid] ?? null;

async function sign(overrides = {}) {
  const args = { key: KEY, method: 'POST', url: URL_, headers: {}, body: BODY, created: AT, ...overrides };
  const headers = { ...args.headers, ...(await signRequest(args)) };
  return { request: { method: args.method, url: args.url, body: args.body }, headers };
}

/** A POST signed over a Content-Digest of the test's own spelling.
 *
 * Built from the base rather than through signRequest, which refuses to sign a digest the body
 * does not bear out (A7, @5zrf8gjk), so a test can hand the verifier a header the signer would not.
 */
async function signOver(digest) {
  const headers = { 'Content-Digest': digest };
  const base = signatureBase({
    method: 'POST',
    url: URL_,
    headers,
    covered: ['@method', '@authority', '@path', '@query', 'content-digest'],
    created: AT,
    keyid: KEY.keyid,
    alg: 'ed25519',
  });
  headers['Signature-Input'] = `sig=${new TextDecoder().decode(base).split('"@signature-params": ').at(-1)}`;
  headers.Signature = `sig=:${Buffer.from(await KEY.sign(base)).toString('base64')}:`;
  return { request: { method: 'POST', url: URL_, body: BODY }, headers };
}

const verify = ({ request, headers }, overrides = {}) =>
  verifyRequest({ ...POLICY, ...request, headers, maxAge: null, ...overrides });

function mangle(headers, old, replacement) {
  assert.ok(headers['Signature-Input'].includes(old), `${old} is not in ${headers['Signature-Input']}`);
  headers['Signature-Input'] = headers['Signature-Input'].replace(old, replacement);
  return headers;
}

const keyidOf = (headers) => headers['Signature-Input'].split('keyid="')[1].split('"')[0];

const REQUEST = { method: 'POST', url: URL_, headers: { 'Content-Digest': await contentDigest(BODY) }, body: BODY };
const RESPONSE_BODY = new TextEncoder().encode('{"done": true}');

async function respond(overrides = {}) {
  const args = { key: KEY, status: 200, request: REQUEST, headers: {}, body: RESPONSE_BODY, created: AT, ...overrides };
  return { ...args.headers, ...(await signResponse(args)) };
}

// 0.8's response policy, stated explicitly now that the default is RESPONSE_MINIMUM and expectedKeyid
// is required (@524c8qgv); the new default has tests of its own.
const check = (headers, overrides = {}) =>
  verifyResponse({
    status: 200, headers, body: RESPONSE_BODY, request: REQUEST, maxAge: null, expectedKeyid: null, minimum: null, ...overrides,
  });

const digestOf = (algorithm, bytes) => createHash(algorithm).update(bytes).digest('base64');

describe('@method is the method as sent (@22g0xkr8)', () => {
  it('is not uppercased in the base', () => {
    const base = signatureBase({ method: 'post', url: URL_, headers: {}, covered: ['@method'], created: AT, keyid: 'k' });
    assert.equal(new TextDecoder().decode(base).split('\n')[0], '"@method": post');
  });
});

describe('a method is required (PR #5 hostile review, finding 3)', () => {
  for (const method of [undefined, null, '', 42]) {
    it(`refuses ${JSON.stringify(method) ?? 'undefined'} as a method rather than signing "undefined"`, async () => {
      const base = { url: URL_, headers: {}, covered: ['@method'], created: AT, keyid: 'k' };
      assert.throws(() => signatureBase({ ...base, method }), callerError('is not an HTTP method'));
      await assert.rejects(() => sign({ method }), callerError('is not an HTTP method'));
      const signed = await sign();
      await assert.rejects(() => verify(signed, { method }), callerError('is not an HTTP method'));
      await assert.rejects(() => respond({ request: { ...REQUEST, method } }), callerError('is not an HTTP method'));
      await assert.rejects(async () => check(await respond(), { request: { ...REQUEST, method } }), callerError('is not an HTTP method'));
    });
  }
});

describe('Content-Digest: every recognized member must match (RFC 9530)', () => {
  it('refuses two recognized digests when one mismatches', async () => {
    const good = await contentDigest(BODY);
    const signed = await signOver(`${good}, sha-512=:${digestOf('sha512', 'other')}:`);
    await assert.rejects(() => verify(signed), errors.DigestMismatch);
  });

  it('accepts two recognized digests that both match', async () => {
    const digest = `sha-512=:${digestOf('sha512', BODY)}:, ${await contentDigest(BODY)}`;
    const signed = await sign({ headers: { 'Content-Digest': digest } });
    assert.equal((await verify(signed)).aid, KEY.aid);
  });

  // RFC 8941 keys are lowercase and cannot start with "_", so "constructor" is the one
  // Object.prototype name a member can carry; the others are here as the same kind of guard.
  for (const name of ['constructor', 'tostring', 'hasownproperty', 'valueof']) {
    it(`ignores a ${name} member as an unknown algorithm, never a lookup on Object.prototype`, async () => {
      // Copilot review of PR #5, C4: the algorithm table is keyed by untrusted member names.
      const digest = `${await contentDigest(BODY)}, ${name}=:AA==:`;
      const signed = await signOver(digest);
      assert.equal((await verify(signed)).aid, KEY.aid);
      const only = await signOver(`${name}=:AA==:`);
      await assert.rejects(() => verify(only), errors.MalformedDigest);
    });
  }

  it('refuses a __proto__ member as an unparsable header, since no RFC 8941 key starts with "_"', async () => {
    const signed = await signOver(`${await contentDigest(BODY)}, __proto__=:AA==:`);
    await assert.rejects(() => verify(signed), errors.MalformedDigest);
  });

  it('refuses a recognized digest that is not a byte sequence as malformed', async () => {
    const signed = await signOver('sha-256="not bytes"');
    await assert.rejects(() => verify(signed), errors.MalformedDigest);
  });

  it('reports an unparsable digest as malformed even when no body was supplied', async () => {
    // Section 9 puts malformed-digest before digest-mismatch.
    const signed = await signOver('((((');
    signed.request.body = null;
    await assert.rejects(() => verify(signed), errors.MalformedDigest);
  });

  it('refuses a covered digest the message does not carry as a missing component', async () => {
    const signed = await sign();
    delete signed.headers['Content-Digest'];
    await assert.rejects(() => verify(signed, { headers: { ...signed.headers, 'X-Unrelated': '1' } }), errors.MissingComponent);
  });
});

describe('a caller-chosen keyid and an authoritative resolver (@6g9zjsv9)', () => {
  it('lets a caller sign with an AID as the keyid', async () => {
    const { headers } = await sign({ keyid: AID });
    assert.ok(headers['Signature-Input'].includes(`keyid="${AID}"`));
  });

  it('takes the key for a transferable AID from the resolver, sync or async', async () => {
    const signed = await sign({ keyid: AID });
    const verdict = await verify(signed, { resolve: table({ [AID]: raw(KEY) }) });
    assert.equal(verdict.aid, AID);
    assert.equal(verdict.keyid, AID);
    assert.equal((await verify(signed, { resolve: async () => raw(KEY) })).aid, AID);
  });

  it('still reports the raw keyid without a resolver', async () => {
    const verdict = await verify(await sign());
    assert.equal(verdict.aid, KEY.aid);
    assert.equal(verdict.keyid, Buffer.from(raw(KEY)).toString('base64url'));
  });

  it('refuses a keyid the resolver does not know as an unknown key', async () => {
    const signed = await sign({ keyid: AID });
    await assert.rejects(() => verify(signed, { resolve: table({}) }), (e) => e instanceof errors.UnknownKey && e.keyid === AID);
    await assert.rejects(() => verify(signed, { resolve: () => undefined }), errors.UnknownKey);
  });

  it('refuses a resolver answer other than 32 bytes as a malformed key', async () => {
    const signed = await sign({ keyid: AID });
    await assert.rejects(() => verify(signed, { resolve: () => new Uint8Array(5) }), errors.MalformedKey);
    await assert.rejects(() => verify(signed, { resolve: () => 'not bytes at all' }), errors.MalformedKey);
  });

  it('lets a resolver refuse a malformed keyid itself', async () => {
    const signed = await sign({ keyid: 'not-an-aid' });
    const resolve = (keyid) => {
      throw new errors.MalformedKey(`${keyid} is not an AID.`, { keyid });
    };
    await assert.rejects(() => verify(signed, { resolve }), errors.MalformedKey);
  });

  it('never decodes a D-prefixed keyid as a key when a resolver is supplied', async () => {
    // Profile R1: D... embeds the inception key, so decoding it would undo pre-rotation.
    const inception = cesr('D', raw(KEY));
    const resolve = table({ [inception]: raw(OTHER) });
    await assert.rejects(async () => verify(await sign({ keyid: inception }), { resolve }), errors.SignatureMismatch);
    assert.equal((await verify(await sign({ key: OTHER, keyid: inception }), { resolve })).aid, inception);
  });

  it('refuses a resolver with no keyid to resolve as a missing key', async () => {
    const signed = await sign({ keyid: AID });
    mangle(signed.headers, `;keyid="${AID}"`, '');
    await assert.rejects(() => verify(signed, { resolve: table({ [AID]: raw(KEY) }) }), errors.MissingKey);
  });

  it('refuses an empty keyid as a missing key', async () => {
    await assert.rejects(async () => verify(await sign({ keyid: '' }), { resolve: table({}) }), errors.MissingKey);
  });

  it('treats expectedAid and a resolver together as a programming error', async () => {
    const signed = await sign();
    await assert.rejects(() => verify(signed, { resolve: table({}), expectedAid: KEY.aid }), callerError('Pass expectedAid or resolve, not both'));
  });

  it('lets a resolver refuse a key state with no single signer', async () => {
    const resolve = (keyid) => {
      throw new errors.UnsupportedSigner(`${keyid} has no single effective signer.`, { keyid });
    };
    await assert.rejects(async () => verify(await sign({ keyid: AID }), { resolve }), errors.UnsupportedSigner);
  });

  for (const code of ['B', 'D', 'E']) {
    it(`refuses a padding-bit alias of a ${code} AID even through a resolver`, async () => {
      const signed = await sign({ keyid: paddingBitAlias(cesr(code, raw(KEY))) });
      await assert.rejects(() => verify(signed, { resolve: () => raw(KEY) }), errors.MalformedKey);
      await assert.rejects(() => verify(signed, { resolve: () => null }), errors.MalformedKey);
    });
  }

  it('refuses an AID-shaped keyid outside the alphabet even through a resolver', async () => {
    const signed = await sign({ keyid: 'E' + '!'.repeat(43) });
    await assert.rejects(() => verify(signed, { resolve: () => raw(KEY) }), errors.MalformedKey);
  });

  it('lets a non-AID keyid of 44 characters reach the resolver', async () => {
    const keyid = 'X' + 'A'.repeat(43);
    assert.equal((await verify(await sign({ keyid }), { resolve: () => raw(KEY) })).aid, keyid);
  });

  it('refuses a raw keyid that is not the canonical spelling of a key', async () => {
    const canonical = Buffer.from(raw(KEY)).toString('base64url');
    // The last character carries two bits a lenient decoder ignores; flipping them aliases the key.
    const alias = canonical.slice(0, -1) + ALPHABET[ALPHABET.indexOf(canonical.at(-1)) ^ 0b000001];
    const signed = await sign({ keyid: alias });
    await assert.rejects(() => verify(signed), errors.MalformedKey);
    await assert.rejects(async () => verify(await sign({ keyid: 'short' })), errors.MalformedKey);
  });

  it('refuses a response from an AID other than the expected one as an unknown key', async () => {
    const headers = await respond({ keyid: AID });
    const resolve = table({ [AID]: raw(KEY) });
    assert.equal((await check(headers, { resolve, expectedKeyid: AID })).keyid, AID);
    await assert.rejects(() => check(headers, { resolve, expectedKeyid: cesr('E', new Uint8Array(32)) }), errors.UnknownKey);
  });
});

describe('a malformed keyid outranks an unexpected one, and an unexpected one is never looked up', () => {
  // Section 9 puts malformed-key ahead of unknown-key, so the keyid's own spelling is checked first
  // (Copilot review of PR #5, C3). A keyid that is not the expected one is then refused WITHOUT
  // calling the resolver, so an attacker cannot make a verifier wait on a lookup for a keyid it is
  // about to refuse; the resolver's own MalformedKey is consulted only for the expected keyid
  // (hostile review at fae18bc, `this.i` @0ekvjgsp).
  const EXPECTED = cesr('E', new Uint8Array(32).fill(7));
  const refusesAs = async (keyid, resolve, ErrorClass) => {
    const signed = await sign({ keyid });
    await assert.rejects(() => verify(signed, { expectedKeyid: EXPECTED, ...(resolve ? { resolve } : {}) }), ErrorClass);
  };
  const malformed = (keyid) => {
    throw new errors.MalformedKey(`${keyid} is not an AID.`, { keyid });
  };
  const group = (keyid) => {
    throw new errors.UnsupportedSigner(`${keyid} is a group.`, { keyid });
  };
  const never = () => new Promise(() => {});
  const untouched = () => {
    throw new Error('the resolver was called for a keyid that was not expected');
  };

  it('reports a raw keyid that is not a key as malformed', async () => {
    await refusesAs('not-a-key', null, errors.MalformedKey);
  });

  it('reports a misspelled AID as malformed, without calling the resolver', async () => {
    await refusesAs('E' + '!'.repeat(43), untouched, errors.MalformedKey);
  });

  it('refuses an unexpected keyid without calling the resolver, even one that never answers', async () => {
    await refusesAs(AID, never, errors.UnknownKey);
    await refusesAs(AID, untouched, errors.UnknownKey);
    await refusesAs('not-an-aid', malformed, errors.UnknownKey);
    await refusesAs(AID, group, errors.UnknownKey);
  });

  it("consults the resolver's own refusals for the expected keyid", async () => {
    const check = async (keyid, resolve, ErrorClass) => {
      const signed = await sign({ keyid });
      await assert.rejects(() => verify(signed, { expectedKeyid: keyid, resolve }), ErrorClass);
    };
    await check('not-an-aid', malformed, errors.MalformedKey);
    await check(AID, () => new Uint8Array(5), errors.MalformedKey);
    await check(AID, group, errors.UnsupportedSigner);
    await check(AID, () => null, errors.UnknownKey);
  });

  it('keeps a caller-defined keyid that is not an AID working', async () => {
    const keyid = 'tenant-7/signing-key';
    const verdict = await verify(await sign({ keyid }), { expectedKeyid: keyid, resolve: () => raw(KEY) });
    assert.equal(verdict.keyid, keyid);
  });
});

describe('component identifiers with parameters', () => {
  it('names a request component from a response with req', () => {
    assert.equal(req('@Method'), '"@method";req');
    assert.equal(req('Content-Digest'), '"content-digest";req');
  });

  it('lets a caller name components in their serialized form', async () => {
    const signed = await sign({ covered: ['"@method"', '"@PATH"', '@query', '"content-digest"'] });
    assert.deepEqual((await verify(signed)).covered, ['@method', '@path', '@query', 'content-digest']);
  });

  it('refuses to sign a duplicate component', async () => {
    await assert.rejects(() => sign({ covered: ['@method', '@method', 'content-digest'] }), errors.DuplicateComponent);
  });

  for (const spec of ['"@path', '"@path" trailing', '"@path";=x', '"@path";req=:AAAA:extra']) {
    it(`refuses the component spec ${spec} as an unsupported component`, async () => {
      await assert.rejects(() => sign({ covered: [spec, 'content-digest'] }), errors.UnsupportedComponent);
    });
  }

  it('refuses to sign an unsupported component parameter', async () => {
    await assert.rejects(() => sign({ covered: ['"@method";sf', '@path', 'content-digest'] }), errors.UnsupportedComponent);
  });
});

describe('responses (RFC 9421 section 2.4)', () => {
  it('verifies a signed response and binds its request', async () => {
    const verdict = await check(await respond());
    assert.equal(verdict.aid, KEY.aid);
    assert.deepEqual(verdict.covered, [
      '@status', '"@method";req', '"@path";req', '"@query";req', 'content-digest', '"content-digest";req',
    ]);
  });

  it('builds a three-digit status line', () => {
    const base = responseSignatureBase({ status: 204, headers: {}, covered: ['@status'], created: AT, keyid: 'k' });
    assert.equal(new TextDecoder().decode(base).split('\n')[0], '"@status": 204');
  });

  it('carries the request values on the req lines', async () => {
    const base = responseSignatureBase({
      status: 200, headers: {}, request: REQUEST, created: AT, keyid: 'k',
      covered: ['@status', req('@method'), req('@path'), req('@query'), req('content-digest'), req('@authority')],
    });
    assert.deepEqual(new TextDecoder().decode(base).split('\n').slice(1, 6), [
      '"@method";req: POST',
      '"@path";req: /identifiers',
      '"@query";req: ?type=rot',
      `"content-digest";req: ${await contentDigest(BODY)}`,
      '"@authority";req: keria.example.com',
    ]);
  });

  it('refuses an altered status', async () => {
    await assert.rejects(async () => check(await respond(), { status: 201 }), errors.SignatureMismatch);
  });

  it('refuses a swapped response body', async () => {
    const body = new TextEncoder().encode('{"done": false}');
    await assert.rejects(async () => check(await respond(), { body }), errors.DigestMismatch);
  });

  it('refuses a response checked against a different request', async () => {
    const other = { ...REQUEST, url: 'https://keria.example.com/other?type=rot' };
    await assert.rejects(async () => check(await respond(), { request: other }), errors.SignatureMismatch);
  });

  it('covers only its own components when there is no request', async () => {
    const verdict = await check(await respond({ request: null }), { request: null });
    assert.deepEqual(verdict.covered, ['@status', 'content-digest']);
  });

  it('covers no digest for a bodyless response to a bodyless request', async () => {
    const get = { method: 'GET', url: URL_ };
    const verdict = await check(await respond({ request: get, body: null }), { request: get, body: null });
    assert.deepEqual(verdict.covered, ['@status', '"@method";req', '"@path";req', '"@query";req']);
  });

  it('refuses to sign a response body without its digest', async () => {
    await assert.rejects(() => respond({ covered: ['@status'] }), errors.UncoveredBody);
  });

  it('refuses a req component with no request to read it from', async () => {
    await assert.rejects(() => respond({ request: null, covered: ['@status', req('@path'), 'content-digest'] }), errors.MissingComponent);
    await assert.rejects(async () => check(await respond(), { request: null }), errors.MissingComponent);
  });

  it('refuses a req field the request lacks', async () => {
    const bare = { method: 'POST', url: URL_ };
    await assert.rejects(
      () => respond({ request: bare, covered: ['@status', req('content-digest'), 'content-digest'] }),
      errors.MissingComponent,
    );
  });

  for (const status of [99, 1000, -200, true, '200', 200.5]) {
    it(`has no status line for ${JSON.stringify(status)}`, async () => {
      assert.throws(
        () => responseSignatureBase({ status, headers: {}, covered: ['@status'], created: AT, keyid: 'k' }),
        (e) => e instanceof errors.MissingComponent && e.component === '@status',
      );
      await assert.rejects(async () => check(await respond(), { status }), errors.MissingComponent);
    });
  }

  for (const status of [100, 999]) {
    it(`includes ${status} in the status range`, () => {
      const base = responseSignatureBase({ status, headers: {}, covered: ['@status'], created: AT, keyid: 'k' });
      assert.equal(new TextDecoder().decode(base).split('\n')[0], `"@status": ${status}`);
    });
  }

  it('refuses an unsigned 401 as unauthenticated before anything else', async () => {
    const body = new TextEncoder().encode('{"title": "no"}');
    await assert.rejects(() => check({ 'Content-Type': 'application/json' }, { status: 401, body }), errors.Unauthenticated);
    await assert.rejects(() => check(undefined, { status: 401 }), errors.Unauthenticated);
  });

  it('refuses an unsigned 200 as missing its signature', async () => {
    await assert.rejects(() => check({}, { status: 200 }), errors.MissingSignature);
  });

  it('verifies a signed 401 like any other response', async () => {
    assert.equal((await check(await respond({ status: 401 }), { status: 401 })).aid, KEY.aid);
  });

  it('requires a maxAge decision', async () => {
    await assert.rejects(async () => verifyResponse({ status: 200, headers: await respond(), request: REQUEST, expectedKeyid: null, minimum: null }), callerError('verifyResponse requires maxAge'));
  });

  it('keeps a Content-Digest the caller supplied, and returns none of its own', async () => {
    const digest = await contentDigest(RESPONSE_BODY);
    const headers = await respond({ headers: { 'content-digest': digest } });
    assert.equal(headers['Content-Digest'], undefined);
    assert.equal((await check(headers)).aid, KEY.aid);
  });

  it('signs a response with no headers of its own', async () => {
    const headers = await respond({ headers: undefined, body: null, request: null });
    assert.equal((await check(headers, { body: null, request: null })).aid, KEY.aid);
  });

  it('uses the wall clock when no created is given', async () => {
    const headers = await respond({ created: undefined });
    assert.equal((await check(headers, { maxAge: 60 })).aid, KEY.aid);
  });
});

describe('the covered list, as received', () => {
  for (const [id, covered] of [
    ['unsupported-parameter', '"@method";sf'],
    ['req-in-a-request', '"@method";req'],
    ['status-in-a-request', '"@status"'],
    ['unknown-derived', '"@target-uri"'],
  ]) {
    it(`refuses ${id} in a request rather than dropping it`, async () => {
      const signed = await sign();
      mangle(signed.headers, '"@method"', covered);
      await assert.rejects(() => verify(signed), errors.UnsupportedComponent);
    });
  }

  for (const [id, old, replacement] of [
    ['status-with-req', '"@status"', '"@status";req'],
    ['request-component-without-req', '"@path";req', '"@path"'],
    ['req-that-is-false', '"@path";req', '"@path";req=?0'],
    ['req-plus-another-parameter', '"@path";req', '"@path";req;bs'],
  ]) {
    it(`refuses ${id} in a response`, async () => {
      const headers = mangle(await respond(), old, replacement);
      await assert.rejects(() => check(headers), errors.UnsupportedComponent);
    });
  }

  it('refuses a duplicate component', async () => {
    const signed = await sign();
    mangle(signed.headers, '"@path"', '"@path" "@path"');
    await assert.rejects(() => verify(signed), errors.DuplicateComponent);
  });

  it('finds a duplicate whatever the parameter order, and before it is unsupported', async () => {
    const headers = mangle(await respond(), '"content-digest";req', '"content-digest";req;sf "content-digest";sf;req');
    await assert.rejects(() => check(headers), errors.DuplicateComponent);
  });
});

describe('Signature-Input, as received', () => {
  for (const [id, old, replacement] of [
    ['uppercase-field-name', '"content-digest"', '"Content-Digest"'],
    ['unknown-parameter', `;created=${AT}`, `;created=${AT};context="x"`],
    ['created-not-an-integer', `;created=${AT}`, ';created="soon"'],
    ['created-a-boolean', `;created=${AT}`, ';created=?1'],
    ['alg-a-token', 'alg="ed25519"', 'alg=ed25519'],
    ['component-a-token', '"@path"', 'path'],
    ['component-an-integer', '"@path"', '7'],
    ['created-of-sixteen-digits', `;created=${AT}`, ';created=1700000000000000'],
    // Parameter names are untrusted keys into the parameter table (Copilot review of PR #5, C4).
    ['a-constructor-parameter', `;created=${AT}`, `;created=${AT};constructor="x"`],
    ['a-tostring-parameter-with-a-function-like-type', `;created=${AT}`, `;created=${AT};tostring=1`],
    ['a-proto-parameter', `;created=${AT}`, `;created=${AT};__proto__="x"`],
  ]) {
    it(`refuses a member with ${id}`, async () => {
      const signed = await sign();
      mangle(signed.headers, old, replacement);
      await assert.rejects(() => verify(signed), errors.MalformedSignatureInput);
    });
  }

  it('refuses a member that is not an inner list', async () => {
    const signed = await sign();
    signed.headers['Signature-Input'] = 'sig="not a list"';
    await assert.rejects(() => verify(signed), errors.MalformedSignatureInput);
  });

  it('refuses two labels in the Signature header as malformed', async () => {
    const signed = await sign();
    const value = signed.headers.Signature.split('=').slice(1).join('=');
    signed.headers.Signature += `, other=${value}`;
    await assert.rejects(() => verify(signed), errors.MalformedSignatureLabel);
  });

  it('refuses a signature that is not 64 bytes as a malformed value', async () => {
    const signed = await sign();
    signed.headers.Signature = `sig=:${Buffer.alloc(32).toString('base64')}:`;
    await assert.rejects(() => verify(signed), errors.MalformedSignatureValue);
  });

  it('finds a Signature member that is not a byte sequence before the labels', async () => {
    const signed = await sign();
    const value = signed.headers['Signature-Input'].split('=').slice(1).join('=');
    signed.headers['Signature-Input'] += `, other=${value}`;
    signed.headers.Signature = 'sig="not bytes"';
    await assert.rejects(() => verify(signed), errors.MalformedSignatureValue);
  });
});

describe("the profile's section 9 order", () => {
  it('reports an unsigned message as missing its signature first', async () => {
    const signed = await sign();
    delete signed.headers.Signature;
    delete signed.headers['Signature-Input'];
    await assert.rejects(() => verify(signed), errors.MissingSignature);
  });

  it('reports an unparsable Signature before an unparsable Signature-Input', async () => {
    const signed = await sign();
    signed.headers.Signature = '((((';
    signed.headers['Signature-Input'] = '((((';
    await assert.rejects(() => verify(signed), errors.MalformedSignature);
  });

  it('reports a malformed key before an unsupported algorithm', async () => {
    const signed = await sign();
    mangle(signed.headers, keyidOf(signed.headers), 'not-a-key');
    mangle(signed.headers, 'alg="ed25519"', 'alg="rsa-pss-sha512"');
    await assert.rejects(() => verify(signed), errors.MalformedKey);
  });

  it('reports staleness before expiry', async () => {
    const signed = await sign({ expires: AT + 10 });
    await assert.rejects(() => verify(signed, { maxAge: 300, skew: 60, now: AT + 1000 }), errors.SignatureTooOld);
  });

  it('reports insufficient coverage before the key', async () => {
    const signed = await sign({ covered: ['@method', '@path', 'content-digest'] });
    mangle(signed.headers, keyidOf(signed.headers), 'not-a-key');
    await assert.rejects(() => verify(signed, { minimum: REQUEST_MINIMUM }), errors.InsufficientCoverage);
  });

  it('reports a missing keyid before the covered list and before the labels', async () => {
    const resolve = table({ [AID]: raw(KEY) });
    const first = await sign({ covered: ['@method', 'content-digest'], keyid: AID });
    mangle(first.headers, `;keyid="${AID}"`, '');
    await assert.rejects(() => verify(first, { resolve, minimum: REQUEST_MINIMUM }), errors.MissingKey);

    const second = await sign({ keyid: AID });
    mangle(second.headers, `;keyid="${AID}"`, '');
    second.headers['Signature-Input'] += `, other=${second.headers['Signature-Input'].split('=').slice(1).join('=')}`;
    await assert.rejects(() => verify(second, { resolve }), errors.MissingKey);
  });

  it('still requires a keyid under a minimum, even when the verifier names the key', async () => {
    // keyid is REQUIRED in the KERI profile, and a minimum is how a caller applies it; expectedAid
    // decides the key, not whether the message is well formed (rust port's hostile review). The
    // message is genuinely signed with no keyid, so nothing but that rule could refuse it.
    const request = { method: 'GET', url: URL_, body: null };
    const base = signatureBase({ ...request, headers: {}, covered: [...REQUEST_MINIMUM], created: AT, alg: 'ed25519' });
    const params = new TextDecoder().decode(base).split('"@signature-params": ')[1];
    assert.ok(!params.includes('keyid'));
    const headers = {
      'Signature-Input': `sig=${params}`,
      Signature: `sig=:${Buffer.from(await KEY.sign(base)).toString('base64')}:`,
    };
    assert.equal((await verify({ request, headers }, { expectedAid: KEY.aid })).aid, KEY.aid);
    await assert.rejects(
      () => verify({ request, headers }, { expectedAid: KEY.aid, minimum: REQUEST_MINIMUM }),
      errors.MissingKey,
    );
  });

  it('needs no keyid when the verifier names the key', async () => {
    const signed = await sign();
    mangle(signed.headers, `;keyid="${keyidOf(signed.headers)}"`, '');
    await assert.rejects(() => verify(signed, { expectedAid: KEY.aid }), errors.SignatureMismatch);
  });
});

describe('the minimum covered set (profile section 3)', () => {
  it("is the profile's", () => {
    assert.deepEqual([...REQUEST_MINIMUM], ['@method', '@path', '@query']);
    assert.deepEqual([...RESPONSE_MINIMUM], ['@status', req('@method'), req('@path'), req('@query')]);
    assert.ok(Object.isFrozen(REQUEST_MINIMUM) && Object.isFrozen(RESPONSE_MINIMUM));
  });

  it('accepts a request covering it', async () => {
    assert.equal((await verify(await sign(), { minimum: REQUEST_MINIMUM })).aid, KEY.aid);
  });

  it('refuses a request covering less, even though it verifies', async () => {
    const signed = await sign({ covered: ['@method', '@path', 'content-digest'] });
    assert.equal((await verify(signed)).aid, KEY.aid);
    await assert.rejects(
      () => verify(signed, { minimum: REQUEST_MINIMUM }),
      (e) => e instanceof errors.InsufficientCoverage && e.component === '@query',
    );
  });

  it('may be named in serialized form', async () => {
    assert.equal((await verify(await sign(), { minimum: ['"@method"', '"@PATH"', '"@query"'] })).aid, KEY.aid);
  });

  for (const [id, extra, body] of [
    ['content-length-above-zero', { 'Content-Length': '18' }, null],
    ['content-length-unreadable', { 'Content-Length': 'many' }, null],
    ['any-transfer-encoding', { 'Transfer-Encoding': 'chunked' }, null],
    ['a-body-that-arrived-anyway', {}, BODY],
    ['a-negative-content-length', { 'Content-Length': '-5' }, null],
    ['a-content-length-with-words', { 'Content-Length': '18 bytes' }, null],
    ['a-signed-content-length', { 'Content-Length': '+3' }, null],
    // Only SP and HTAB are field whitespace; NBSP or a vertical tab is not, so " 0 " so spelled is
    // not a plain decimal, and fails closed (Copilot review of PR #5, C1).
    ['a-zero-wrapped-in-nbsp', { 'Content-Length': '\u00a00\u00a0' }, null],
    ['a-zero-after-a-vertical-tab', { 'Content-Length': '\v0' }, null],
  ]) {
    it(`refuses ${id} without a covered digest`, async () => {
      const signed = await sign({ body: null, headers: extra });
      signed.request.body = body;
      await assert.rejects(
        () => verify(signed, { minimum: REQUEST_MINIMUM }),
        (e) => e instanceof errors.InsufficientCoverage && e.component === 'content-digest',
      );
    });
  }

  it('needs no digest for a bodyless request', async () => {
    assert.equal((await verify(await sign({ method: 'GET', body: null }), { minimum: REQUEST_MINIMUM })).aid, KEY.aid);
  });

  it('treats a zero Content-Length as no body, field whitespace and all', async () => {
    const signed = await sign({ body: null, headers: { 'Content-Length': ' \t00 ' } });
    signed.request.body = new Uint8Array(0);
    assert.equal((await verify(signed, { minimum: REQUEST_MINIMUM })).aid, KEY.aid);
  });

  it('accepts a response covering it', async () => {
    assert.equal((await check(await respond(), { minimum: RESPONSE_MINIMUM })).aid, KEY.aid);
  });

  it('refuses a response missing a req component', async () => {
    const headers = await respond({ covered: ['@status', req('@method'), req('@query'), 'content-digest', req('content-digest')] });
    await assert.rejects(
      () => check(headers, { minimum: RESPONSE_MINIMUM }),
      (e) => e instanceof errors.InsufficientCoverage && e.component === '"@path";req',
    );
  });

  it('refuses a response body without its digest', async () => {
    const headers = await respond({ body: null, headers: { 'Content-Length': '14' } });
    await assert.rejects(
      () => check(headers, { body: RESPONSE_BODY, minimum: RESPONSE_MINIMUM }),
      (e) => e instanceof errors.InsufficientCoverage && e.component === 'content-digest',
    );
  });

  it("refuses a response to a request with a body that does not cover the request's digest", async () => {
    const headers = await respond({ covered: [...RESPONSE_MINIMUM, 'content-digest'] });
    await assert.rejects(
      () => check(headers, { minimum: RESPONSE_MINIMUM }),
      (e) => e instanceof errors.InsufficientCoverage && e.component === '"content-digest";req',
    );
  });

  it("judges a response's request body by content, not headers (@7p9s3g9k)", async () => {
    const chunked = { method: 'POST', url: URL_, headers: { 'Transfer-Encoding': 'chunked', 'Content-Digest': await contentDigest(BODY) } };
    const headers = await respond({ request: chunked, covered: [...RESPONSE_MINIMUM, 'content-digest'] });
    assert.equal((await check(headers, { request: chunked, minimum: RESPONSE_MINIMUM })).aid, KEY.aid);
  });

  it('may add requirements beyond the profile', async () => {
    assert.equal((await verify(await sign(), { minimum: [...REQUEST_MINIMUM, '@authority'] })).aid, KEY.aid);
    const narrow = await sign({ covered: [...REQUEST_MINIMUM, 'content-digest'] });
    await assert.rejects(() => verify(narrow, { minimum: [...REQUEST_MINIMUM, '@authority'] }), errors.InsufficientCoverage);
  });

  for (const minimum of [[], ['@method', '@path'], [req('@method')]]) {
    it(`refuses a request minimum of ${JSON.stringify(minimum)} as a caller error`, async () => {
      const signed = await sign();
      await assert.rejects(() => verify(signed, { minimum }), callerError('A minimum covered set must include the profile\'s own'));
      await assert.rejects(() => sign({ minimum }), callerError('A minimum covered set must include the profile\'s own'));
    });
  }

  for (const minimum of [[], [...REQUEST_MINIMUM], ['@status', req('@method')]]) {
    it(`refuses a response minimum of ${JSON.stringify(minimum)} as a caller error`, async () => {
      const headers = await respond();
      await assert.rejects(() => check(headers, { minimum }), callerError('A minimum covered set must include the profile\'s own'));
      await assert.rejects(() => respond({ minimum }), callerError('A minimum covered set must include the profile\'s own'));
    });
  }
});

describe('the default response covered set (@2f227n4r, @7p9s3g9k)', () => {
  it('does not bind a request body only its headers announce', async () => {
    const asked = { method: 'POST', url: URL_, headers: { 'Content-Length': '18', 'Content-Digest': await contentDigest(BODY) } };
    const verdict = await check(await respond({ request: asked }), { request: asked, minimum: RESPONSE_MINIMUM });
    assert.ok(!verdict.covered.includes(req('content-digest')));
  });

  it('binds the digest of a request with content', async () => {
    const verdict = await check(await respond(), { minimum: RESPONSE_MINIMUM });
    assert.ok(verdict.covered.includes(req('content-digest')));
  });

  it('refuses at signing a request body with no digest to bind', async () => {
    await assert.rejects(() => respond({ request: { method: 'POST', url: URL_, body: BODY } }), errors.UncoveredBody);
  });

  it('gives a HEAD response carrying a Content-Length no body', async () => {
    const head = { method: 'HEAD', url: URL_ };
    const headers = await respond({ request: head, body: null, headers: { 'Content-Length': '898' } });
    const verdict = await check(headers, { request: head, body: null, minimum: RESPONSE_MINIMUM });
    assert.ok(!verdict.covered.includes('content-digest'));
  });
});

describe('signers given a minimum (@2f227n4r)', () => {
  it('refuse a covered list below it', async () => {
    await assert.rejects(() => sign({ body: null, covered: ['@method', '@path'], minimum: REQUEST_MINIMUM }), errors.InsufficientCoverage);
    const signed = await sign({ minimum: REQUEST_MINIMUM });
    assert.equal((await verify(signed, { minimum: REQUEST_MINIMUM })).aid, KEY.aid);
  });

  it('refuse a body they would not cover', async () => {
    await assert.rejects(
      () => sign({ body: null, headers: { 'Transfer-Encoding': 'chunked' }, minimum: REQUEST_MINIMUM }),
      errors.InsufficientCoverage,
    );
  });

  it('refuse a response covered list below it', async () => {
    await assert.rejects(() => respond({ covered: ['@status', 'content-digest'], minimum: RESPONSE_MINIMUM }), errors.InsufficientCoverage);
    assert.equal((await check(await respond({ minimum: RESPONSE_MINIMUM }), { minimum: RESPONSE_MINIMUM })).aid, KEY.aid);
  });
});

describe('served authorities (profile section 3)', () => {
  it('refuses a covered authority outside the served set as a signature mismatch', async () => {
    const signed = await sign({ url: '/identifiers', headers: { Host: 'other.example.com' } });
    assert.equal((await verify(signed, { authorities: ['other.example.com'] })).aid, KEY.aid);
    await assert.rejects(() => verify(signed, { authorities: new Set(['keria.example.com']) }), errors.SignatureMismatch);
  });

});

describe('supplying authorities makes @authority required (@605z9tnw, tick 7zde)', () => {
  it('refuses a request signed for another host without @authority, the cross-host replay', async () => {
    const signed = await sign({
      method: 'GET', url: 'https://attacker.example/identifiers?type=rot', body: null,
      covered: [...REQUEST_MINIMUM], minimum: REQUEST_MINIMUM,
    });
    signed.request.url = 'https://victim.example/identifiers?type=rot';
    await assert.rejects(
      () => verify(signed, { minimum: REQUEST_MINIMUM, authorities: ['victim.example'] }),
      (error) => error instanceof errors.InsufficientCoverage && error.component === '@authority',
    );
  });

  it('leaves an uncovered @authority alone when no authorities are supplied', async () => {
    const signed = await sign({ covered: ['@method', '@path', '@query', 'content-digest'] });
    assert.equal((await verify(signed)).aid, KEY.aid);
  });

  it('refuses before the key is resolved, as section 9 orders', async () => {
    const signed = await sign({ covered: ['@method', '@path', '@query', 'content-digest'], keyid: AID });
    await assert.rejects(
      () => verify(signed, { resolve: table({}), authorities: ['keria.example.com'] }),
      errors.InsufficientCoverage,
    );
  });

  it('verifies a covered @authority for the right host and refuses the wrong one', async () => {
    const signed = await sign({
      method: 'GET', url: 'https://victim.example/identifiers', body: null, covered: [...REQUEST_MINIMUM, '@authority'],
    });
    assert.equal((await verify(signed, { authorities: ['victim.example'] })).aid, KEY.aid);
    await assert.rejects(() => verify(signed, { authorities: ['attacker.example'] }), errors.SignatureMismatch);
  });
});

describe('a base that cannot be built (@2f227n4r)', () => {
  for (const value of ['café', 'two\nlines', 'bell\x07']) {
    it(`is a signature mismatch for ${JSON.stringify(value)}`, async () => {
      const signed = await sign({ headers: { 'X-Note': 'plain' }, covered: ['@method', '@path', '@query', 'x-note', 'content-digest'] });
      signed.headers['X-Note'] = value;
      await assert.rejects(() => verify(signed), errors.SignatureMismatch);
      assert.throws(
        () => signatureBase({ method: 'GET', url: URL_, headers: { 'X-Note': value }, covered: ['x-note'], created: AT, keyid: 'k' }),
        errors.SignatureMismatch,
      );
    });
  }

  for (const value of ['admin\r\n', '\r\nadmin', '\nadmin', 'admin\r', 'admin\0', '\0admin', ' admin\r\n ', 'admin\v', 'admin\f', 'admin\u00a0']) {
    it(`refuses ${JSON.stringify(value)} rather than trimming it to the signed "admin"`, async () => {
      // The forbidden-character check runs on the value as received; only SP and HTAB are field
      // whitespace (RFC 9110 section 5.5), so nothing else may be trimmed away before it.
      const signed = await sign({ headers: { 'X-Role': 'admin' }, covered: ['@method', '@path', '@query', 'x-role', 'content-digest'] });
      signed.headers['X-Role'] = value;
      await assert.rejects(() => verify(signed), errors.SignatureMismatch);
      assert.throws(
        () => signatureBase({ method: 'GET', url: URL_, headers: { 'X-Role': value }, covered: ['x-role'], created: AT, keyid: 'k' }),
        errors.SignatureMismatch,
      );
    });
  }

  it('trims only SP and HTAB from a field value, as RFC 9110 field OWS', async () => {
    const signed = await sign({ headers: { 'X-Role': 'admin' }, covered: ['@method', '@path', '@query', 'x-role', 'content-digest'] });
    signed.headers['X-Role'] = ' \t admin\t ';
    assert.equal((await verify(signed)).aid, KEY.aid);
    const base = signatureBase({ method: 'GET', url: '/f', headers: { Host: ' \tEXAMPLE.com ' }, covered: ['@authority'], created: AT, keyid: 'k' });
    assert.equal(new TextDecoder().decode(base).split('\n')[0], '"@authority": example.com');
    assert.throws(
      () => signatureBase({ method: 'GET', url: '/f', headers: { Host: 'example.com\r\n' }, covered: ['@authority'], created: AT, keyid: 'k' }),
      errors.SignatureMismatch,
    );
  });

  it('still builds with a tab in a field value', async () => {
    const signed = await sign({ headers: { 'X-Note': 'a\tb' }, covered: ['@method', '@path', '@query', 'x-note', 'content-digest'] });
    assert.equal((await verify(signed)).aid, KEY.aid);
  });
});

describe('created under a minimum (@7p9s3g9k)', () => {
  async function withoutCreated() {
    const signed = await sign();
    signed.headers['Signature-Input'] = signed.headers['Signature-Input'].replace(`;created=${AT}`, '');
    return signed;
  }

  it('is required as part of Signature-Input', async () => {
    await assert.rejects(async () => verify(await withoutCreated(), { minimum: REQUEST_MINIMUM }), errors.MalformedSignatureInput);
  });

  it('is reported missing before the covered list', async () => {
    const signed = await withoutCreated();
    mangle(signed.headers, '"@path"', '"@path" "@path"');
    await assert.rejects(() => verify(signed, { minimum: REQUEST_MINIMUM }), errors.MalformedSignatureInput);
  });

  it('stays optional without a minimum, as RFC 9421 makes it', async () => {
    await assert.rejects(async () => verify(await withoutCreated()), errors.SignatureMismatch);
  });
});

describe('a covered "content-digest";req is recomputed over the request body', () => {
  const covered = [...RESPONSE_MINIMUM, req('content-digest'), 'content-digest'];
  const swapped = { ...REQUEST, body: new TextEncoder().encode('{"hello": "mallory"}') };
  const unread = { method: 'POST', url: URL_, headers: { 'Content-Digest': '((((' } };
  const odd = { ...unread, body: BODY };

  it('refuses a swapped request body', async () => {
    await assert.rejects(async () => check(await respond(), { request: swapped }), errors.DigestMismatch);
  });

  it('refuses an unreadable request digest as malformed', async () => {
    const headers = await respond({ request: unread, covered });
    await assert.rejects(() => check(headers, { request: odd }), errors.MalformedDigest);
  });

  it('ranks a malformed request digest above a mismatched response digest', async () => {
    const headers = await respond({ request: unread, covered });
    await assert.rejects(() => check(headers, { request: odd, body: new TextEncoder().encode('{"done": false}') }), errors.MalformedDigest);
  });

  it('is checked by the signer too, so it never vouches for a digest its body contradicts', async () => {
    await assert.rejects(() => respond({ request: swapped }), errors.DigestMismatch);
    await assert.rejects(() => respond({ request: odd }), errors.MalformedDigest);
    const empty = { ...REQUEST, body: new Uint8Array(0) };
    await assert.rejects(() => respond({ request: empty, covered }), errors.DigestMismatch);
  });

  it('is refused at signing when the request carries no digest to bind', async () => {
    // The signer reads the request's digest before the base, so the absence is a malformed digest
    // there rather than a missing component, as in fiki-py.
    await assert.rejects(() => respond({ request: { method: 'POST', url: URL_, body: BODY }, covered }), errors.MalformedDigest);
  });

  it('is a caller error to verify without the request body it binds', async () => {
    const bodiless = { method: REQUEST.method, url: REQUEST.url, headers: REQUEST.headers };
    await assert.rejects(async () => check(await respond(), { request: bodiless }), callerError('so the request body it binds must be supplied in request.body'));
  });
});
