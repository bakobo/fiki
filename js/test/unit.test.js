// The ground the shared vectors do not cover.
//
// The vectors pin what every port must agree on: bases, signatures, refusal classes. They say
// nothing about signing a fresh request, generating a key, or the parser's own error branches,
// because those are not cross-implementation contracts — they are this port working. So they are
// tested here, at the same 100% branch gate the Python port holds.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  DEFAULT_COVERED,
  Key,
  contentDigest,
  errors,
  signRequest,
  signatureBase,
  toAid,
  verifyRequest,
  verifyingKey,
} from '../src/index.js';
import { parseDictionary, serializeInnerList } from '../src/sfv.js';

const SEED = Uint8Array.from({ length: 32 }, (_, i) => i);
const AID = 'BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4';
const URL_WITH_QUERY = 'https://api.example.com/things?limit=1&sort=name';
const BODY = new TextEncoder().encode('{"hello": "world"}');
const SIGNED_AT = 1700000000;

const key = await Key.fromSeed(SEED);

async function signed(overrides = {}) {
  const args = { key, method: 'POST', url: URL_WITH_QUERY, headers: {}, body: BODY, created: SIGNED_AT, ...overrides };
  const headers = { ...(args.headers ?? {}), ...(await signRequest(args)) };
  return { request: { method: args.method, url: args.url, body: args.body }, headers };
}

describe('keys', () => {
  it('derives the AID keripy produces for the same seed', () => {
    assert.equal(key.aid, AID);
  });

  it('generates a distinct key each time, non-extractable by default', async () => {
    const a = await Key.generate();
    const b = await Key.generate();
    assert.notEqual(a.aid, b.aid);
    assert.equal(a.aid.length, 44);
    assert.throws(() => a.seed, errors.MalformedKey);
  });

  it('hands back a seed only when the caller asked for a portable identity', async () => {
    const portable = await Key.generate({ extractable: true });
    assert.equal(portable.seed.length, 32);
    assert.equal((await Key.fromSeed(portable.seed)).aid, portable.aid);
  });

  it('keeps the seed of an extractable fromSeed key', async () => {
    const portable = await Key.fromSeed(SEED, { extractable: true });
    assert.deepEqual(portable.seed, SEED);
  });

  it('refuses a seed of the wrong length', async () => {
    await assert.rejects(() => Key.fromSeed(new Uint8Array(31)), errors.MalformedKey);
    await assert.rejects(() => Key.fromSeed('not bytes'), errors.MalformedKey);
  });

  for (const [id, aid] of [
    ['too short', 'B' + 'A'.repeat(42)],
    ['too long', 'B' + 'A'.repeat(44)],
    ['transferable prefix', 'D' + 'A'.repeat(43)],
    ['not a string', 42],
    // "=" is inside base64's alphabet, so a 44-character string of the right shape still decodes
    // short. A decoder is exactly the place a quiet shortfall turns into somebody else's error.
    ['padded, decodes short', 'B' + 'A'.repeat(41) + '=='],
    ['outside the alphabet', 'B' + '!'.repeat(43)],
  ]) {
    it(`refuses an AID that is ${id}`, () => {
      assert.throws(() => verifyingKey(aid), errors.MalformedKey);
    });
  }

  it('round-trips a raw key through the lens', () => {
    assert.equal(toAid(verifyingKey(AID)), AID);
  });
});

describe('the signature base', () => {
  const line = (component, overrides = {}) =>
    new TextDecoder()
      .decode(
        signatureBase({
          method: 'POST',
          url: URL_WITH_QUERY,
          headers: {},
          covered: [component],
          created: SIGNED_AT,
          keyid: 'k',
          ...overrides,
        }),
      )
      .split('\n')[0];

  it('takes the authority from the Host header when the URL is relative', () => {
    assert.equal(line('@authority', { url: '/things', headers: { Host: 'API.example.com' } }), '"@authority": api.example.com');
  });

  it('refuses @authority with neither a URL authority nor a Host header', () => {
    assert.throws(() => line('@authority', { url: '/things' }), errors.MissingComponent);
  });

  it('omits a default port and keeps a non-default one', () => {
    assert.equal(line('@authority', { url: 'https://EXAMPLE.com:443/f' }), '"@authority": example.com');
    assert.equal(line('@authority', { url: 'https://example.com:8443/f' }), '"@authority": example.com:8443');
  });

  it('treats an empty path as the slash the origin server sees', () => {
    assert.equal(line('@path', { url: 'https://example.com' }), '"@path": /');
  });

  it('binds "no query" as a bare question mark', () => {
    assert.equal(line('@query', { url: 'https://example.com/f' }), '"@query": ?');
  });

  it('uppercases the method and lowercases header names', () => {
    assert.equal(line('@method', { method: 'post' }), '"@method": POST');
    assert.equal(line('Content-Type', { headers: { 'Content-Type': '  application/json  ' } }), '"content-type": application/json');
  });

  it('refuses a derived component it cannot build, rather than skipping it', () => {
    assert.throws(() => line('@target-uri'), errors.UnsupportedComponent);
  });

  it('refuses a covered header the request lacks', () => {
    assert.throws(() => line('x-absent'), errors.MissingComponent);
  });

  it('serializes the optional parameters in a fixed order', () => {
    const base = new TextDecoder().decode(
      signatureBase({
        method: 'POST', url: 'https://example.com/f', headers: {}, covered: ['@method'],
        created: SIGNED_AT, keyid: 'k', alg: 'ed25519', expires: SIGNED_AT + 60, nonce: 'abc', tag: 'app',
      }),
    );
    assert.equal(
      base.split('\n').at(-1),
      `"@signature-params": ("@method");created=${SIGNED_AT};expires=${SIGNED_AT + 60};nonce="abc";alg="ed25519";keyid="k";tag="app"`,
    );
  });
});

describe('signing and verifying', () => {
  it('round-trips and names the signer', async () => {
    const { request, headers } = await signed();
    const verdict = await verifyRequest({ ...request, headers, maxAge: null });
    assert.equal(verdict.aid, AID);
    for (const component of DEFAULT_COVERED) assert.ok(verdict.covered.includes(component));
  });

  it('carries the raw key in keyid rather than the AID', async () => {
    const { headers } = await signed();
    const keyid = headers['Signature-Input'].split('keyid="')[1].split('"')[0];
    assert.equal(keyid.length, 43);
  });

  it('digests a body and covers the digest', async () => {
    const { request, headers } = await signed();
    assert.ok(headers['Content-Digest']);
    const verdict = await verifyRequest({ ...request, headers, maxAge: null });
    assert.ok(verdict.covered.includes('content-digest'));
  });

  it('uses a caller-supplied Content-Digest rather than recomputing it', async () => {
    const supplied = { 'Content-Digest': await contentDigest(BODY) };
    const { request, headers } = await signed({ headers: supplied });
    assert.equal(headers['Content-Digest'], supplied['Content-Digest']);
    assert.equal((await verifyRequest({ ...request, headers, maxAge: null })).aid, AID);
  });

  it('refuses to sign a body under a chosen covered set that omits the digest', async () => {
    await assert.rejects(
      () => signRequest({ key, method: 'POST', url: URL_WITH_QUERY, headers: {}, body: BODY, covered: ['@method'] }),
      errors.UncoveredBody,
    );
  });

  it('signs a body under a chosen covered set that includes the digest', async () => {
    const { request, headers } = await signed({ covered: ['@method', '@path', 'content-digest'] });
    assert.equal((await verifyRequest({ ...request, headers, maxAge: null })).aid, AID);
  });

  it('needs no digest for a bodyless request', async () => {
    const { request, headers } = await signed({ body: null });
    assert.equal(headers['Content-Digest'], undefined);
    assert.equal((await verifyRequest({ ...request, headers, maxAge: null })).aid, AID);
  });

  it('uses the wall clock when no created is given', async () => {
    const { request, headers } = await signed({ created: null });
    assert.equal((await verifyRequest({ ...request, headers, maxAge: 300 })).aid, AID);
  });

  it('treats an expected AID as authoritative over the inline keyid', async () => {
    const { request, headers } = await signed();
    assert.equal((await verifyRequest({ ...request, headers, expectedAid: AID, maxAge: null })).aid, AID);
    const stranger = (await Key.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i + 1))).aid;
    await assert.rejects(
      () => verifyRequest({ ...request, headers, expectedAid: stranger, maxAge: null }),
      errors.SignatureMismatch,
    );
  });

  it('refuses a request with no freshness policy stated at all', async () => {
    const { request, headers } = await signed();
    await assert.rejects(() => verifyRequest({ ...request, headers }), TypeError);
  });

  it('refuses a digest naming only algorithms it cannot compute', async () => {
    const { request, headers } = await signed({ headers: { 'Content-Digest': 'sha-1=:AAAA:' } });
    await assert.rejects(() => verifyRequest({ ...request, headers, maxAge: null }), errors.MalformedDigest);
  });

  it('accepts a digest naming an unknown algorithm alongside one it knows', async () => {
    const supplied = { 'Content-Digest': `sha-1=:AAAA:, ${await contentDigest(BODY)}` };
    const { request, headers } = await signed({ headers: supplied });
    assert.equal((await verifyRequest({ ...request, headers, maxAge: null })).aid, AID);
  });
});

describe('freshness', () => {
  it('accepts a signature inside max age and refuses one outside it', async () => {
    const { request, headers } = await signed();
    assert.equal((await verifyRequest({ ...request, headers, maxAge: 300, now: SIGNED_AT + 299 })).aid, AID);
    await assert.rejects(
      () => verifyRequest({ ...request, headers, maxAge: 300, now: SIGNED_AT + 400 }),
      errors.SignatureTooOld,
    );
  });

  it('tolerates skew, and lets the allowance be tightened', async () => {
    const { request, headers } = await signed();
    assert.equal((await verifyRequest({ ...request, headers, maxAge: 300, now: SIGNED_AT + 303 })).aid, AID);
    await assert.rejects(
      () => verifyRequest({ ...request, headers, maxAge: 300, skew: 0, now: SIGNED_AT + 301 }),
      errors.SignatureTooOld,
    );
  });

  it('refuses a created in the future beyond the skew allowance', async () => {
    const { request, headers } = await signed();
    await assert.rejects(
      () => verifyRequest({ ...request, headers, maxAge: 300, now: SIGNED_AT - 60 }),
      errors.SignatureTooOld,
    );
  });

  it('enforces the signer\'s own expires even when max age is declined', async () => {
    const { request, headers } = await signed({ expires: SIGNED_AT + 60 });
    assert.equal((await verifyRequest({ ...request, headers, maxAge: null, now: SIGNED_AT + 30 })).aid, AID);
    await assert.rejects(
      () => verifyRequest({ ...request, headers, maxAge: null, now: SIGNED_AT + 66 }),
      errors.SignatureExpired,
    );
  });

  it('refuses a max-age check against a signature carrying no created', async () => {
    // RFC 9421 makes created optional, so a foreign signer may omit it. fiki's own never does,
    // and the signature has to be genuinely made this way — freshness is checked after the
    // signature, so a doctored Signature-Input just fails the signature instead.
    const covered = ['@method', '@path'];
    const inner = { items: covered, params: new Map([['keyid', key.keyid]]) };
    const { componentLines } = await import('../src/base.js');
    const lines = componentLines({ method: 'GET', url: '/a', headers: {}, covered });
    lines.push(`"@signature-params": ${serializeInnerList(inner)}`);
    const signature = await key.sign(new TextEncoder().encode(lines.join('\n')));
    const headers = {
      'Signature-Input': `sig=${serializeInnerList(inner)}`,
      Signature: `sig=:${Buffer.from(signature).toString('base64')}:`,
    };
    assert.equal((await verifyRequest({ method: 'GET', url: '/a', headers, maxAge: null })).aid, AID);
    await assert.rejects(
      () => verifyRequest({ method: 'GET', url: '/a', headers, maxAge: 300, now: SIGNED_AT }),
      errors.SignatureTooOld,
    );
  });
});

describe('the structured-fields subset', () => {
  it('round-trips what RFC 9421 puts in Signature-Input', () => {
    const parsed = parseDictionary('sig=("@method" "@path");created=1;keyid="k";alg="ed25519"');
    assert.equal(
      serializeInnerList(parsed.get('sig')),
      '("@method" "@path");created=1;keyid="k";alg="ed25519"',
    );
  });

  it('reads the shapes RFC 8941 allows here', () => {
    assert.equal(parseDictionary('a=?1, b=?0').get('a').value, true);
    assert.equal(parseDictionary('a=?0').get('a').value, false);
    assert.equal(parseDictionary('a=-12').get('a').value, -12);
    assert.equal(parseDictionary('a').get('a').value, true);
    assert.equal(parseDictionary('a;x').get('a').params.get('x'), true);
    assert.equal(parseDictionary('a="say \\"hi\\" \\\\"').get('a').value, 'say "hi" \\');
    assert.deepEqual([...parseDictionary('a=()').get('a').items], []);
    assert.equal(parseDictionary('  a=1  ').get('a').value, 1);
  });

  it('escapes on the way back out', () => {
    assert.equal(
      serializeInnerList({ items: ['a"b\\c'], params: new Map([['f', true], ['g', false]]) }),
      '("a\\"b\\\\c");f;g=?0',
    );
  });

  for (const [id, text] of [
    ['a key that does not start a key', '1=2'],
    ['an unterminated string', 'a="oops'],
    ['a bad escape', 'a="o\\ps"'],
    ['a byte sequence that is not base64', 'a=:not base64!:'],
    ['an unterminated byte sequence', 'a=:AAAA'],
    ['a bad boolean', 'a=?2'],
    ['an item of no supported type', 'a=%bad'],
    ['an unterminated inner list', 'a=("@method"'],
    ['parameters on a covered component', 'a=("@method";q=1)'],
    ['a missing separator inside an inner list', 'a=("@method""@path")'],
    ['a missing comma between members', 'a=1 b=2'],
    ['a trailing comma', 'a=1, '],
    ['an integer that is not one', 'a=-'],
  ]) {
    it(`refuses ${id}`, () => {
      assert.throws(() => parseDictionary(text));
    });
  }
});

describe('the defensive arms', () => {
  // Six branches that only fire when a caller omits something optional. They are cheap to reach
  // and expensive to leave untested: an untaken arm in a parser or a header walk is where a
  // "cannot happen" turns into somebody else's exception.

  it('builds a base for a request with no headers at all', () => {
    const base = signatureBase({
      method: 'GET', url: 'https://example.com/f', covered: ['@method'], created: 1, keyid: 'k',
    });
    assert.equal(new TextDecoder().decode(base).split('\n')[0], '"@method": GET');
  });

  it('signs a request with no headers at all', async () => {
    const headers = await signRequest({ key, method: 'GET', url: 'https://example.com/f', created: 1 });
    assert.ok(headers['Signature-Input'].startsWith('sig=('));
  });

  it('signs a body on a request with no headers at all, and returns the digest it made', async () => {
    const headers = await signRequest({
      key, method: 'POST', url: 'https://example.com/f', body: BODY, created: 1,
    });
    assert.ok(headers['Content-Digest'].startsWith('sha-256=:'));
    const verdict = await verifyRequest({
      method: 'POST', url: 'https://example.com/f', headers, body: BODY, maxAge: null,
    });
    assert.equal(verdict.aid, AID);
  });

  it('refuses to verify a request with no headers at all', async () => {
    await assert.rejects(
      () => verifyRequest({ method: 'GET', url: '/f', maxAge: null }),
      errors.MissingSignatureInput,
    );
  });

  it('refuses a parameter name that runs off the end of the field', () => {
    assert.throws(() => parseDictionary('a;'));
  });

  it('refuses a member whose value runs off the end of the field', () => {
    assert.throws(() => parseDictionary('a='));
  });
});
