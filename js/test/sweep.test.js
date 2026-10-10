// The 0.8.0 cross-port sweep: every port gives the same answer to the same input (@5zrf8gjk).
//
// One describe block per rule of the sweep, numbered as the spec numbers them and in the order of
// fiki-py's tests/test_sweep.py, so the two suites can be read side by side. Caller errors are
// tested here and not in the vectors, because they are API behaviour; in this port a caller error
// is a TypeError and never a FikiError. Everything a vector can pin is also in vectors/.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

import * as fiki from '../src/index.js';
import {
  Key,
  REQUEST_MINIMUM,
  contentDigest,
  errors,
  req,
  responseSignatureBase,
  signRequest,
  signResponse,
  signatureBase,
  verifyRequest,
  verifyResponse,
} from '../src/index.js';
import { parseDictionary } from '../src/sfv.js';
import { callerError } from './caller.js';

// Format 3 made the verifier's default minimum fiki's own signing default and authorities a
// required decision (@524c8qgv). These tests predate both and are about other things, so they
// state the 0.8 policy explicitly — no minimum, no authority check — and a test that wants either
// says so after it.
const POLICY = { minimum: null, authorities: null };

const KEY = await Key.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i));
const URL_ = 'https://api.example.com/things?limit=1';
const BODY = new TextEncoder().encode('{"hello": "world"}');
const AT = 1700000000;
const BASE_ARGS = { created: AT, keyid: 'k' };
const DIGEST = await contentDigest(BODY);

async function sign(overrides = {}) {
  const args = { key: KEY, method: 'GET', url: URL_, headers: {}, body: null, created: AT, ...overrides };
  const headers = { ...args.headers, ...(await signRequest(args)) };
  return [{ method: args.method, url: args.url, body: args.body }, headers];
}

const verify = (request, headers, overrides = {}) =>
  verifyRequest({ ...POLICY, headers, maxAge: null, now: AT, ...request, ...overrides });

/** A POST validly signed over a Content-Digest of the caller's spelling.
 *
 * Built from the base rather than through signRequest, which refuses to sign a digest it cannot
 * check against the body (A7), so a test can hand the verifier a header the signer would refuse.
 */
async function withDigest(digest) {
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
  return [{ method: 'POST', url: URL_, body: BODY }, headers];
}

const authority = (url) =>
  new TextDecoder().decode(signatureBase({ method: 'GET', url, headers: {}, covered: ['@authority'], ...BASE_ARGS })).split('\n')[0].split(': ')[1];

const cesr = (code, bytes) => code + Buffer.concat([Buffer.alloc(1), Buffer.from(bytes)]).toString('base64url').slice(1);
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const flipPadBit = (aid) => aid[0] + ALPHABET[ALPHABET.indexOf(aid[1]) ^ 16] + aid.slice(2);


describe('A3: an IP-literal keeps its brackets, and only :port may follow "]"', () => {
  for (const [url, expected] of [
    ['https://[2001:db8::1]:8443/x', '[2001:db8::1]:8443'],
    ['https://[2001:DB8::1]/x', '[2001:db8::1]'],
    ['https://[v1.example]:81/x', '[v1.example]:81'],
  ]) {
    it(`${url} has the authority ${expected}`, () => assert.equal(authority(url), expected));
  }

  for (const url of ['https://[::1]x/things', 'https://[::1]:443x/things', 'https://[::1/things', 'https://::1]/things', 'https://a]b/x']) {
    it(`${url} is a caller error when signing`, () => assert.throws(() => authority(url), callerError('cannot be read:')));
  }

  for (const url of ['https://[::1]x/things', 'https://[::1/things']) {
    it(`${url} is a signature mismatch when verifying`, async () => {
      const [request, headers] = await sign({ url: 'https://[::1]/things' });
      await assert.rejects(verify({ ...request, url }, headers), errors.SignatureMismatch);
    });
  }
});

describe('A3: what sits between an IP-literal\'s brackets is an IPv6 address or IPvFuture', () => {
  // The same lists as fiki-py's tests/test_sweep.py, whose oracle is Python's own ipaddress.
  const notAddresses = ['not-an-ip', '1.2.3.4', 'vZ.x', 'v1.', 'V1.x', 'v.x', '::1%', 'fe80::1%a%b',
    '1:2:3:4:5:6:7:8:9', '::01.2.3.4', '::256.1.1.1', '12345::', '', '1::2::3'];
  for (const inside of notAddresses) {
    it(`[${inside}] is a caller error when signing`, () =>
      assert.throws(() => authority(`https://[${inside}]/x`), callerError('its IP-literal is not an IPv6 address or IPvFuture')));
    it(`[${inside}] is a signature mismatch when verifying`, async () => {
      const [request, headers] = await sign({ url: 'https://[::1]/x' });
      await assert.rejects(verify({ ...request, url: `https://[${inside}]/x` }, headers), errors.SignatureMismatch);
    });
  }
  for (const inside of ['::1', '::', '1::', '2001:DB8::1', '1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7::', '::ffff:1.2.3.4',
    '1:2:3:4:5:6:1.2.3.4', 'fe80::1%25eth0', 'v1.x', 'vF.a:b', 'v12.[']) {
    it(`[${inside}] is an IP-literal`, () => assert.equal(authority(`https://[${inside}]/x`), `[${inside.toLowerCase()}]`));
  }
});

describe('B14: a port of thousands of digits is read without converting them', () => {
  const zeros = '0'.repeat(5000);
  it('5,000 leading zeros before 443 are the https default', async () => {
    assert.equal(authority(`https://a.example:${zeros}443/x`), 'a.example');
    assert.equal(authority(`https://a.example:${zeros}8443/x`), 'a.example:8443');
    const [request, headers] = await sign({ url: 'https://a.example:443/x' });
    assert.equal((await verify({ ...request, url: `https://a.example:${zeros}443/x` }, headers)).aid, KEY.aid);
  });
  for (const port of [`${zeros}65536`, `1${zeros}`, '9'.repeat(5000)]) {
    it(`a port of ${port.length} digits is out of range`, async () => {
      assert.throws(() => authority(`https://a.example:${port}/x`), callerError('is not a number from 0 to 65535'));
      const [request, headers] = await sign({ url: 'https://a.example/x' });
      await assert.rejects(verify({ ...request, url: `https://a.example:${port}/x` }, headers), errors.SignatureMismatch);
    });
  }
});

describe('A4: header values are strings, and a field is named once', () => {
  for (const headers of [{ 'x-a': null }, { 'x-a': undefined }, { 'x-a': 1 }, { 'x-a': ['1'] }]) {
    it(`${JSON.stringify(headers)} is a caller error on sign and verify`, async () => {
      await assert.rejects(sign({ headers }), callerError('A header is a name and a string value'));
      await assert.rejects(verifyRequest({ ...POLICY, method: 'GET', url: URL_, headers, maxAge: null }), callerError('A header is a name and a string value'));
    });
  }

  it('two names equal case-insensitively are a caller error, whatever the first value', async () => {
    await assert.rejects(sign({ headers: { 'X-A': '', 'x-a': '1' } }), callerError('twice in different case, so it holds two values for one field'));
    await assert.rejects(verifyRequest({ ...POLICY, method: 'GET', url: URL_, headers: { 'X-A': '1', 'x-a': '1' }, maxAge: null }), callerError('twice in different case, so it holds two values for one field'));
  });
});

/** The least time over several interleaved trials of each shape, so a slow or loaded runner, which
 * slows every trial alike, changes no ratio, and one descheduled trial changes no minimum. */
function fastest(shapes, parse, { trials = 9, reps = 40 } = {}) {
  const best = shapes.map(() => Infinity);
  for (let trial = 0; trial < trials; trial += 1) {
    shapes.forEach((text, i) => {
      const start = performance.now();
      for (let rep = 0; rep < reps; rep += 1) parse(text);
      best[i] = Math.min(best[i], performance.now() - start);
    });
  }
  return best;
}

describe('A6: parsing the signature headers is linear', () => {
  // Compared by ratio rather than against a clock (tick 7xbw): the time at four times the size must
  // stay well under the sixteen times a quadratic parse would take. Absolute time failed on a
  // loaded machine and passed a quadratic parse on a fast one.
  const QUADRATIC = 16;
  const shapes = (n) => [
    // One component whose name is most of the field.
    `sig=("${'a'.repeat(n * 118)}")`,
    // n components, each with sixteen distinct parameters.
    `sig=(${Array.from({ length: n }, (_, i) => `"c${i}"${Array.from({ length: 16 }, (_, j) => `;k${j}`).join('')}`).join(' ')})`,
  ];

  it('takes well under four times as long again at four times the size', () => {
    const small = shapes(16);
    const large = shapes(64);
    for (const text of large) assert.ok(new TextEncoder().encode(text).length <= fiki.MAX_FIELD_BYTES, text.length);
    for (const [i, text] of large.entries()) assert.ok(text.length > 3 * small[i].length, `${text.length} vs ${small[i].length}`);
    const times = fastest([...small, ...large], parseDictionary);
    for (let i = 0; i < small.length; i += 1) {
      const ratio = times[small.length + i] / times[i];
      assert.ok(ratio < QUADRATIC / 2, `shape ${i}: ${times[small.length + i].toFixed(2)} ms at 4N against ${times[i].toFixed(2)} ms at N, a ratio of ${ratio.toFixed(1)}`);
    }
  });

  it('refuses an over-long inner list without reading it to its end (@5zrf8gjk)', () => {
    // The item bound is enforced as the parse reaches it, so the work stops at the 65th item and
    // does not grow with what follows: four times the input takes about the same time, where
    // reading to the end would take four times as long.
    const list = (n) => `sig=(${Array(n).fill('"a"').join(' ')})`;
    const [short, long] = [list(20_000), list(80_000)];
    for (const text of [short, long]) assert.throws(() => parseDictionary(text), /more than 64 items/);
    const [n, n4] = fastest([short, long], (text) => {
      try {
        parseDictionary(text);
      } catch {
        // the refusal is the point
      }
    }, { reps: 200 });
    assert.ok(n4 / n < 2, `${n4.toFixed(2)} ms at 4N against ${n.toFixed(2)} ms at N, a ratio of ${(n4 / n).toFixed(1)}`);
  });
});

describe('A7: a supplied Content-Digest must match the body it is signed with', () => {
  for (const digest of ['sha-256=:AAAA:', 'x-unknown=:AAAA:', 'not a dictionary (((']) {
    it(`${digest} is a caller error on sign`, async () => {
      await assert.rejects(sign({ method: 'POST', body: BODY, headers: { 'Content-Digest': digest } }), callerError('The Content-Digest supplied with this body is not one a verifier would accept'));
      await assert.rejects(
        signResponse({ key: KEY, status: 200, body: BODY, headers: { 'content-digest': digest }, created: AT }),
        callerError('The Content-Digest supplied with this body is not one a verifier would accept'),
      );
    });
  }

  it('a digest of another body is a caller error on sign', async () => {
    const digest = await contentDigest(new TextEncoder().encode('another body'));
    await assert.rejects(sign({ method: 'POST', body: BODY, headers: { 'Content-Digest': digest } }), callerError('The Content-Digest supplied with this body is not one a verifier would accept'));
  });

  it('a supplied digest that matches is signed as given', async () => {
    const digest = `x-unknown=:AAAA:, ${DIGEST}`;
    const [request, headers] = await sign({ method: 'POST', body: BODY, headers: { 'Content-Digest': digest } });
    assert.equal(headers['Content-Digest'], digest);
    assert.equal((await verify(request, headers)).aid, KEY.aid);
  });
});

describe('A8: Content-Length is trimmed of SP and HTAB only', () => {
  for (const length of ['0 ', '0\x0b', '0\x0c', ' 0']) {
    it(`${JSON.stringify(length)} counts as a body`, async () => {
      const [request, headers] = await sign({ headers: { 'Content-Length': length } });
      await assert.rejects(verify(request, headers, { minimum: REQUEST_MINIMUM }), errors.InsufficientCoverage);
    });
  }

  it('SP and HTAB around a zero leave it zero', async () => {
    const [request, headers] = await sign({ headers: { 'Content-Length': ' \t0\t ' } });
    assert.equal((await verify(request, headers, { minimum: REQUEST_MINIMUM })).aid, KEY.aid);
  });
});

describe('A9: a lookup keyed by untrusted input never reaches Object.prototype', () => {
  it('a header named __proto__ or constructor is a header like any other', async () => {
    const fields = JSON.parse('{"__proto__": "a", "constructor": "b"}');
    const [request, headers] = await sign({ headers: fields, covered: ['@method', '__proto__', 'constructor'] });
    assert.deepEqual((await verify(request, headers)).covered, ['@method', '__proto__', 'constructor']);
  });

  it('a digest algorithm named constructor is an unknown algorithm, not a function', async () => {
    assert.equal((await verify(...(await withDigest(`constructor=:AAAA:, ${DIGEST}`)))).aid, KEY.aid);
    await assert.rejects(verify(...(await withDigest('constructor=:AAAA:'))), errors.MalformedDigest);
  });

  it('a signature parameter named constructor is unknown', async () => {
    const [request, headers] = await sign();
    headers['Signature-Input'] += ';constructor=1';
    await assert.rejects(verify(request, headers), errors.MalformedSignatureInput);
  });

  it('a scheme named constructor has no default port', () => {
    assert.equal(authority('constructor://a.example:80/x'), 'a.example:80');
  });

  it('a label named constructor is a label', async () => {
    const [request, headers] = await sign({ label: 'constructor' });
    assert.equal((await verify(request, headers)).aid, KEY.aid);
  });
});

describe('A10: keyid well-formedness, then the expected keyid, then the resolver', () => {
  it('a malformed raw keyid beside an expected keyid is malformed, not unknown', async () => {
    const [request, headers] = await sign({ keyid: 'not-a-key' });
    await assert.rejects(verify(request, headers, { expectedKeyid: KEY.keyid }), errors.MalformedKey);
  });

  it('a small-order raw keyid beside an expected keyid is malformed, not unknown', async () => {
    const identity = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]).toString('base64url');
    const [request, headers] = await sign({ keyid: identity });
    await assert.rejects(verify(request, headers, { expectedKeyid: KEY.keyid }), errors.MalformedKey);
  });

  it('a misspelled AID beside an expected keyid is malformed and never resolved', async () => {
    const aid = cesr('E', createHash('sha256').update('x').digest());
    const calls = [];
    const [request, headers] = await sign({ keyid: flipPadBit(aid) });
    await assert.rejects(
      verify(request, headers, { expectedKeyid: aid, resolve: (keyid) => calls.push(keyid) }),
      errors.MalformedKey,
    );
    assert.deepEqual(calls, []);
  });

  it('an unexpected keyid is unknown without asking the resolver', async () => {
    const aid = cesr('E', createHash('sha256').update('x').digest());
    const calls = [];
    const [request, headers] = await sign({ keyid: aid });
    await assert.rejects(
      verify(request, headers, { expectedKeyid: `E${'A'.repeat(43)}`, resolve: (keyid) => calls.push(keyid) }),
      errors.UnknownKey,
    );
    assert.deepEqual(calls, []);
  });
});

describe('A11: a 401 whose Signature header is empty is an unsigned 401', () => {
  it('is Unauthenticated, with or without a Signature-Input', async () => {
    await assert.rejects(verifyResponse({ status: 401, headers: { Signature: '' }, maxAge: null, expectedKeyid: null, minimum: null }), errors.Unauthenticated);
    await assert.rejects(
      verifyResponse({ status: 401, headers: { Signature: '', 'Signature-Input': 'sig=()' }, maxAge: null, expectedKeyid: null, minimum: null }),
      errors.Unauthenticated,
    );
  });
});

describe('A12: RFC 8941 parsing is strict', () => {
  for (const member of ['x=1.', 'x=-1.', 'x=1.;a=2', 'x=(1.)', 'x=2;a=1.']) {
    it(`a decimal without a fractional digit, ${member}, is malformed`, async () => {
      await assert.rejects(verify(...(await withDigest(`${DIGEST}, ${member}`))), errors.MalformedDigest);
    });
  }

  it('a bare decimal is malformed in the other two headers', async () => {
    const [request, headers] = await sign();
    await assert.rejects(verify(request, { ...headers, Signature: `${headers.Signature};x=1.` }), errors.MalformedSignature);
    await assert.rejects(
      verify(request, { ...headers, 'Signature-Input': `${headers['Signature-Input']};x=1.` }),
      errors.MalformedSignatureInput,
    );
  });

  for (const member of ['x=1234567890123456', 'x=:QQ:', 'x=:QQ=:', 'x=:=:', 'x=:Q=Q=:']) {
    it(`${JSON.stringify(member)} is malformed`, async () => {
      await assert.rejects(verify(...(await withDigest(`${DIGEST}, ${member}`))), errors.MalformedDigest);
    });
  }

  it('a line break inside a byte sequence is malformed, not skipped', async () => {
    const [request, headers] = await sign();
    const [label, encoded] = headers.Signature.split('=:');
    const broken = `${label}=:${encoded.slice(0, 40)}\r\n${encoded.slice(40)}`;
    await assert.rejects(verify(request, { ...headers, Signature: broken }), errors.MalformedSignature);
  });

  it('canonically padded byte sequences and fifteen-digit integers are read', async () => {
    const members = 'a=:QQ==:, b=:QUE=:, c=:QUFB:, d=::, e=123456789012345';
    assert.equal((await verify(...(await withDigest(`${DIGEST}, ${members}`)))).aid, KEY.aid);
  });

  it('trailing OWS after a dictionary member is accepted', async () => {
    const [request, headers] = await sign();
    headers.Signature += ' \t';
    assert.equal((await verify(request, headers)).aid, KEY.aid);
  });
});

describe('B13: the method is a token, wherever a request message is built', () => {
  for (const method of ['', ' ', 'G T', 'GET\r\n', 'GET\n', 'G(T', 'café']) {
    it(`${JSON.stringify(method)} is a caller error`, async () => {
      await assert.rejects(sign({ method, covered: ['@path'] }), callerError('is not an HTTP method'));
      assert.throws(() => signatureBase({ method, url: URL_, headers: {}, covered: ['@path'], ...BASE_ARGS }), callerError('is not an HTTP method'));
      const [request, headers] = await sign();
      await assert.rejects(verify({ ...request, method }, headers), callerError('is not an HTTP method'));
      assert.throws(
        () => responseSignatureBase({ status: 200, headers: {}, covered: ['@status'], request: { method, url: URL_ }, ...BASE_ARGS }),
        callerError('is not an HTTP method'),
      );
      await assert.rejects(
        verifyResponse({ status: 200, headers: {}, maxAge: null, expectedKeyid: null, minimum: null, request: { method, url: URL_ } }),
        callerError('is not an HTTP method'),
      );
    });
  }

  it('a method that is not a string is a caller error', async () => {
    await assert.rejects(sign({ method: null, covered: ['@path'] }), callerError('is not an HTTP method'));
    await assert.rejects(sign({ method: new TextEncoder().encode('GET'), covered: ['@path'] }), callerError('is not an HTTP method'));
  });

  for (const method of ['M-SEARCH', 'get', 'PROPFIND', "x!#$%&'*+.^_`|~1"]) {
    it(`${method} is a method, and keeps its case`, async () => {
      const [request, headers] = await sign({ method });
      assert.equal((await verify(request, headers)).aid, KEY.aid);
      const base = signatureBase({ method, url: URL_, headers: {}, covered: ['@method'], ...BASE_ARGS });
      assert.ok(new TextDecoder().decode(base).startsWith(`"@method": ${method}\n`));
    });
  }
});

describe('B14: a port is a run of ASCII digits, read as a number, in 0..65535', () => {
  for (const [url, expected] of [
    ['http://a.example:000080/x', 'a.example'],
    ['https://a.example:0443/x', 'a.example'],
    ['https://a.example:08443/x', 'a.example:8443'],
    [`https://a.example:${'0'.repeat(200)}8443/x`, 'a.example:8443'],
    ['https://a.example:65535/x', 'a.example:65535'],
    ['https://a.example:0/x', 'a.example:0'],
    ['https://a.example:/x', 'a.example'],
    ['https://A.example:81/x', 'a.example:81'],
  ]) {
    it(`${url.slice(0, 60)} has the authority ${expected}`, () => assert.equal(authority(url), expected));
  }

  const BAD_PORTS = ['65536', '99999', '8x', '+80', ' 80', '-1', '٨٠', '80 ', '0x50', '1e3'];
  for (const port of BAD_PORTS) {
    it(`${JSON.stringify(port)} is a caller error when signing`, async () => {
      assert.throws(() => authority(`https://a.example:${port}/x`), callerError('cannot be read:'));
      await assert.rejects(sign({ url: `https://a.example:${port}/x` }), callerError('cannot be read:'));
    });

    it(`${JSON.stringify(port)} is a signature mismatch when verifying`, async () => {
      const [request, headers] = await sign({ url: 'https://a.example/x' });
      await assert.rejects(verify({ ...request, url: `https://a.example:${port}/x` }, headers), errors.SignatureMismatch);
    });
  }

  it('is a signature mismatch in the request a response answers', async () => {
    const asked = { method: 'GET', url: 'https://a.example/x' };
    const headers = await signResponse({ key: KEY, status: 200, request: asked, created: AT, covered: ['@status', req('@authority')] });
    await assert.rejects(
      verifyResponse({
        status: 200, headers, maxAge: null, expectedKeyid: null, minimum: null,
        request: { method: 'GET', url: 'https://a.example:99999/x' },
      }),
      errors.SignatureMismatch,
    );
  });

  it('is never read when @authority is not covered', async () => {
    const [request, headers] = await sign({ url: 'https://a.example/x', covered: ['@method', '@path', '@query'] });
    assert.equal((await verify({ ...request, url: 'https://a.example:99999/x' }, headers)).aid, KEY.aid);
  });
});

describe('B15: what the signer serializes must be serializable', () => {
  for (const label of ['a\r\nb', 'Sig', '1sig', '', 'si g', 'sigé', '-a']) {
    it(`the label ${JSON.stringify(label)} is a caller error`, async () => {
      await assert.rejects(sign({ label }), callerError('is not an RFC 8941 key'));
      await assert.rejects(signResponse({ key: KEY, status: 200, created: AT, label }), callerError('is not an RFC 8941 key'));
    });
  }

  it('a label that is not a string is a caller error', async () => {
    await assert.rejects(sign({ label: null }), callerError('is not an RFC 8941 key'));
    await assert.rejects(sign({ label: 7 }), callerError('is not an RFC 8941 key'));
  });

  for (const label of ['sig', '*', 'a1_.-*', 'signify']) {
    it(`${label} is a label`, async () => {
      const [request, headers] = await sign({ label });
      assert.ok(headers.Signature.startsWith(`${label}=:`));
      assert.equal((await verify(request, headers)).aid, KEY.aid);
    });
  }

  for (const field of ['keyid', 'nonce', 'tag', 'alg']) {
    for (const value of ['a\r\nb', 'a\nb', 'café', 'a\x7f', 'a\tb', '\x00']) {
      it(`the ${field} ${JSON.stringify(value)} is a caller error`, async () => {
        if (field !== 'alg') await assert.rejects(sign({ [field]: value }), callerError('is not a string of printable ASCII'));
        assert.throws(
          () => signatureBase({ method: 'GET', url: URL_, headers: {}, covered: ['@path'], ...BASE_ARGS, [field]: value }),
          callerError('is not a string of printable ASCII'),
        );
      });
    }

    it(`a ${field} that is not a string is a caller error`, async () => {
      if (field !== 'alg') await assert.rejects(sign({ [field]: 7 }), callerError('is not a string of printable ASCII'));
      assert.throws(
        () => responseSignatureBase({ status: 200, headers: {}, covered: ['@status'], ...BASE_ARGS, [field]: 7 }),
        callerError('is not a string of printable ASCII'),
      );
    });
  }

  for (const field of ['nonce', 'tag']) {
    it(`every printable ASCII character is a serializable ${field}`, async () => {
      const value = String.fromCharCode(...Array.from({ length: 0x5f }, (_, i) => 0x20 + i));
      const [request, headers] = await sign({ [field]: value });
      assert.equal((await verify(request, headers)).aid, KEY.aid);
    });
  }

  for (const name of ['x\r\ny', 'a b', '', 'x:y', 'café', 'x\t']) {
    it(`the component name ${JSON.stringify(name)} is a caller error`, async () => {
      await assert.rejects(sign({ covered: ['@method', name], headers: name ? { [name]: '1' } : {} }), callerError('is not a component fiki can name'));
    });
  }

  it('a serialized component whose name is not a field name is a caller error', async () => {
    await assert.rejects(sign({ covered: ['"a b"'] }), callerError('is not a component fiki can name'));
    await assert.rejects(
      signResponse({ key: KEY, status: 200, created: AT, covered: ['@status', '"a b";req'], request: { method: 'GET', url: URL_ } }),
      callerError('is not a component fiki can name'),
    );
  });

  it('an unknown derived component keeps its own refusal (E6)', async () => {
    await assert.rejects(sign({ covered: ['@target-uri'] }), errors.UnsupportedComponent);
  });

  it('a field name is still lowercased for a local caller', async () => {
    const [request, headers] = await sign({ covered: ['@method', 'X-Role'], headers: { 'X-Role': 'admin' } });
    assert.ok(headers['Signature-Input'].includes('"x-role"'));
    assert.deepEqual((await verify(request, headers)).covered, ['@method', 'x-role']);
  });
});

describe("B16: created and expires fit RFC 8941's integer range", () => {
  for (const field of ['created', 'expires']) {
    for (const value of [1e15, -1, 2 ** 64, 1.5, Number.NaN, Infinity, '1700000000', true, 1700000000n]) {
      it(`${field}=${String(value)} is a caller error`, async () => {
        await assert.rejects(sign({ [field]: value }), callerError('RFC 8941 carries an integer of at most fifteen digits'));
        assert.throws(
          () => signatureBase({ method: 'GET', url: URL_, headers: {}, covered: ['@path'], ...BASE_ARGS, [field]: value }),
          callerError('RFC 8941 carries an integer of at most fifteen digits'),
        );
      });
    }
  }

  it('the largest and smallest timestamps are signed', async () => {
    const [request, headers] = await sign({ created: 0, expires: 1e15 - 1 });
    assert.ok(headers['Signature-Input'].includes('created=0;expires=999999999999999'));
    assert.equal((await verify(request, headers)).aid, KEY.aid);
  });
});

describe('B17: maxAge and skew are positive integers when given', () => {
  for (const field of ['maxAge', 'skew']) {
    for (const value of [0, -1, -1e30, 1.5, '300', true, Number.NaN, 300n]) {
      it(`${field}=${String(value)} is a caller error`, async () => {
        const [request, headers] = await sign();
        await assert.rejects(verify(request, headers, { [field]: value }), callerError('a freshness window is a positive whole number of seconds'));
        await assert.rejects(verifyResponse({ status: 200, headers: {}, maxAge: null, expectedKeyid: null, minimum: null, [field]: value }), callerError('a freshness window is a positive whole number of seconds'));
      });
    }
  }

  it('skew null is not a way to decline the check', async () => {
    const [request, headers] = await sign();
    await assert.rejects(verify(request, headers, { skew: null }), callerError('a freshness window is a positive whole number of seconds'));
  });

  it('maxAge null still declines the age check', async () => {
    const [request, headers] = await sign({ created: 0 });
    assert.equal((await verify(request, headers, { maxAge: null })).aid, KEY.aid);
  });

  it('enormous windows neither overflow nor refuse', async () => {
    const [request, headers] = await sign({ expires: 1e15 - 1 });
    const verdict = await verify(request, headers, { maxAge: 1e30, skew: 1e30, now: 1e18 });
    assert.equal(verdict.aid, KEY.aid);
    const [late, lateHeaders] = await sign({ created: 0 });
    await assert.rejects(verify(late, lateHeaders, { maxAge: 1, skew: 1, now: 1e18 }), errors.SignatureTooOld);
  });
});

describe('B18: the verdict keyid is the wire keyid, and the aid is who vouched', () => {
  it('reports both', async () => {
    let [request, headers] = await sign();
    let verdict = await verify(request, headers);
    assert.deepEqual([verdict.keyid, verdict.aid], [KEY.keyid, KEY.aid]);
    [request, headers] = await sign({ keyid: 'any keyid at all' });
    verdict = await verify(request, headers, { expectedAid: KEY.aid });
    assert.deepEqual([verdict.keyid, verdict.aid], ['any keyid at all', KEY.aid]);
  });

  it('is null when the signature had no keyid', async () => {
    const [request, headers] = await sign();
    headers['Signature-Input'] = headers['Signature-Input'].replace(/;keyid="[^"]*"/, '');
    // The base changed, so the signature no longer verifies; re-sign over the edited parameters.
    const base = signatureBase({ method: 'GET', url: URL_, headers: {}, covered: ['@method', '@authority', '@path', '@query'], created: AT, alg: 'ed25519' });
    headers.Signature = `sig=:${Buffer.from(await KEY.sign(base)).toString('base64')}:`;
    const verdict = await verify(request, headers, { expectedAid: KEY.aid });
    assert.equal(verdict.keyid, null);
    assert.equal(verdict.aid, KEY.aid);
  });

  it('is documented where the verdict is returned', () => {
    const source = readFileSync(new URL('../src/messages.js', import.meta.url), 'utf8').replace(/\s*\n\s*\*?\s*/g, ' ');
    assert.ok(source.includes('exactly as it appeared on the wire'));
    assert.ok(source.includes('null when the signature had none'));
    assert.ok(source.includes('the identity that vouched for the key'));
  });
});

describe('B19: both vectors formats are exported', () => {
  it('as integers', () => {
    assert.ok(Number.isInteger(fiki.VECTORS_FORMAT));
    assert.ok(Number.isInteger(fiki.KERI_VECTORS_FORMAT));
  });
});

describe('B20: input bounds, size before shape', () => {
  it('the bounds are exported constants', () => {
    assert.deepEqual(
      [fiki.MAX_FIELD_BYTES, fiki.MAX_DICTIONARY_MEMBERS, fiki.MAX_INNER_LIST_ITEMS, fiki.MAX_PARAMETERS],
      [8192, 16, 64, 16],
    );
  });

  /** Trailing spaces an RFC 8941 parser discards, so only the size check can refuse it. */
  const padTo = (value, size) => value + ' '.repeat(size - new TextEncoder().encode(value).length);

  for (const [header, error] of [
    ['Signature', errors.MalformedSignature],
    ['Signature-Input', errors.MalformedSignatureInput],
    ['Content-Digest', errors.MalformedDigest],
  ]) {
    it(`a ${header} over 8192 bytes is malformed before it is parsed`, async () => {
      const [request, headers] = await sign({ method: 'POST', body: BODY });
      headers[header] = padTo(headers[header], 8193);
      await assert.rejects(verify(request, headers), (err) => err instanceof error && /8192/.test(err.message));
    });

    it(`a ${header} of exactly 8192 bytes is read`, async () => {
      const [request, headers] = await sign({ method: 'POST', body: BODY });
      headers[header] = padTo(headers[header], 8192);
      assert.equal((await verify(request, headers)).aid, KEY.aid);
    });
  }

  it('a field over 8192 bytes is refused whatever it holds, counted in bytes', async () => {
    const [request, headers] = await sign({ method: 'POST', body: BODY });
    const refused = (err) => err instanceof errors.MalformedSignatureInput && /8192/.test(err.message);
    await assert.rejects(verify(request, { ...headers, 'Signature-Input': '('.repeat(9000) }), refused);
    await assert.rejects(verify(request, { ...headers, 'Signature-Input': 'é'.repeat(4097) }), refused);
  });

  // An unpaired surrogate has no UTF-8 spelling; fiki-py's encode raised on one (PR #14 hostile #3).
  for (const value of ['\ud800', 'sig=:\udfff:', '\ud800'.repeat(9000)]) {
    for (const [header, error] of [['Signature', errors.MalformedSignature], ['Signature-Input', errors.MalformedSignatureInput]]) {
      it(`a ${header} holding an unpaired surrogate (${value.length} units) is malformed`, async () => {
        const [request, headers] = await sign({ method: 'POST', body: BODY });
        await assert.rejects(verify(request, { ...headers, [header]: value }), error);
      });
    }
  }
  for (const value of ['\ud800', 'sha-256=:\udfff:']) {
    it(`a Content-Digest holding an unpaired surrogate is malformed (${JSON.stringify(value)})`, async () => {
      const asked = { method: 'POST', url: URL_, headers: { 'Content-Digest': value }, body: BODY };
      for (const covered of [['@status', req('content-digest')], undefined]) {
        await assert.rejects(signResponse({ key: KEY, status: 200, request: asked, created: AT, covered }), errors.MalformedDigest);
      }
      await assert.rejects(sign({ method: 'POST', body: BODY, headers: { 'Content-Digest': value } }), callerError('The Content-Digest supplied with this body is not one a verifier would accept'));
    });
  }

  const extraMembers = (n) => Array.from({ length: n }, (_, i) => `, x${i}=:AAAA:`).join('');

  it('a dictionary of seventeen members is malformed', async () => {
    const [request, headers] = await sign({ method: 'POST', body: BODY });
    await assert.rejects(verify(request, { ...headers, Signature: headers.Signature + extraMembers(16) }), errors.MalformedSignature);
    await assert.rejects(
      verify(request, { ...headers, 'Signature-Input': headers['Signature-Input'] + extraMembers(16) }),
      errors.MalformedSignatureInput,
    );
    await assert.rejects(verify(...(await withDigest(DIGEST + extraMembers(16)))), errors.MalformedDigest);
  });

  it('a dictionary of sixteen members is read', async () => {
    const [request, headers] = await sign({ method: 'POST', body: BODY });
    await assert.rejects(verify(request, { ...headers, Signature: headers.Signature + extraMembers(15) }), errors.MalformedSignatureLabel);
    assert.equal((await verify(...(await withDigest(DIGEST + extraMembers(15))))).aid, KEY.aid);
  });

  it('an inner list of sixty-four components is read, and sixty-five is malformed', async () => {
    const fields = Object.fromEntries(Array.from({ length: 62 }, (_, i) => [`x-h${i}`, String(i)]));
    const covered = ['@method', '@path', '@query', ...Object.keys(fields)];
    let [request, headers] = await sign({ headers: fields, covered: covered.slice(0, 64) });
    assert.equal((await verify(request, headers)).covered.length, 64);
    [request, headers] = await sign({ headers: fields, covered });
    await assert.rejects(verify(request, headers), errors.MalformedSignatureInput);
  });

  it('an inner list anywhere holds at most sixty-four items', async () => {
    await assert.rejects(verify(...(await withDigest(`${DIGEST}, x=(${Array(65).fill('1').join(' ')})`))), errors.MalformedDigest);
  });

  const params = (n) => Array.from({ length: n }, (_, i) => `;p${i}`).join('');

  it('an item with seventeen parameters is malformed', async () => {
    const [request, headers] = await sign({ method: 'POST', body: BODY });
    const bad = headers['Signature-Input'].replace('"@path"', `"@path"${params(17)}`);
    await assert.rejects(verify(request, { ...headers, 'Signature-Input': bad }), errors.MalformedSignatureInput);
    await assert.rejects(verify(request, { ...headers, Signature: headers.Signature + params(17) }), errors.MalformedSignature);
    await assert.rejects(verify(...(await withDigest(DIGEST + params(17)))), errors.MalformedDigest);
    await assert.rejects(
      verify(request, { ...headers, 'Signature-Input': headers['Signature-Input'] + params(17) }),
      errors.MalformedSignatureInput,
    );
  });

  it('an item with sixteen parameters is read', async () => {
    assert.equal((await verify(...(await withDigest(DIGEST + params(16))))).aid, KEY.aid);
  });
});

describe('E, superseded by @524c8qgv: a target holding a space or a control is refused, never cleaned', () => {
  // Format 2 cleaned a URL as urlsplit cleans it, which made "/\nx" verify as "/x". Format 3 refuses
  // such a target anywhere in it: a caller error on sign, a base that cannot be built on verify.
  const linesOf = (url) =>
    new TextDecoder()
      .decode(signatureBase({ method: 'GET', url, headers: {}, covered: ['@authority', '@path', '@query'], ...BASE_ARGS }))
      .split('\n')
      .slice(0, 3);

  for (const url of [
    'https://a.example/x\ty?q=1',
    'https://a.example/x?q=1\r\n2',
    'https://a.ex\tample:80/p',
    ' https://a.example/p',
    '\x01https://a.example/p',
    'https://a.example/p ',
    'https://a.example/p\x1f',
    'https://a.example/p\x7f',
    '/p\nx',
  ]) {
    it(`${JSON.stringify(url)} is a caller error on sign and a mismatch on verify`, async () => {
      assert.throws(() => linesOf(url), callerError('it contains a space or a control character'));
      const [request, headers] = await sign({ url: 'https://a.example/p' });
      await assert.rejects(verify({ ...request, url }, headers), errors.SignatureMismatch);
    });
  }

  it('builds the base of the same target without them', () => {
    assert.deepEqual(linesOf('https://a.example/xy?q=12'), ['"@authority": a.example', '"@path": /xy', '"@query": ?q=12']);
  });
});

// Format 3 part two (@524c8qgv): what the shared vectors cannot pin portably.
describe('format 3 part two', () => {
  it('quotes at most 64 characters of an untrusted URL, and escapes its controls', async () => {
    // Review A9, B9: a 5 MB URL made a 10 MB error message, and this port echoed controls raw.
    const [, headers] = await sign();
    const refusal = async (url) => {
      try {
        await verify({ method: 'GET', url }, headers);
      } catch (err) {
        assert.ok(err instanceof errors.SignatureMismatch, String(err));
        return err.message;
      }
      throw new Error('accepted');
    };
    const long = await refusal(`https://api.example.com/${'p'.repeat(9000)}`);
    assert.ok(long.length < 400, long);
    assert.ok(long.includes('(cut from 9024 characters)'), long);
    for (const [control, escaped] of [['\x1b', '\\u001b'], ['\x7f', '\\u007f']]) {
      const message = await refusal(`https://api.example.com/a${control}b`);
      assert.ok(!message.includes(control) && message.includes(escaped), message);
    }
    // A C1 control never reaches a quoted value through a URL, whose non-ASCII is refused unquoted,
    // so the escaping is checked where it is defined.
    const { quoted } = await import('../src/base.js');
    assert.equal(quoted('a\x85b'), '"a\\u0085b"');
  });

  it('quotes at most 64 characters of a label or a covered name from Signature-Input (#18)', async () => {
    // Copilot on bakobo/fiki#18: labels and component names reached messages unbounded.
    const [request, headers] = await sign();
    const refusal = async (input, Class) => {
      try {
        await verify(request, { ...headers, 'Signature-Input': input });
      } catch (err) {
        assert.ok(err instanceof Class, String(err));
        return err.message;
      }
      throw new Error('accepted');
    };
    const params = headers['Signature-Input'].slice(headers['Signature-Input'].indexOf(')') + 1);
    const label = `l${'x'.repeat(3000)}`;
    const cases = [
      [`${label}=("@method")${params}`, errors.MissingSignatureLabel],
      [`sig=("X-${'Y'.repeat(3000)}")${params}`, errors.MalformedSignatureInput],
      [`sig=("x-${'y'.repeat(3000)}")${params}`, errors.MissingComponent],
    ];
    for (const [input, Class] of cases) {
      const message = await refusal(input, Class);
      assert.ok(message.length <= 1024 && message.includes('(cut from 30'), message);
    }
    // A non-string is bounded too, unquoted: String() of an array can be as long as any string.
    const { quoted } = await import('../src/base.js');
    assert.equal(quoted(['a'.repeat(70)]), `${'a'.repeat(64)} (cut from 70 characters)`);
  });

  it('names a null keyid plainly when it is not the one expected', async () => {
    // Without a minimum, expectedAid alone decides the key, so a signature may carry no keyid.
    const [request, headers] = await sign({ keyid: null });
    const bare = { ...headers, 'Signature-Input': headers['Signature-Input'].replace(/;keyid="[^"]*"/, '') };
    await assert.rejects(
      verify(request, bare, { expectedAid: KEY.aid, expectedKeyid: KEY.aid }),
      (err) => err instanceof errors.UnknownKey && err.message.includes('signed by null'),
    );
  });

  for (const value of [42, new Uint8Array(4), '']) {
    it(`refuses an expectedKeyid of ${Object.prototype.toString.call(value)} ${String(value)} as a mistake in the call`, async () => {
      // "" names no AID, and reading it as the decline would turn a missing value into "any signer".
      const [request, headers] = await sign();
      await assert.rejects(verify(request, headers, { expectedKeyid: value }), callerError('verifyRequest\'s expectedKeyid is'));
      await assert.rejects(
        verifyResponse({ status: 200, headers: {}, maxAge: null, minimum: null, expectedKeyid: value }),
        callerError('verifyResponse\'s expectedKeyid is'),
      );
    });
  }

  it('requires an expectedKeyid decision, and applies RESPONSE_MINIMUM when no minimum is stated', async () => {
    const asked = { method: 'GET', url: URL_, headers: {} };
    const headers = await signResponse({ key: KEY, status: 200, request: asked, created: AT, covered: ['@status'] });
    const args = { status: 200, headers, request: asked, maxAge: null };
    await assert.rejects(verifyResponse(args), callerError('verifyResponse requires expectedKeyid'));
    await assert.rejects(verifyResponse({ ...args, expectedKeyid: null }), errors.InsufficientCoverage);
    assert.deepEqual((await verifyResponse({ ...args, expectedKeyid: KEY.keyid, minimum: null })).covered, ['@status']);
  });

  it('folds field names A-Z only, so U+212A KELVIN SIGN stays itself', async () => {
    const { asciiLower, canonicalHeaders } = await import('../src/base.js');
    assert.equal(asciiLower('X-Note'), 'x-note');
    assert.equal(asciiLower('Key'), 'Key');
    assert.deepEqual(Object.keys(canonicalHeaders({ 'Key-Id': 'v', 'Key-Id': 'w' })).sort(), ['key-id', 'Key-id']);
  });

  it('bounds a covered value as received, Content-Digest by its own class', async () => {
    // Exactly the bound is accepted; one byte more, before any whitespace is trimmed, is not.
    const at = (size) => ({ 'X-Note': 'n'.repeat(size) });
    const covered = ['@method', '@path', 'x-note'];
    const [request, headers] = await sign({ headers: at(8192), covered });
    assert.ok(await verify(request, headers));
    await assert.rejects(sign({ headers: { 'X-Note': `${'n'.repeat(8192)} ` }, covered }), errors.SignatureMismatch);
    // An oversized Content-Digest builds into a base, and is refused when parsed, as MalformedDigest.
    await assert.rejects(verify(...(await withDigest(`sha-256=:${'A'.repeat(8200)}=:`))), errors.MalformedDigest);
  });
});
