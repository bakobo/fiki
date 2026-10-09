// Lone UTF-16 surrogates in every untrusted string fiki measures or character-checks (tick 7us4).
//
// A JavaScript string can hold a lone surrogate, which no JSON vector carries portably, so this is
// a native test. fiki-py's size checks once raised UnicodeEncodeError on one (#18 hostile finding
// 3); a Python string can hold one too, so each expectation below is the outcome fiki-py gives the
// same string, read from a scratch script that called fiki-py with it, and the comment on each
// names the path py takes. None may escape as a runtime exception (TypeError from outside fiki's
// own checks, URIError): every refusal is the FikiError py raises, or a caller error carrying the
// message fragment fiki writes.
//
// The byte bound counts a lone surrogate as three bytes, as py's
// len(value.encode("utf-8", "surrogatepass")) does; TextEncoder writes one as U+FFFD, also three.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { FikiError, Key, errors, signRequest, verifyRequest } from '../src/index.js';

const KEY = await Key.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i));
const AT = 1700000000;
const URL_ = 'https://example.com/p?q=1';
const POLICY = { minimum: null, authorities: null, maxAge: null, now: AT };

const sign = (overrides = {}) =>
  signRequest({ key: KEY, method: 'POST', url: URL_, headers: { 'x-a': 'v', Host: 'example.com' }, created: AT, ...overrides });

const verify = (signed, overrides = {}) =>
  verifyRequest({ ...POLICY, method: 'POST', url: URL_, headers: { 'x-a': 'v', Host: 'example.com', ...signed }, ...overrides });

/** The FikiError py raises, with a fragment of its message, and never a caller error. */
const refused = (Class, fragment) => (err) => {
  assert.ok(err instanceof Class, `expected ${Class.name}, got ${err?.name}: ${err?.message}`);
  assert.ok(err.message.includes(fragment), `expected "${fragment}" in: ${err.message}`);
  return true;
};

/** A caller error: a TypeError carrying fiki's own message, never a FikiError. */
const callerError = (fragment) => (err) => {
  assert.ok(err instanceof TypeError && !(err instanceof FikiError), `expected a caller error, got ${err?.name}: ${err?.message}`);
  assert.ok(err.message.includes(fragment), `expected "${fragment}" in: ${err.message}`);
  return true;
};

const NON_ASCII = 'a line break, a control character or a non-ASCII character';
const NO_UTF8 = 'holds a character that has no UTF-8 encoding';
const OVER = 'over 8192 bytes';

for (const [which, s] of [['high', '\ud800'], ['low', '\udc00']]) {
  describe(`a lone ${which} surrogate`, async () => {
    const good = await sign({ covered: ['@method', '@path', 'x-a'] });
    const hosted = await sign({ covered: ['@authority'], url: '/p' });
    const bodied = await sign({ body: 'hi' });

    // py: _check_raw on the @path value, after _split counted the URL.
    it('in the URL is a signature mismatch, signing or verifying', async () => {
      await assert.rejects(sign({ url: `https://example.com/p${s}` }), refused(errors.SignatureMismatch, NON_ASCII));
      await assert.rejects(verify(good, { url: `https://example.com/p${s}` }), refused(errors.SignatureMismatch, NON_ASCII));
      await assert.rejects(verify(good, { url: `/p${s}` }), refused(errors.SignatureMismatch, NON_ASCII));
    });

    // py: the URL is split only when a component needs it, so nothing reads it.
    it('in a URL nothing covers is never read', async () => {
      const fieldOnly = await sign({ covered: ['x-a'] });
      assert.equal((await verify(fieldOnly, { url: `/p${s}` })).covered[0], 'x-a');
      assert.equal((await verify(fieldOnly, { url: `/ab${s.repeat(2730)}` })).covered[0], 'x-a');
    });

    // py: _check_raw on Host in _authority.
    it('in a Host header is a signature mismatch, signing or verifying', async () => {
      await assert.rejects(
        sign({ covered: ['@authority'], url: '/p', headers: { Host: `example.com${s}` } }),
        refused(errors.SignatureMismatch, NON_ASCII),
      );
      await assert.rejects(verify(hosted, { url: '/p', headers: { Host: `ex${s}`, ...hosted } }), refused(errors.SignatureMismatch, NON_ASCII));
    });

    // py: _check_raw on the covered field's value.
    it('in a covered field value is a signature mismatch, signing or verifying', async () => {
      await assert.rejects(sign({ covered: ['x-a'], headers: { 'x-a': `v${s}` } }), refused(errors.SignatureMismatch, NON_ASCII));
      await assert.rejects(verify(good, { headers: { 'x-a': `v${s}`, Host: 'example.com', ...good } }), refused(errors.SignatureMismatch, NON_ASCII));
    });

    // py: _parse refuses a string with no UTF-8 spelling before it counts or parses.
    it('in Signature-Input or Signature is that header\'s malformed class', async () => {
      const input = good['Signature-Input'];
      await assert.rejects(verify({ ...good, 'Signature-Input': input + s }), refused(errors.MalformedSignatureInput, NO_UTF8));
      await assert.rejects(
        verify({ ...good, 'Signature-Input': input.replace('"x-a"', `"x-a${s}"`) }),
        refused(errors.MalformedSignatureInput, NO_UTF8),
      );
      await assert.rejects(verify({ ...good, Signature: good.Signature + s }), refused(errors.MalformedSignature, NO_UTF8));
    });

    // py: a covered Content-Digest's value is character-checked when the base is built, which
    // comes before the digest is parsed.
    it('in a covered Content-Digest is a signature mismatch', async () => {
      await assert.rejects(
        verify({ ...bodied, 'Content-Digest': bodied['Content-Digest'] + s }, { body: 'hi' }),
        refused(errors.SignatureMismatch, NON_ASCII),
      );
    });

    // py: check_signer_params, a caller error.
    for (const name of ['keyid', 'nonce', 'tag']) {
      it(`in a ${name} to sign with is a caller error`, async () => {
        await assert.rejects(sign({ [name]: `k${s}` }), callerError('is not a string of printable ASCII'));
      });
    }

    // py: compared, never read, so it is simply not the keyid that signed.
    it('in an expected keyid is an unknown key', async () => {
      await assert.rejects(verify(good, { expectedKeyid: `k${s}` }), refused(errors.UnknownKey, 'and the one expected is'));
    });

    // py: verifying_key refuses an AID of the wrong length before decoding it.
    it('in an expected AID is a malformed key', async () => {
      await assert.rejects(verify(good, { expectedAid: `B${s}` }), errors.MalformedKey);
    });

    // py: component() refuses a name that is not a field name, a caller error; a serialized one
    // does not parse, and is UnsupportedComponent.
    it('in a component name is a caller error, and in a serialized one unsupported', async () => {
      await assert.rejects(sign({ covered: [`x-${s}`] }), callerError('is not a component fiki can name'));
      await assert.rejects(
        verify(good, { minimum: ['@method', '@path', '@query', `x-${s}`] }),
        callerError('is not a component fiki can name'),
      );
      await assert.rejects(sign({ covered: [`"x-${s}"`] }), refused(errors.UnsupportedComponent, 'as a component identifier'));
    });

    // py: check_label, a caller error.
    it('in a label is a caller error', async () => {
      await assert.rejects(sign({ label: `a${s}` }), callerError('is not an RFC 8941 key'));
    });

    // The 8192-byte bound counts a lone surrogate as three bytes. 2730 of them are 8190 bytes, so
    // two ASCII characters beside them reach the bound exactly and three pass it. Where py counts
    // first, at the bound the refusal is the character check and past it the size.
    it('counts three bytes in a URL, as py does', async () => {
      await assert.rejects(verify(good, { url: `/a${s.repeat(2730)}` }), refused(errors.SignatureMismatch, NON_ASCII));
      await assert.rejects(verify(good, { url: `/ab${s.repeat(2730)}` }), refused(errors.SignatureMismatch, OVER));
    });

    it('counts three bytes in a covered field value, as py does', async () => {
      await assert.rejects(verify(good, { headers: { 'x-a': `ab${s.repeat(2730)}`, ...good } }), refused(errors.SignatureMismatch, NON_ASCII));
      await assert.rejects(verify(good, { headers: { 'x-a': `abc${s.repeat(2730)}`, ...good } }), refused(errors.SignatureMismatch, OVER));
    });

    it('counts three bytes in a Host header, as py does', async () => {
      await assert.rejects(
        verify(hosted, { url: '/p', headers: { Host: `ab${s.repeat(2730)}`, ...hosted } }),
        refused(errors.SignatureMismatch, NON_ASCII),
      );
      await assert.rejects(
        verify(hosted, { url: '/p', headers: { Host: `abc${s.repeat(2730)}`, ...hosted } }),
        refused(errors.SignatureMismatch, OVER),
      );
    });

    // py refuses a surrogate in a signature header before it counts bytes, so past the bound the
    // refusal is still the encoding, not the size.
    it('in an over-long signature header is refused for the encoding, as py does', async () => {
      await assert.rejects(verify({ ...good, 'Signature-Input': `abc${s.repeat(2730)}` }), refused(errors.MalformedSignatureInput, NO_UTF8));
      await assert.rejects(verify({ ...good, Signature: `abc${s.repeat(2730)}` }), refused(errors.MalformedSignature, NO_UTF8));
    });
  });
}

describe('a well-formed surrogate pair', () => {
  it('in a signature header is refused by the grammar, not the encoding', async () => {
    const good = await sign({ covered: ['@method'] });
    await assert.rejects(verify({ ...good, Signature: `${good.Signature}😀` }), (err) => {
      assert.ok(err instanceof errors.MalformedSignature);
      assert.ok(!err.message.includes(NO_UTF8));
      return true;
    });
  });
});
