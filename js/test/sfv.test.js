// RFC 8941's bare item types, all of them and none of RFC 9651's (`this.i` @7vdhfv3q).
//
// fiki-js never parsed tokens or decimals, so a Signature member whose value was a token failed to
// parse here and was MalformedSignature, where every other port parses it and refuses it as
// MalformedSignatureValue. The verifier-level expectations below are fiki-py's outcomes for the
// same headers, read from a scratch script that called fiki-py with them.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { Key, errors, signRequest, verifyRequest } from '../src/index.js';
import { Decimal, SfvSyntaxError, Token, parseDictionary, parseItem, parseList, serializeItem } from '../src/sfv.js';

const bare = (text) => parseItem(text).value;

describe('tokens', () => {
  for (const text of ['a', 'A', '*', 'foo123/456', 'a:b', "a!#$%&'*+-.^_`|~9Z"]) {
    it(`${text} is a token`, () => {
      const value = bare(text);
      assert.ok(value instanceof Token);
      assert.equal(value.value, text);
    });
  }
  for (const text of ['a"b', 'a,b', 'a(b']) {
    it(`${text} is not a whole token`, () => assert.throws(() => parseItem(text), SfvSyntaxError));
  }
  it('serializes as itself', () => assert.equal(serializeItem({ value: new Token('a:b/c'), params: new Map() }), 'a:b/c'));
});

describe('decimals', () => {
  for (const [text, expected] of [
    ['1.5', 1.5],
    ['-1.5', -1.5],
    ['0.001', 0.001],
    ['123456789012.123', 123456789012.123],
    ['-0.0', -0],
  ]) {
    it(`${text} is the decimal ${expected}`, () => {
      const value = bare(text);
      assert.ok(value instanceof Decimal);
      assert.equal(value.value, expected);
    });
  }
  for (const text of ['1.', '-1.', '1.1234', '1234567890123.1', '.5', '-.5', '1..2', '-', '-a']) {
    it(`${text} is refused`, () => assert.throws(() => parseItem(text), SfvSyntaxError));
  }
  it('an integer still has at most fifteen digits, and is a number', () => {
    assert.equal(bare('999999999999999'), 999999999999999);
    assert.equal(bare('-1'), -1);
    assert.throws(() => parseItem('1000000000000000'), SfvSyntaxError);
  });
  for (const [value, expected] of [
    [1.5, '1.5'],
    [-1.5, '-1.5'],
    [2, '2.0'],
    [0.125, '0.125'],
    [123456789012.123, '123456789012.123'],
  ]) {
    it(`${value} serializes as ${expected}`, () => assert.equal(serializeItem({ value: new Decimal(value), params: new Map() }), expected));
  }
});

describe('RFC 9651 additions', () => {
  for (const text of ['@1659578233', '%"a"', '%"%c3%a9"']) {
    it(`${text} is refused`, () => {
      assert.throws(() => parseItem(text), SfvSyntaxError);
      assert.throws(() => parseDictionary(`a=${text}`), SfvSyntaxError);
      assert.throws(() => parseList(text), SfvSyntaxError);
    });
  }
});

describe('lists', () => {
  it('hold items and inner lists with parameters', () => {
    const [a, b] = parseList('tok;x=1, ("s" 2);y');
    assert.equal(a.value.value, 'tok');
    assert.equal(a.params.get('x'), 1);
    assert.deepEqual(b.items.map((item) => item.value), ['s', 2]);
    assert.equal(b.params.get('y'), true);
  });
  it('may be empty', () => assert.deepEqual(parseList(''), []));
  for (const text of ['a,', 'a b', ',a', 'a,,b']) {
    it(`${JSON.stringify(text)} is refused`, () => assert.throws(() => parseList(text), SfvSyntaxError));
  }
  it('hold at most sixteen members, as a dictionary does', () => {
    assert.equal(parseList(Array(16).fill('a').join(', ')).length, 16);
    assert.throws(() => parseList(Array(17).fill('a').join(', ')), SfvSyntaxError);
  });
});

const KEY = await Key.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i));
const AT = 1700000000;
const URL_ = 'https://example.com/p';
const good = await signRequest({ key: KEY, method: 'GET', url: URL_, headers: {}, created: AT, covered: ['@method'] });
const input = good['Signature-Input'];
const verify = (headers) =>
  verifyRequest({ method: 'GET', url: URL_, headers: { ...good, ...headers }, maxAge: null, now: AT, authorities: null, minimum: null });

/** fiki-py's class for the same header, and a fragment of the message saying why. */
const refused = (Class, fragment) => (err) => {
  assert.ok(err instanceof Class, `expected ${Class.name}, got ${err?.name}: ${err?.message}`);
  assert.ok(err.message.includes(fragment), `expected "${fragment}" in: ${err.message}`);
  return true;
};

describe('a verifier reads tokens and decimals and refuses them where fiki-py does', () => {
  it('a Signature member that is a token or a decimal is not a byte sequence', async () => {
    await assert.rejects(verify({ Signature: 'sig=tok' }), refused(errors.MalformedSignatureValue, 'carries something else'));
    await assert.rejects(verify({ Signature: 'sig=1.5' }), refused(errors.MalformedSignatureValue, 'carries something else'));
  });
  it('a covered component with a token or decimal parameter is unsupported', async () => {
    for (const param of ['a=tok', 'a=1.5', 'req=tok']) {
      await assert.rejects(
        verify({ 'Signature-Input': input.replace('"@method"', `"@method";${param}`) }),
        refused(errors.UnsupportedComponent, 'the only component parameter it supports is "req"'),
      );
    }
  });
  it('a covered component named by a token or a decimal is not a string', async () => {
    for (const name of ['tok', '1.5']) {
      await assert.rejects(
        verify({ 'Signature-Input': input.replace('"@method"', name) }),
        refused(errors.MalformedSignatureInput, 'named by a quoted string'),
      );
    }
  });
  it('a decimal created and a token nonce have the wrong type', async () => {
    await assert.rejects(verify({ 'Signature-Input': `${input};created=1.5` }), refused(errors.MalformedSignatureInput, 'must be an integer'));
    await assert.rejects(
      verify({ 'Signature-Input': input.replace('created=1700000000', 'created=1700000000.0') }),
      refused(errors.MalformedSignatureInput, 'must be an integer'),
    );
    await assert.rejects(verify({ 'Signature-Input': `${input};nonce=tok` }), refused(errors.MalformedSignatureInput, 'must be a quoted string'));
  });
  it('an unknown parameter is refused whatever its type, and a Date or Display String does not parse', async () => {
    for (const value of ['tok', '1.5']) {
      await assert.rejects(verify({ 'Signature-Input': `${input};x=${value}` }), refused(errors.MalformedSignatureInput, 'is not one fiki understands'));
    }
    for (const value of ['@12', '%"a"', '1234567890123.1', '123456789012.1234']) {
      await assert.rejects(verify({ 'Signature-Input': `${input};x=${value}` }), refused(errors.MalformedSignatureInput, 'I could not parse'));
    }
  });
});
