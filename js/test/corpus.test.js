// The httpwg structured-field-tests corpus against fiki-js's RFC 8941 parser (`this.i` @7fexwu3s).
//
// Dictionaries go through the bounded entry point the verifier reads Signature-Input with, so a
// dictionary is refused exactly where a verifier would refuse it. Items and lists go through the
// parser's own parseItem and parseList, which apply the inner-list, parameter and member bounds as
// they read, behind the same 8192-byte bound on the combined raw value. Every case runs; none is
// skipped. The rules, the same in all six ports:
//
// - Dates and Display Strings are refused: RFC 9421 references RFC 8941, not RFC 9651 (@7vdhfv3q).
// - Input over any of fiki's four bounds is refused, at every entry point (@5zrf8gjk).
// - A can_fail case has the one outcome fiki's decisions dictate: a byte sequence with missing,
//   partial or extra padding is refused and non-zero pad bits are accepted (@2g4xxev9); any other
//   takes fiki-py's outcome.
// - Everything else matches the corpus exactly, parameters and their order included, except where
//   a recorded fiki decision says otherwise; those cases are listed in DECIDED below.

import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { describe, it } from 'node:test';

import {
  Key,
  MAX_DICTIONARY_MEMBERS,
  MAX_FIELD_BYTES,
  MAX_INNER_LIST_ITEMS,
  MAX_PARAMETERS,
  errors,
  signRequest,
} from '../src/index.js';
import { parse } from '../src/messages.js';
import { Decimal, SfvSyntaxError, Token, parseItem, parseList } from '../src/sfv.js';
import { callerError } from './caller.js';

const CORPUS = new URL('../../vectors/third_party/structured-field-tests/', import.meta.url);

/** Parse JSON keeping each number's literal, since JSON.parse cannot tell 1.0 from 1.
 *
 * A number literal outside a string is rewritten to {"__number": "<literal>"} before parsing.
 */
function loadKeepingNumbers(url) {
  const text = readFileSync(url, 'utf8');
  let out = '';
  for (let i = 0; i < text.length; ) {
    const char = text[i];
    if (char === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (/[-0-9]/.test(char)) {
      const [literal] = /^-?[0-9]+(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?/.exec(text.slice(i));
      out += `{"__number": "${literal}"}`;
      i += literal.length;
    } else {
      out += char;
      i += 1;
    }
  }
  return JSON.parse(out);
}

// RFC 4648 base32, as the corpus encodes binary values.
function base32(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of text.replace(/=+$/, '')) bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  return Uint8Array.from(bits.match(/.{8}/g) ?? [], (byte) => parseInt(byte, 2));
}

const hex = (bytes) => Buffer.from(bytes).toString('hex');

// Both sides are normalized to one comparable shape, which carries each value's type: an integer
// and a decimal never compare equal, and a decimal compares at three fractional digits.
function expectedBare(value) {
  if (typeof value === 'string' || typeof value === 'boolean') return [typeof value, value];
  if (value.__number !== undefined) {
    const literal = value.__number;
    return /[.eE]/.test(literal) ? ['decimal', Number(literal).toFixed(3)] : ['integer', Number(literal)];
  }
  if (value.__type === 'token') return ['token', value.value];
  if (value.__type === 'binary') return ['binary', hex(base32(value.value))];
  throw new Error(`The corpus expects a ${value.__type}, which no case fiki accepts may carry.`);
}

function actualBare(value) {
  if (typeof value === 'string' || typeof value === 'boolean') return [typeof value, value];
  if (typeof value === 'number') return ['integer', value];
  if (value instanceof Decimal) return ['decimal', value.value.toFixed(3)];
  if (value instanceof Token) return ['token', value.value];
  assert.ok(value instanceof Uint8Array, `the parser returned ${value}`);
  return ['binary', hex(value)];
}

const expectedParams = (params) => params.map(([key, value]) => [key, expectedBare(value)]);
const actualParams = (params) => [...params].map(([key, value]) => [key, actualBare(value)]);

// A member is an inner list, whose expected value is an array, or an item.
const expectedMember = ([value, params]) =>
  Array.isArray(value)
    ? ['inner', value.map(expectedMember), expectedParams(params)]
    : ['item', expectedBare(value), expectedParams(params)];
const actualMember = (member) =>
  member.items !== undefined
    ? ['inner', member.items.map(actualMember), actualParams(member.params)]
    : ['item', actualBare(member.value), actualParams(member.params)];

const EXPECTED = {
  item: (expected) => expectedMember(expected),
  list: (expected) => expected.map(expectedMember),
  dictionary: (expected) => expected.map(([key, member]) => [key, expectedMember(member)]),
};
const ACTUAL = {
  item: actualMember,
  list: (list) => list.map(actualMember),
  dictionary: (dictionary) => [...dictionary].map(([key, member]) => [key, actualMember(member)]),
};

/** The 8192-byte bound every entry point applies to the combined raw value before parsing. */
function bounded(parser) {
  return (raw) => {
    if (new TextEncoder().encode(raw).length > MAX_FIELD_BYTES) {
      throw new SfvSyntaxError(`The field is over ${MAX_FIELD_BYTES} bytes.`);
    }
    return parser(raw);
  };
}

// Each header type's entry point, and the one error it may refuse with.
const ENTRY = {
  dictionary: [(raw) => parse(raw, 'Signature-Input', errors.MalformedSignatureInput), errors.MalformedSignatureInput],
  item: [bounded(parseItem), SfvSyntaxError],
  list: [bounded(parseList), SfvSyntaxError],
};

// Whether a case's input uses a type RFC 9651 added: its file is about one, or its expected value
// holds one.
const usesRfc9651 = (file, c) =>
  file === 'date.json' || file === 'display-string.json' || /"__type":"(?:date|displaystring)"/.test(JSON.stringify(c.expected ?? null));

// Whether the expected value exceeds one of fiki's count bounds. Lists count members against the
// dictionary bound, as parseList does, so every entry point applies all four.
function overCounts(type, expected) {
  if (expected === undefined) return false;
  const members = type === 'item' ? [expected] : type === 'list' ? expected : expected.map(([, member]) => member);
  if (type !== 'item' && members.length > MAX_DICTIONARY_MEMBERS) return true;
  return members.some(([value, params]) => {
    if (params.length > MAX_PARAMETERS) return true;
    if (!Array.isArray(value)) return false;
    return value.length > MAX_INNER_LIST_ITEMS || value.some(([, itemParams]) => itemParams.length > MAX_PARAMETERS);
  });
}

// Corpus cases whose outcome a recorded fiki decision sets against the corpus's.
const DECIDED = new Map([
  // vectors/refusals.json signature-header-of-spaces (review B7, vectors_format 3 under @524c8qgv):
  // a signature header present but empty after OWS is malformed, as every port says alike. The
  // corpus's empty dictionary is that header.
  ['dictionary.json/empty dictionary', 'refused'],
]);

// can_fail cases: the outcome fiki's decisions dictate (@2g4xxev9), or fiki-py's.
const CAN_FAIL = new Map([
  ['binary.json/unpadded', 'refused'],
  ['binary.json/partially padded', 'refused'],
  ['binary.json/extra padding', 'refused'],
  ['binary.json/non-zero pad bits', 'accepted'],
  // fiki-py, through http_sfv, parses the two lines combined with ", " as the string "foo, bar".
  ['string.json/two lines string', 'accepted'],
  // RFC 9651 types, refused whatever their range (@7vdhfv3q).
  ['date.json/syntactic max date - 999,999,999,999,999', 'refused'],
  ['date.json/syntactic min date - -999,999,999,999,999', 'refused'],
  ['display-string.json/two lines display string', 'refused'],
]);

/** What fiki must do with a case: 'accepted' with the corpus's value, or 'refused'. */
function outcome(file, c) {
  const id = `${file}/${c.name}`;
  if (DECIDED.has(id)) return DECIDED.get(id);
  if (c.can_fail) {
    assert.ok(CAN_FAIL.has(id), `${id} is can_fail and nothing here says what fiki does with it`);
    return CAN_FAIL.get(id);
  }
  if (c.must_fail || usesRfc9651(file, c)) return 'refused';
  const raw = c.raw.join(', ');
  if (new TextEncoder().encode(raw).length > MAX_FIELD_BYTES) return 'refused';
  if (overCounts(c.header_type, c.expected)) return 'refused';
  return 'accepted';
}

// Every parsing file, with the number of cases it holds, how many fiki accepts and how many it
// refuses; nothing is skipped. Pinned, so a change to the corpus cannot shrink coverage silently.
const COUNTS = {
  'binary.json': [17, 4, 13],
  'boolean.json': [12, 2, 10],
  'date.json': [17, 0, 17],
  'dictionary.json': [26, 18, 8],
  'display-string.json': [22, 0, 22],
  'examples.json': [21, 21, 0],
  'item.json': [5, 2, 3],
  'key-generated.json': [640, 166, 474],
  'large-generated.json': [11, 5, 6],
  'list.json': [11, 8, 3],
  'listlist.json': [12, 5, 7],
  'number-generated.json': [193, 189, 4],
  'number.json': [37, 19, 18],
  'param-dict.json': [14, 9, 5],
  'param-list.json': [20, 10, 10],
  'param-listlist.json': [3, 3, 0],
  'string-generated.json': [256, 95, 161],
  'string.json': [14, 6, 8],
  'token-generated.json': [256, 134, 122],
  'token.json': [6, 6, 0],
};

const files = readdirSync(CORPUS).filter((name) => name.endsWith('.json')).sort();

describe('the httpwg structured-field-tests corpus', () => {
  it('has exactly the parsing files whose counts are pinned here', () => {
    assert.deepEqual(files, Object.keys(COUNTS).sort());
  });

  for (const file of files) {
    describe(file, () => {
      const cases = loadKeepingNumbers(new URL(file, CORPUS));
      const tally = { run: 0, accepted: 0, refused: 0 };

      for (const c of cases) {
        it(c.name, () => {
          const [entry, Refusal] = ENTRY[c.header_type];
          assert.ok(entry, `unknown header_type ${c.header_type}`);
          const raw = c.raw.join(', ');
          const want = outcome(file, c);
          tally.run += 1;
          tally[want] += 1;
          if (want === 'refused') {
            assert.throws(() => entry(raw), (err) => err instanceof Refusal, `${file}/${c.name} must be refused`);
            return;
          }
          assert.deepEqual(ACTUAL[c.header_type](entry(raw)), EXPECTED[c.header_type](c.expected));
        });
      }

      it('ran every case, with the pinned outcomes', () => {
        assert.deepEqual([cases.length, tally.accepted, tally.refused], COUNTS[file]);
        assert.equal(tally.run, cases.length);
      });
    });
  }
});

// --- serialisation, through the public signing API ---

const KEY = await Key.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i));
const SERIAL = new URL('serialisation-tests/', CORPUS);
const signWith = (overrides) => signRequest({ key: KEY, method: 'GET', url: 'https://example.com/', headers: {}, created: 1, ...overrides });


describe('the corpus serialisation cases, through signRequest', () => {
  const counts = { label: 0, param: 0, string: 0, number: 0 };

  // Each gives a key: the dictionary member's, or the list item's parameter's.
  for (const c of loadKeepingNumbers(new URL('key-generated.json', SERIAL))) {
    const [first] = c.expected;
    const key = c.header_type === 'dictionary' ? first[0] : first[1][0][0];
    it(`key-generated: ${c.name}`, async () => {
      assert.equal(c.must_fail, true);
      counts.label += 1;
      counts.param += 1;
      await assert.rejects(signWith({ label: key }), callerError('is not an RFC 8941 key'));
      // A serialized component that does not parse, or parses to a parameter other than req, is
      // UnsupportedComponent in fiki-py too: the spec names a component fiki cannot build, which
      // its taxonomy names rather than calling it a caller error.
      await assert.rejects(signWith({ covered: [`"@method";${key}`] }), errors.UnsupportedComponent);
    });
  }

  for (const c of loadKeepingNumbers(new URL('string-generated.json', SERIAL))) {
    const [text] = c.expected;
    it(`string-generated: ${c.name}`, async () => {
      assert.equal(c.must_fail, true);
      for (const name of ['keyid', 'nonce', 'tag']) {
        counts.string += 1;
        await assert.rejects(signWith({ [name]: text }), callerError('is not a string of printable ASCII'));
      }
    });
  }

  for (const c of loadKeepingNumbers(new URL('number.json', SERIAL)).filter((c) => c.name.startsWith('too big'))) {
    const literal = c.expected[0].__number;
    it(`number: ${c.name}`, async () => {
      assert.equal(c.must_fail, true);
      counts.number += 1;
      await assert.rejects(signWith({ created: Number(literal) }), callerError('RFC 8941 carries an integer of at most fifteen digits'));
    });
  }

  it('ran every case', () => {
    assert.deepEqual(counts, { label: 378, param: 378, string: 99, number: 4 });
  });
});
