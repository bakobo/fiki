// The RFC 8941 subset RFC 9421 actually uses (`this.i` @2q9gv70t).
//
// Hand-rolled rather than depended upon, because fiki's slice of structured fields is small and
// CLOSED — a dictionary whose members are inner lists of strings with parameters, plus byte
// sequences — and because a browser library with no dependencies ships as one file with no supply
// chain. The usual argument against writing your own parser holds where the grammar is open-ended;
// this one's entire output surface is pinned byte for byte by the shared vectors.
//
// Every bare item type RFC 8941 defines is parsed, tokens and decimals included, though fiki reads
// neither in any header it uses: a parser that refuses one where every other port parses it moves
// the refusal to a different class, MalformedSignature where the others say
// MalformedSignatureValue (@7vdhfv3q). RFC 9651's Dates and Display Strings are NOT parsed, since
// RFC 9421 references RFC 8941, and fall to the same syntax error as any other text the grammar
// does not allow. Inner-list items carry parameters, because RFC 9421 section 2.4's `req` is one,
// and fiki decides what a parameter means only after the parse, where refusing it can name the
// component rather than the syntax (@7f28p7xk).

// Thrown by this module alone and never exported: the parser cannot know WHICH header it is
// reading, and the taxonomy distinguishes an unparsable Signature from an unparsable
// Signature-Input. So callers catch this and re-raise the class that names the header, exactly as
// the Python port wraps http_sfv (@8zw78n0v).
export class SfvSyntaxError extends Error {}

const MalformedSyntax = SfvSyntaxError;

import { fromBase64, toBase64 } from './bytes.js';

// RFC 4648 base64 whose only "=" are the ones completing the final quantum (section 3.3), which is
// the only spelling RFC 8941 section 3.3.5 decodes: missing or partial padding is refused, and so
// is anything outside the alphabet, CR and LF included (@5zrf8gjk).
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Input bounds (@5zrf8gjk, ticks 65q7 and 6mhg), far above anything an honest signer sends and low
// enough that no parse is slow. The byte bound is checked by the caller before parsing; these
// counts are enforced as the parse reaches them, so an over-long list is refused without being
// read to its end.
export const MAX_FIELD_BYTES = 8192;
export const MAX_DICTIONARY_MEMBERS = 16;
export const MAX_INNER_LIST_ITEMS = 64;
export const MAX_PARAMETERS = 16;

class Cursor {
  constructor(text) {
    this.text = text;
    this.at = 0;
  }

  get done() {
    return this.at >= this.text.length;
  }

  peek() {
    return this.text[this.at];
  }

  take() {
    return this.text[this.at++];
  }

  // RFC 8941 distinguishes SP, which is all it allows inside an inner list, after a parameter's
  // ";" and at the start of a field, from OWS (SP or HTAB), which it allows only around a list or
  // dictionary comma and after a member (section 4.2).
  skipSP() {
    while (!this.done && this.peek() === ' ') this.at += 1;
  }

  skipOWS() {
    while (!this.done && (this.peek() === ' ' || this.peek() === '\t')) this.at += 1;
  }

  expect(char) {
    if (this.done || this.peek() !== char) {
      throw new MalformedSyntax(`Expected "${char}" at offset ${this.at} of ${this.text}.`);
    }
    this.at += 1;
  }
}

function parseKey(cursor) {
  // RFC 8941 section 3.1.2: lcalpha / "*" to start, then lcalpha / digit / "_" / "-" / "." / "*".
  const start = cursor.at;
  if (!/[a-z*]/.test(cursor.peek() ?? '')) {
    throw new MalformedSyntax(`A key must start with a lowercase letter or "*", at offset ${start}.`);
  }
  while (!cursor.done && /[a-z0-9_\-.*]/.test(cursor.peek())) cursor.at += 1;
  return cursor.text.slice(start, cursor.at);
}

// RFC 8941 section 3.3.3: unescaped = %x20-21 / %x23-5B / %x5D-7E.
const UNESCAPED = /^[\x20\x21\x23-\x5b\x5d-\x7e]$/;

function parseString(cursor) {
  cursor.expect('"');
  let out = '';
  while (!cursor.done) {
    const char = cursor.take();
    if (char === '\\') {
      // A lone trailing backslash takes nothing, which is no escape either.
      const escaped = cursor.take();
      if (escaped !== '"' && escaped !== '\\') {
        throw new MalformedSyntax('Only \\" and \\\\ may be escaped in a string.');
      }
      out += escaped;
    } else if (char === '"') {
      return out;
    } else if (UNESCAPED.test(char)) {
      out += char;
    } else {
      throw new MalformedSyntax('A string holds printable ASCII and nothing else.');
    }
  }
  throw new MalformedSyntax('A string ran to the end of the field without closing.');
}

function parseByteSequence(cursor) {
  cursor.expect(':');
  const start = cursor.at;
  while (!cursor.done && cursor.peek() !== ':') cursor.at += 1;
  const encoded = cursor.text.slice(start, cursor.at);
  cursor.expect(':');
  if (!BASE64.test(encoded)) {
    throw new MalformedSyntax('A byte sequence must be base64 between colons.');
  }
  return fromBase64(encoded);
}

/** An RFC 8941 token (section 3.3.4), kept apart from a string, which fiki reads and a token it
 * never does. */
export class Token {
  constructor(value) {
    this.value = value;
  }
}

/** An RFC 8941 decimal (section 3.3.2), kept apart from an integer, so that `created=1.5` is a
 * parameter of the wrong type rather than a time. */
export class Decimal {
  constructor(value) {
    this.value = value;
  }
}

// RFC 8941 section 4.2.6: ALPHA or "*", then tchar, ":" or "/".
const TOKEN_START = /^[A-Za-z*]$/;
const TOKEN_CHAR = /^[!#$%&'*+\-.^_`|~0-9A-Za-z:/]$/;

function parseToken(cursor) {
  const start = cursor.at;
  cursor.at += 1;
  while (!cursor.done && TOKEN_CHAR.test(cursor.peek())) cursor.at += 1;
  return new Token(cursor.text.slice(start, cursor.at));
}

// RFC 8941 section 4.2.4: an integer of at most fifteen digits, or a decimal of at most twelve
// integer and three fractional digits, with at least one of each. Fifteen digits is also what keeps
// an integer exact in a JavaScript number: a longer one would round, and a rounded `created` is a
// different one.
const NUMBER = /^-?(?:[0-9]{1,15}(?![0-9.])|[0-9]{1,12}\.[0-9]{1,3}(?![0-9]))/;

function parseNumber(cursor) {
  const match = NUMBER.exec(cursor.text.slice(cursor.at, cursor.at + 18));
  if (match === null) {
    throw new MalformedSyntax(
      `Expected an integer of at most 15 digits, or a decimal of at most 12 and 3, at offset ${cursor.at} of ${cursor.text}.`,
    );
  }
  cursor.at += match[0].length;
  // An RFC 8941 integer is a whole number, which has no negative zero: "-0" is 0, as the httpwg
  // corpus expects, and adding 0 turns JavaScript's -0 into it.
  return match[0].includes('.') ? new Decimal(Number(match[0])) : Number(match[0]) + 0;
}

function parseBareItem(cursor) {
  const char = cursor.peek();
  if (char === '"') return parseString(cursor);
  if (char === ':') return parseByteSequence(cursor);
  if (char === '?') {
    cursor.take();
    const flag = cursor.take();
    if (flag !== '0' && flag !== '1') throw new MalformedSyntax('A boolean is ?0 or ?1.');
    return flag === '1';
  }
  if (char === '-' || /[0-9]/.test(char ?? '')) return parseNumber(cursor);
  if (TOKEN_START.test(char ?? '')) return parseToken(cursor);
  throw new MalformedSyntax(`Unsupported item at offset ${cursor.at} of ${cursor.text}.`);
}

function parseParameters(cursor) {
  const params = new Map();
  while (!cursor.done && cursor.peek() === ';') {
    cursor.take();
    cursor.skipSP();
    const key = parseKey(cursor);
    if (!cursor.done && cursor.peek() === '=') {
      cursor.take();
      params.set(key, parseBareItem(cursor));
    } else {
      params.set(key, true);
    }
    if (params.size > MAX_PARAMETERS) {
      throw new MalformedSyntax(`An item carries more than ${MAX_PARAMETERS} parameters.`);
    }
  }
  return params;
}

function parseInnerList(cursor) {
  cursor.expect('(');
  const items = [];
  for (;;) {
    cursor.skipSP();
    if (cursor.done) throw new MalformedSyntax('An inner list ran to the end of the field.');
    if (cursor.peek() === ')') {
      cursor.take();
      break;
    }
    items.push({ value: parseBareItem(cursor), params: parseParameters(cursor) });
    if (items.length > MAX_INNER_LIST_ITEMS) {
      throw new MalformedSyntax(`An inner list holds more than ${MAX_INNER_LIST_ITEMS} items.`);
    }
    if (!cursor.done && cursor.peek() !== ' ' && cursor.peek() !== ')') {
      throw new MalformedSyntax(`Expected a space or ")" at offset ${cursor.at}.`);
    }
  }
  return { items, params: parseParameters(cursor) };
}

/** Parse one RFC 8941 item with its parameters, the whole of `text`: `"@path";req`. */
export function parseItem(text) {
  const cursor = new Cursor(text);
  cursor.skipSP();
  const item = { value: parseBareItem(cursor), params: parseParameters(cursor) };
  cursor.skipSP();
  if (!cursor.done) throw new MalformedSyntax(`Unexpected text after the item at offset ${cursor.at} of ${text}.`);
  return item;
}

/** Parse an RFC 8941 list of items and inner lists (section 4.2.1).
 *
 * fiki reads no list-valued header, so this exists for the httpwg corpus (@7fexwu3s). It applies the
 * dictionary's member bound to a list's members, so that every entry point applies all four bounds.
 */
export function parseList(text) {
  const cursor = new Cursor(text);
  const out = [];
  cursor.skipSP();
  while (!cursor.done) {
    out.push(member(cursor));
    if (out.length > MAX_DICTIONARY_MEMBERS) {
      throw new MalformedSyntax(`A list holds more than ${MAX_DICTIONARY_MEMBERS} members.`);
    }
    if (separated(cursor)) break;
  }
  return out;
}

// A list or dictionary member's value: an inner list, or an item with its parameters.
const member = (cursor) =>
  cursor.peek() === '(' ? parseInnerList(cursor) : { value: parseBareItem(cursor), params: parseParameters(cursor) };

// After a list or dictionary member: true at the end of the field, past a comma otherwise.
function separated(cursor) {
  cursor.skipOWS();
  if (cursor.done) return true;
  cursor.expect(',');
  cursor.skipOWS();
  if (cursor.done) throw new MalformedSyntax('A list or dictionary ended with a trailing comma.');
  return false;
}

/** Parse an RFC 8941 dictionary whose members are inner lists or byte sequences. */
export function parseDictionary(text) {
  const cursor = new Cursor(text);
  const out = new Map();
  cursor.skipSP();
  while (!cursor.done) {
    const key = parseKey(cursor);
    let value;
    if (!cursor.done && cursor.peek() === '=') {
      cursor.take();
      value = member(cursor);
    } else {
      value = { value: true, params: parseParameters(cursor) };
    }
    out.set(key, value);
    if (out.size > MAX_DICTIONARY_MEMBERS) {
      throw new MalformedSyntax(`A dictionary holds more than ${MAX_DICTIONARY_MEMBERS} members.`);
    }
    if (separated(cursor)) break;
  }
  return out;
}

// RFC 8941 section 4.1.5: at most three fractional digits, and at least one. Only ever handed what
// parseNumber read, which has at most three already.
const serializeDecimal = (value) => value.toFixed(3).replace(/0{1,2}$/, '');

const serializeBareItem = (value) => {
  if (typeof value === 'string') return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  if (typeof value === 'number') return String(value);
  // A token or a decimal reaches here only as a parameter a verifier received, which fiki
  // reserializes to compare one component with another before it refuses the parameter.
  if (value instanceof Token) return value.value;
  if (value instanceof Decimal) return serializeDecimal(value.value);
  // Only `false` reaches here: RFC 8941 renders a true-valued parameter as a bare key, which
  // serializeParameters does before calling this, and fiki never puts a boolean in an item
  // position. A `?1` arm would be unreachable.
  if (value === false) return '?0';
  return `:${toBase64(value)}:`;
};

const serializeParameters = (params) =>
  [...params].map(([key, value]) => (value === true ? `;${key}` : `;${key}=${serializeBareItem(value)}`)).join('');

/** Serialize one item with its parameters: `{value: '@path', params: {req: true}}` is `"@path";req`. */
export const serializeItem = ({ value, params }) => `${serializeBareItem(value)}${serializeParameters(params)}`;

/** Serialize an inner list of covered components with its signature parameters. */
export function serializeInnerList({ items, params }) {
  return `(${items.map(serializeItem).join(' ')})${serializeParameters(params)}`;
}

/** Serialize a byte sequence as a dictionary member, which is how RFC 9421 carries a signature. */
export const serializeByteSequence = (bytes) => serializeBareItem(bytes);
