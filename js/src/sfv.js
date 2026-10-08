// The RFC 8941 subset RFC 9421 actually uses (`this.i` @2q9gv70t).
//
// Hand-rolled rather than depended upon, because fiki's slice of structured fields is small and
// CLOSED — a dictionary whose members are inner lists of strings with parameters, plus byte
// sequences — and because a browser library with no dependencies ships as one file with no supply
// chain. The usual argument against writing your own parser holds where the grammar is open-ended;
// this one's entire output surface is pinned byte for byte by the shared vectors.
//
// What is deliberately NOT here: decimals, tokens, and every field type RFC 9421 never puts in
// these two headers. A parser that accepts less than the spec can only refuse things fiki would
// not have understood anyway, which is the safe direction. Inner-list items DO carry parameters,
// because RFC 9421 section 2.4's `req` is one, and fiki decides what a parameter means only after
// the parse, where refusing it can name the component rather than the syntax (@7f28p7xk).

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

  skipSpace() {
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

function parseString(cursor) {
  cursor.expect('"');
  let out = '';
  while (!cursor.done) {
    const char = cursor.take();
    if (char === '\\') {
      const escaped = cursor.take();
      if (escaped !== '"' && escaped !== '\\') {
        throw new MalformedSyntax(`Only \\" and \\\\ may be escaped in a string, not \\${escaped}.`);
      }
      out += escaped;
    } else if (char === '"') {
      return out;
    } else {
      out += char;
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

function parseInteger(cursor) {
  const start = cursor.at;
  if (cursor.peek() === '-') cursor.at += 1;
  while (!cursor.done && /[0-9]/.test(cursor.peek())) cursor.at += 1;
  const digits = cursor.text.slice(start, cursor.at);
  // RFC 8941 section 3.3.1 caps an integer at fifteen digits, which is also what keeps it exact
  // in a JavaScript number: a longer one would round, and a rounded `created` is a different one.
  if (!/^-?[0-9]{1,15}$/.test(digits)) {
    throw new MalformedSyntax(`Expected an integer of at most 15 digits at offset ${start} of ${cursor.text}.`);
  }
  return Number(digits);
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
  if (char === '-' || /[0-9]/.test(char ?? '')) return parseInteger(cursor);
  throw new MalformedSyntax(`Unsupported item at offset ${cursor.at} of ${cursor.text}.`);
}

function parseParameters(cursor) {
  const params = new Map();
  while (!cursor.done && cursor.peek() === ';') {
    cursor.take();
    cursor.skipSpace();
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
    cursor.skipSpace();
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
  cursor.skipSpace();
  const item = { value: parseBareItem(cursor), params: parseParameters(cursor) };
  cursor.skipSpace();
  if (!cursor.done) throw new MalformedSyntax(`Unexpected text after the item at offset ${cursor.at} of ${text}.`);
  return item;
}

/** Parse an RFC 8941 dictionary whose members are inner lists or byte sequences. */
export function parseDictionary(text) {
  const cursor = new Cursor(text);
  const out = new Map();
  cursor.skipSpace();
  while (!cursor.done) {
    const key = parseKey(cursor);
    let value;
    if (!cursor.done && cursor.peek() === '=') {
      cursor.take();
      value =
        cursor.peek() === '('
          ? parseInnerList(cursor)
          : { value: parseBareItem(cursor), params: parseParameters(cursor) };
    } else {
      value = { value: true, params: parseParameters(cursor) };
    }
    out.set(key, value);
    if (out.size > MAX_DICTIONARY_MEMBERS) {
      throw new MalformedSyntax(`A dictionary holds more than ${MAX_DICTIONARY_MEMBERS} members.`);
    }
    cursor.skipSpace();
    if (cursor.done) break;
    cursor.expect(',');
    cursor.skipSpace();
    if (cursor.done) throw new MalformedSyntax('A dictionary ended with a trailing comma.');
  }
  return out;
}

const serializeBareItem = (value) => {
  if (typeof value === 'string') return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  if (typeof value === 'number') return String(value);
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
