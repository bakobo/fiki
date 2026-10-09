// The RFC 9421 signature base, section 2.5 (`this.i` @2hwvpm42, @2q9gv70t, @7f28p7xk).
//
// Public surface, not an internal detail. When two implementations disagree about a signature,
// the base is where they disagree, and a caller debugging an interop failure needs to see the
// bytes both sides actually hashed.
//
// Derived components fiki builds: @method, @authority, @path, @query in a request, and @status in
// a response, which may also name its request's components with the `req` parameter of section
// 2.4. Anything else raises rather than being skipped — a component silently dropped from the base
// is a component the caller believes is covered and is not.

import { utf8 } from './bytes.js';
import { DuplicateComponent, MissingComponent, SignatureMismatch, UnsupportedComponent } from './errors.js';
import { parseItem, serializeInnerList, serializeItem } from './sfv.js';

export const DERIVED = ['@method', '@authority', '@path', '@query'];

// The one derived component a response has of its own (RFC 9421 section 2.2.9). Every request
// component reaches a response only through `req`.
export const RESPONSE_DERIVED = ['@status'];

// @method, @authority, @path, @query — plus content-digest whenever there is a body (@2hwvpm42).
// This closes the query, host, and body gaps that heti's KERI dialect leaves open and
// structurally cannot close. `created` is a signature parameter rather than a component.
export const DEFAULT_COVERED = ['@method', '@authority', '@path', '@query'];

export const CONTENT_DIGEST = 'content-digest';

// The only component parameter fiki supports, and only in a response (RFC 9421 section 2.4).
const REQ = 'req';

// Order is the signer's choice — a verifier reserializes whatever it received — so fiki fixes one
// order and keeps it, which makes its own output reproducible.
const PARAM_ORDER = ['created', 'expires', 'nonce', 'alg', 'keyid', 'tag'];

// A Map, because it is keyed by the caller's scheme, and an object literal would answer
// "constructor" from Object.prototype (Copilot review of PR #5, C4).
const DEFAULT_PORTS = new Map([
  ['http', '80'],
  ['https', '443'],
  ['ws', '80'],
  ['wss', '443'],
]);

// RFC 9110 section 5.6.2: a token is one or more tchar. A method is one (section 9.1), and so is a
// field name (section 5.1), which fiki further requires lowercased in a covered list.
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
// RFC 8941 section 3.3.3: an sf-string holds printable ASCII and nothing else.
const SF_STRING = /^[\x20-\x7e]*$/;
// RFC 8941 section 3.1.2: a dictionary key, which is what a signature label is.
const SF_KEY = /^[a-z*][a-z0-9_.*-]*$/;
// RFC 8941 section 3.3.1: at most fifteen digits.
const SF_INTEGER_MAX = 999_999_999_999_999;

// A caller's value in a message about it: quoted when it is a string, so a control character shows.
const shown = (value) => (typeof value === 'string' ? JSON.stringify(value) : String(value));

/** A component identifier from a caller's spelling of it.
 *
 * A plain name (`"@method"`, `"Content-Digest"`) or its RFC 8941 serialization with parameters
 * (`'"@method";req'`). Names are lowercased as a convenience to a local caller; a name parsed from
 * the wire is never lowercased, and is refused instead when it is not already. A field name that
 * is not a token is the caller's mistake, a TypeError, because it would be serialized into
 * Signature-Input as given (@5zrf8gjk); a derived name fiki does not build is refused later, as
 * UnsupportedComponent, which names it.
 */
export function component(spec) {
  const item = componentItem(spec);
  if (!item.value.startsWith('@') && !TOKEN.test(item.value)) {
    throw new TypeError(
      `${JSON.stringify(spec)} is not a component fiki can name: a field is named by an HTTP field ` +
        'name, one or more token characters, and a derived component by its @ name.',
    );
  }
  return item;
}

function componentItem(spec) {
  if (!spec.startsWith('"')) return { value: spec.toLowerCase(), params: new Map() };
  let item;
  try {
    item = parseItem(spec);
  } catch {
    item = null;
  }
  // A spec that opens with a quote can only parse as a string, so the parse is the whole test.
  if (item === null) {
    throw new UnsupportedComponent(
      `fiki cannot read ${spec} as a component identifier; name a component plainly, as "@path", ` +
        `or in its serialized form, as '"@path";req'.`,
      { component: spec, supported: [...DERIVED, ...RESPONSE_DERIVED].join(', ') },
    );
  }
  return { value: item.value.toLowerCase(), params: item.params };
}

/** The spelling of a request component named from a response: `req('@path')` is `'"@path";req'`. */
export const req = (name) => serializeItem({ value: name.toLowerCase(), params: new Map([[REQ, true]]) });

/** The inverse of `component`: a plain name when it has no parameters. */
export const specOf = (item) => (item.params.size > 0 ? serializeItem(item) : item.value);

/** What two identifiers must share to be the same component. Parameter order is not it. */
export const identity = (item) => serializeItem({ value: item.value, params: new Map([...item.params].sort()) });

/** Refuse a covered list fiki cannot build faithfully: duplicates first, then the unsupported.
 *
 * That order is the KERI profile's section 9, so a list that is both has one correct refusal.
 */
export function checkCovered(items, { response }) {
  const seen = new Set();
  for (const item of items) {
    if (seen.has(identity(item))) {
      throw new DuplicateComponent(
        `The covered components name ${specOf(item)} twice, so the signature base would not be ` +
          'what either copy says it is.',
        { component: specOf(item) },
      );
    }
    seen.add(identity(item));
  }

  for (const item of items) {
    const isReq = item.params.get(REQ) === true;
    const others = [...item.params.keys()].some((name) => name !== REQ);
    if (others || (item.params.has(REQ) && !(isReq && response))) {
      throw new UnsupportedComponent(
        `fiki does not support the component ${specOf(item)}: the only component parameter it ` +
          `supports is "${REQ}", and only in a response.`,
        { component: specOf(item), supported: REQ },
      );
    }
    if (item.value.startsWith('@')) {
      const supported = isReq || !response ? DERIVED : RESPONSE_DERIVED;
      if (!supported.includes(item.value)) {
        throw new UnsupportedComponent(
          `fiki does not build the derived component ${specOf(item)} in a ` +
            `${response ? 'response' : 'request'}; it builds ${supported.join(', ')}.`,
          { component: specOf(item), supported: supported.join(', ') },
        );
      }
    }
  }
}

/** A URL fiki cannot read: the caller's mistake when signing, an unbuildable base when not.
 *
 * The profile's section 9 names a base that cannot be built a signature mismatch, so a received
 * URL whose authority cannot be read is refused like any other base that does not verify, never
 * thrown as an exception from outside fiki's taxonomy (@5zrf8gjk).
 */
function unreadable(message, reason) {
  if (message.received) {
    return new SignatureMismatch(
      `The URL ${message.url} cannot be read: ${reason} So there is no signature base to check the ` +
        'signature against.',
    );
  }
  return new TypeError(`The URL ${message.url} cannot be read: ${reason}`);
}

// A scheme, "://", and at least one character of authority (RFC 3986 section 3).
const ABSOLUTE = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]/;

/** The target as RFC 9112 section 3.2 reads it (@524c8qgv), split with nothing decoded.
 *
 * A target beginning with "/" is origin-form: everything before the first "?" is the path,
 * verbatim, however many slashes it starts with, and it has no authority of its own, so `authority`
 * reads the Host header. Reading "//evil.example/p" as a network-path reference would let the
 * sender choose the authority (review A1). Anything else must be an absolute URI with a non-empty
 * authority. A space or an ASCII control anywhere, or a fragment, which no request target has, is
 * refused rather than stripped.
 *
 * Not `new URL`, which follows the WHATWG URL standard: it resolves dot segments and
 * percent-encodes characters, so its pathname is not the path that was sent. The KERI profile
 * requires @path "in its encoded form, percent-encoding included and unnormalized" (section 2), and
 * so does RFC 9421 section 2.2.6. Split only when a component needs it, so a target nothing covers
 * is never refused, as in every other port.
 */
function splitUrl(message) {
  const { url } = message;
  if (/[\x00-\x20\x7f]/.test(url)) throw unreadable(message, 'it contains a space or a control character.');
  if (url.includes('#')) throw unreadable(message, 'it carries a fragment, which no request target has.');
  if (url.startsWith('/')) {
    const mark = url.indexOf('?');
    return mark < 0
      ? { scheme: '', netloc: '', path: url, query: '' }
      : { scheme: '', netloc: '', path: url.slice(0, mark), query: url.slice(mark + 1) };
  }
  if (!ABSOLUTE.test(url)) {
    throw unreadable(
      message,
      'it is neither origin-form, beginning with a slash, nor an absolute URI with a scheme and an authority.',
    );
  }
  // Split by index rather than by one regular expression: two adjacent classes that both match
  // "." backtrack polynomially on a long run of them (CodeQL js/polynomial-redos on #17).
  // ABSOLUTE has established scheme "://" authority, and a scheme holds no ":".
  const sep = url.indexOf('://');
  const rest = url.slice(sep + 3);
  const slash = rest.search(/[/?]/);
  const netloc = slash < 0 ? rest : rest.slice(0, slash);
  const target = slash < 0 ? '' : rest.slice(slash);
  const mark = target.indexOf('?');
  const path = mark < 0 ? target : target.slice(0, mark);
  const query = mark < 0 ? '' : target.slice(mark + 1);
  return { scheme: url.slice(0, sep).toLowerCase(), netloc, path, query };
}

const partsOf = (message) => {
  message.parts ??= splitUrl(message);
  return message.parts;
};

// RFC 3986 section 3.2.2's IP-literal, as Python's urlsplit checks it from 3.11.4, so a host fiki-py
// refuses is refused here too: IPvFuture ("v", hex digits, ".", then anything but a line feed), or
// an IPv6address with an optional zone after "%". The IPv6 grammar is RFC 3986's own, which accepts
// exactly what Python's ipaddress.IPv6Address does.
const H16 = '[0-9A-Fa-f]{1,4}';
const DEC_OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const LS32 = `(?:${H16}:${H16}|${DEC_OCTET}(?:\\.${DEC_OCTET}){3})`;
const IPV6 = [
  `(?:${H16}:){6}${LS32}`,
  `::(?:${H16}:){5}${LS32}`,
  `(?:${H16})?::(?:${H16}:){4}${LS32}`,
  `(?:(?:${H16}:){0,1}${H16})?::(?:${H16}:){3}${LS32}`,
  `(?:(?:${H16}:){0,2}${H16})?::(?:${H16}:){2}${LS32}`,
  `(?:(?:${H16}:){0,3}${H16})?::${H16}:${LS32}`,
  `(?:(?:${H16}:){0,4}${H16})?::${LS32}`,
  `(?:(?:${H16}:){0,5}${H16})?::${H16}`,
  `(?:(?:${H16}:){0,6}${H16})?::`,
].join('|');
const IP_LITERAL = new RegExp(`^(?:v[0-9A-Fa-f]+\\.[^\\n]+|(?:${IPV6})(?:%[^%]+)?)$`);

/** Split an authority's host-and-port into the host as written and the port's text.
 *
 * An IP-literal keeps its brackets, which RFC 3986 section 3.2.2 makes part of the host, and only
 * ":port" may follow its closing bracket. A bracket anywhere else is not a host.
 */
function hostAndPort(hostport, message) {
  if (hostport.startsWith('[')) {
    const close = hostport.indexOf(']');
    const rest = close < 0 ? '' : hostport.slice(close + 1);
    if (close < 0 || (rest !== '' && !rest.startsWith(':'))) {
      throw unreadable(message, 'an IP-literal must close with "]", followed by nothing but ":" and a port.');
    }
    if (!IP_LITERAL.test(hostport.slice(1, close))) {
      throw unreadable(message, 'its IP-literal is not an IPv6 address or IPvFuture.');
    }
    return [hostport.slice(0, close + 1), rest.slice(1)];
  }
  const colon = hostport.indexOf(':');
  const [host, port] = colon < 0 ? [hostport, ''] : [hostport.slice(0, colon), hostport.slice(colon + 1)];
  if (/[[\]]/.test(host)) throw unreadable(message, 'a bracket belongs only around an IP-literal.');
  return [host, port];
}

/** host[:port] normalized per RFC 9421 section 2.2.3, or a base that cannot be built.
 *
 * Lowercase host, default port omitted. RFC 3986 section 3.2.3: port = *DIGIT, so any run of ASCII
 * digits, leading zeros and all, and the value is the number: "000080" is 80. The range is checked
 * on the digits that remain, so a long run of zeros cannot hide an overflow. An empty port is no
 * port at all, as section 6.2.3 normalizes it.
 */
function hostport(text, scheme, message) {
  // Checked as written, before lowercasing: toLowerCase reads U+212A KELVIN SIGN as an ASCII "k",
  // so a host that is not ASCII could otherwise pass as one that is (review A6, B5).
  if (/[^\x00-\x7f]/.test(text)) throw unreadable(message, 'its host is not ASCII.');
  const [host, port] = hostAndPort(text, message);
  if (port === '') return host.toLowerCase();
  const digits = /^[0-9]+$/.test(port) ? port.replace(/^0+(?=[0-9])/, '') : null;
  if (digits === null || digits.length > 5 || Number(digits) > 65535) {
    throw unreadable(message, `its port "${port}" is not a number from 0 to 65535.`);
  }
  if (digits === DEFAULT_PORTS.get(scheme)) return host.toLowerCase();
  return `${host.toLowerCase()}:${digits}`;
}

function authority(message) {
  // A target with no authority of its own is origin-form, and the Host header, which in HTTP/1.1
  // *is* the authority, supplies it — the shape a server-side verifier actually holds.
  const { headers } = message;
  const parts = partsOf(message);
  if (parts.netloc) return hostport(parts.netloc.slice(parts.netloc.lastIndexOf('@') + 1), parts.scheme, message);
  const host = headers.get('host');
  if (host === undefined) {
    throw new MissingComponent(
      'The signature covers "@authority", but the URL carries no authority and the request has ' +
        'no Host header, so there is nothing to derive it from.',
      { component: '@authority' },
    );
  }
  const value = ows(checked(host, '"@authority"'));
  // Host passes the same checks as an absolute URL's authority, and with no scheme no port is a
  // default one (this.i, "Host is validated like any authority"). Userinfo and a list of hosts
  // have no place in it.
  if (/[@,]/.test(value)) throw unreadable(message, 'its Host header is not a single host and optional port.');
  return hostport(value, '', message);
}

/** Headers with every name lowercased, refusing two names that are one field (D-Q9ZT).
 *
 * Field names are case-insensitive, so `X-Role` beside `x-role` is two values for one field, and
 * keeping either would let a signer cover one while the application reads the other. Only a caller
 * can build such an object, so it is a TypeError. Values are kept exactly as given.
 */
export function canonicalHeaders(headers, name = 'headers') {
  // Null-prototype, so a field named "__proto__" is an own property like any other rather than an
  // assignment to the prototype that silently drops it (PR #5 hostile review, H1).
  const out = Object.create(null);
  for (const [field, value] of Object.entries(headers ?? {})) {
    // A name is always a string here, since an object's keys are; a value has to be checked
    // (@5zrf8gjk), or null would be signed as the string "null".
    if (typeof value !== 'string') {
      throw new TypeError(`A header is a name and a string value; the value of "${field}" is ${String(value)}.`);
    }
    const lower = field.toLowerCase();
    if (Object.hasOwn(out, lower)) {
      throw new TypeError(
        `${name} names the field "${lower}" twice in different case, so it holds two values for one ` +
          'field; pass one.',
      );
    }
    out[lower] = value;
  }
  return out;
}

function lowered(headers) {
  // Header field names are case-insensitive and appear lowercased in the base (section 2.1). Values
  // are kept exactly as received here: they are checked for forbidden characters before any
  // whitespace is trimmed, or a trailing CR LF would be trimmed into the value that was signed.
  const map = new Map();
  for (const [name, value] of Object.entries(canonicalHeaders(headers))) map.set(name, value);
  return map;
}

// Leading and trailing field whitespace, which RFC 9110 section 5.5 defines as SP and HTAB only.
const ows = (value) => value.replace(/^[ \t]+|[ \t]+$/g, '');

/** A value refused when it has no single serialization both sides agree on.
 *
 * A line break inside a value would forge a line of the base, and a byte outside visible ASCII is
 * encoded differently by different stacks. The KERI profile names such a base unbuildable, and so
 * a signature mismatch (@2f227n4r).
 */
function checked(value, spec) {
  if (!/^[\t\x20-\x7e]*$/.test(value)) {
    throw new SignatureMismatch(
      `The value of ${spec} contains a line break, a control character or a non-ASCII ` +
        'character, so there is no signature base both sides would build from it.',
    );
  }
  return value;
}

/** A request's method is an RFC 9110 token, covered or not, or the call is a mistake.
 *
 * Its case is kept as given (@22g0xkr8). Checked wherever a request message is built, on sign and
 * verify alike (@5zrf8gjk): an empty or spaced method is never a request anybody sent.
 */
function checkMethod(method) {
  if (typeof method !== 'string' || !TOKEN.test(method)) {
    throw new TypeError(
      `The method ${shown(method)} is not an HTTP method: a method is a ` +
        'string of one or more token characters, with no spaces, line breaks or separators.',
    );
  }
}

export function requestMessage(method, url, headers, { received = false } = {}) {
  checkMethod(method);
  // `received` marks a message handed to a verifier rather than built by a signer, which decides
  // what a URL that cannot be read is: a base that cannot be built, or a caller error.
  return { headers: lowered(headers), method, url, parts: null, received };
}

export const responseMessage = (status, headers, request, { received = false } = {}) => ({
  headers: lowered(headers),
  status,
  request: request ? requestMessage(request.method, request.url, request.headers, { received }) : null,
});

function componentValue(item, message) {
  let source = message;
  if (item.params.get(REQ) === true) {
    if (message.request === null) {
      throw new MissingComponent(
        `The signature covers ${specOf(item)}, which is read from the request this response ` +
          'answers, and no request was supplied.',
        { component: specOf(item) },
      );
    }
    source = message.request;
  }
  const name = item.value;
  if (name === '@status') {
    // Section 2.2.9: the three-digit status code. Anything else is not a status this component
    // can carry, so there is no value to sign or to check.
    const { status } = source;
    if (!Number.isInteger(status) || status < 100 || status > 999) {
      throw new MissingComponent(
        `The signature covers @status, and ${String(status)} is not a three-digit HTTP status ` +
          'code, so there is no status line to build.',
        { component: '@status' },
      );
    }
    return String(status);
  }
  // Section 2.2.1: the method as sent, with no case transformation (@22g0xkr8).
  if (name === '@method') return source.method;
  if (name === '@authority') return authority(source);
  // An empty path is the "/" the origin server would have received.
  if (name === '@path') return partsOf(source).path || '/';
  // Section 2.2.7: the whole query string including the leading "?", percent-encoding preserved,
  // and a bare "?" when the request carries no query at all.
  if (name === '@query') return `?${partsOf(source).query}`;
  const value = source.headers.get(name);
  if (value === undefined) {
    throw new MissingComponent(
      `The signature covers ${specOf(item)}, but the message carries no value for it, so the ` +
        'signature base cannot be built.',
      { component: specOf(item) },
    );
  }
  // Checked as received, then trimmed of field whitespace only.
  return ows(checked(value, specOf(item)));
}

/** A component's value, refused when it has no single serialization both sides agree on. */
export const valueOf = (item, message) => checked(componentValue(item, message), specOf(item));

/** Every line of the signature base except the trailing `@signature-params`. */
export const linesFor = (items, message) => items.map((item) => `${serializeItem(item)}: ${valueOf(item, message)}`);

/** Every line of a request's signature base except the trailing `@signature-params`.
 *
 * Split out because the verify side cannot call `signatureBase`: it must reserialize the
 * parameters exactly as they arrived, in the order they arrived, rather than in fiki's own fixed
 * order — a verifier that reorders what it received computes a different base and rejects a good
 * signature.
 */
export function componentLines({ method, url, headers, covered }) {
  const items = covered.map(component);
  checkCovered(items, { response: false });
  return linesFor(items, requestMessage(method, url, headers));
}

/** What a signer serializes must be serializable, or the call is a mistake (@5zrf8gjk).
 *
 * created and expires are RFC 8941 integers that are not negative; keyid, alg, nonce and tag are
 * sf-strings, printable ASCII only, so a line break can never forge a header line. An absent one
 * (undefined or null) is not serialized and so not checked.
 */
export function checkSignerParams({ created, expires, keyid, alg, nonce, tag }) {
  for (const [name, value] of [['created', created], ['expires', expires]]) {
    if (value === undefined || value === null) continue;
    if (!Number.isInteger(value) || value < 0 || value > SF_INTEGER_MAX) {
      throw new TypeError(
        `${name} is ${String(value)}, and RFC 8941 carries an integer of at most fifteen digits; fiki ` +
          `signs a whole number of seconds from 0 to ${SF_INTEGER_MAX}.`,
      );
    }
  }
  for (const [name, value] of [['keyid', keyid], ['alg', alg], ['nonce', nonce], ['tag', tag]]) {
    if (value === undefined || value === null) continue;
    if (typeof value !== 'string' || !SF_STRING.test(value)) {
      throw new TypeError(
        `The ${name} ${shown(value)} is not a string of printable ASCII, which is all an RFC ` +
          '8941 string can carry; a line break there would forge a header line.',
      );
    }
  }
}

/** A signature label is an RFC 8941 dictionary key, or the call is a mistake (@5zrf8gjk). */
export function checkLabel(label) {
  if (typeof label !== 'string' || !SF_KEY.test(label)) {
    throw new TypeError(
      `The label ${shown(label)} is not an RFC 8941 key: it starts with a lowercase letter ` +
        'or "*" and continues with lowercase letters, digits, "_", "-", "." and "*".',
    );
  }
}

/** The whole base for already-checked items: the component lines, then fiki's own parameters. */
export function finishBase(items, message, values) {
  const lines = linesFor(items, message);
  const params = new Map();
  for (const name of PARAM_ORDER) {
    if (values[name] !== undefined && values[name] !== null) params.set(name, values[name]);
  }
  lines.push(`"@signature-params": ${serializeInnerList({ items, params })}`);
  return utf8(lines.join('\n'));
}

/** Build the RFC 9421 signature base for a request.
 *
 * Throws DuplicateComponent for a component named twice, UnsupportedComponent for a derived
 * component outside DERIVED or a component parameter, and MissingComponent for a covered header
 * the request does not carry.
 */
export function signatureBase({ method, url, headers, covered, created, keyid, alg, expires, nonce, tag }) {
  checkSignerParams({ created, expires, keyid, alg, nonce, tag });
  const items = covered.map(component);
  checkCovered(items, { response: false });
  return finishBase(items, requestMessage(method, url, headers), { created, expires, nonce, alg, keyid, tag });
}

/** Build the RFC 9421 signature base for a response (sections 2.2.9 and 2.4).
 *
 * `request` is the request being answered, `{method, url, headers}`, which `req` components are
 * read from — spelled `req('@path')` or `'"@path";req'`. Without one, a `req` component is a
 * MissingComponent.
 */
export function responseSignatureBase({ status, headers, covered, created, keyid, request, alg, expires, nonce, tag }) {
  checkSignerParams({ created, expires, keyid, alg, nonce, tag });
  const items = covered.map(component);
  checkCovered(items, { response: true });
  return finishBase(items, responseMessage(status, headers, request), { created, expires, nonce, alg, keyid, tag });
}
