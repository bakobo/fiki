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

const DEFAULT_PORTS = { http: '80', https: '443', ws: '80', wss: '443' };

/** A component identifier from a caller's spelling of it.
 *
 * A plain name (`"@method"`, `"Content-Digest"`) or its RFC 8941 serialization with parameters
 * (`'"@method";req'`). Names are lowercased as a convenience to a local caller; a name parsed from
 * the wire is never lowercased, and is refused instead when it is not already.
 */
export function component(spec) {
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

/** A URL split as sent, per RFC 3986 section 3, with nothing decoded or normalized.
 *
 * Not `new URL`, which follows the WHATWG URL standard: it resolves dot segments and
 * percent-encodes characters such as a space, so its pathname is not the path that was sent. The
 * KERI profile requires @path "in its encoded form, percent-encoding included and unnormalized"
 * (section 2), and so does RFC 9421 section 2.2.6, which is what fiki-py's urlsplit gives.
 */
export function splitUrl(url) {
  const match = /^(?:([A-Za-z][A-Za-z0-9+.-]*):)?(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?/.exec(url);
  const [, scheme = '', netloc, path, query = ''] = match;
  return { scheme: scheme.toLowerCase(), netloc: netloc ?? '', path, query };
}

function authority(parts, headers) {
  // RFC 9421 section 2.2.3: lowercase host, default port omitted. A relative URL falls back to the
  // Host header, which in HTTP/1.1 *is* the authority — the shape a server-side verifier actually
  // holds. Nothing is normalized away there, because without a scheme no port is a default port.
  if (parts.netloc) {
    const hostport = parts.netloc.slice(parts.netloc.lastIndexOf('@') + 1).toLowerCase();
    const [, host, port = ''] = /^(\[[^\]]*\]|[^:]*)(?::(.*))?$/.exec(hostport);
    if (port === '') return host;
    // RFC 3986 section 3.2.3: port = *DIGIT, so any run of ASCII digits, leading zeros and all, and
    // the value is the number: "000080" is 80 and is the default, as urlsplit reads it. The range
    // is checked on the digits that remain, so a long run of zeros cannot hide an overflow.
    const digits = /^[0-9]+$/.test(port) ? port.replace(/^0+(?=[0-9])/, '') : null;
    if (digits === null || digits.length > 5 || Number(digits) > 65535) {
      throw new TypeError(`The URL's port "${port}" is not a port number between 0 and 65535.`);
    }
    if (digits === DEFAULT_PORTS[parts.scheme]) return host;
    return `${host}:${digits}`;
  }
  const host = headers.get('host');
  if (host === undefined) {
    throw new MissingComponent(
      'The signature covers "@authority", but the URL carries no authority and the request has ' +
        'no Host header, so there is nothing to derive it from.',
      { component: '@authority' },
    );
  }
  return ows(checked(host, '"@authority"')).toLowerCase();
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
  for (const [name, value] of Object.entries(canonicalHeaders(headers))) map.set(name, String(value));
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

export function requestMessage(method, url, headers) {
  // A method is the caller's to supply, and an absent one would otherwise be signed as the string
  // "undefined". Required here, where every request and every response's request passes.
  if (typeof method !== 'string' || method === '') {
    throw new TypeError(`A request needs its method as a non-empty string, as sent; got ${String(method) || 'an empty string'}.`);
  }
  return { headers: lowered(headers), method, parts: splitUrl(url) };
}

export const responseMessage = (status, headers, request) => ({
  headers: lowered(headers),
  status,
  request: request ? requestMessage(request.method, request.url, request.headers) : null,
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
  if (name === '@authority') return authority(source.parts, source.headers);
  // An empty path is the "/" the origin server would have received.
  if (name === '@path') return source.parts.path || '/';
  // Section 2.2.7: the whole query string including the leading "?", percent-encoding preserved,
  // and a bare "?" when the request carries no query at all.
  if (name === '@query') return `?${source.parts.query}`;
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
  const items = covered.map(component);
  checkCovered(items, { response: true });
  return finishBase(items, responseMessage(status, headers, request), { created, expires, nonce, alg, keyid, tag });
}
