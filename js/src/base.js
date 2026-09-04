// The RFC 9421 signature base, section 2.5 (`this.i` @2hwvpm42, @2q9gv70t).
//
// Public surface, not an internal detail. When two implementations disagree about a signature,
// the base is where they disagree, and a caller debugging an interop failure needs to see the
// bytes both sides actually hashed.
//
// Derived components fiki builds: @method, @authority, @path, @query. Anything else raises rather
// than being skipped — a component silently dropped from the base is a component the caller
// believes is covered and is not.

import { utf8 } from './bytes.js';
import { MissingComponent, UnsupportedComponent } from './errors.js';
import { serializeInnerList } from './sfv.js';

export const DERIVED = ['@method', '@authority', '@path', '@query'];

// @method, @authority, @path, @query — plus content-digest whenever there is a body (@2hwvpm42).
// This closes the query, host, and body gaps that heti's KERI dialect leaves open and
// structurally cannot close. `created` is a signature parameter rather than a component.
export const DEFAULT_COVERED = ['@method', '@authority', '@path', '@query'];

export const CONTENT_DIGEST = 'content-digest';

// Order is the signer's choice — a verifier reserializes whatever it received — so fiki fixes one
// order and keeps it, which makes its own output reproducible.
const PARAM_ORDER = ['created', 'expires', 'nonce', 'alg', 'keyid', 'tag'];

const DEFAULT_PORTS = { 'http:': '80', 'https:': '443', 'ws:': '80', 'wss:': '443' };

// A relative URL has no authority of its own, and `new URL` will not parse one without a base.
// This base is never read: only pathname, search, hostname and port are used, and the fallback
// below supplies the authority from the Host header instead.
const RELATIVE_BASE = 'https://relative.invalid';

function split(url) {
  const relative = !/^[a-z][a-z0-9+.-]*:/i.test(url);
  const parsed = new URL(url, relative ? RELATIVE_BASE : undefined);
  return { parsed, relative };
}

function authority({ parsed, relative }, headers) {
  // RFC 9421 section 2.2.3: lowercase host, default port omitted. A relative URL falls back to the
  // Host header, which in HTTP/1.1 *is* the authority — the shape a server-side verifier actually
  // holds. Nothing is normalized away there, because without a scheme no port is a default port.
  if (!relative) {
    const host = parsed.hostname.toLowerCase();
    if (parsed.port === '' || parsed.port === DEFAULT_PORTS[parsed.protocol]) return host;
    return `${host}:${parsed.port}`;
  }
  const host = headers.get('host');
  if (host === undefined) {
    throw new MissingComponent(
      'The signature covers "@authority", but the URL carries no authority and the request has ' +
        'no Host header, so there is nothing to derive it from.',
      { component: '@authority' },
    );
  }
  return host.toLowerCase();
}

function componentValue(component, method, url, headers) {
  if (component === '@method') return method.toUpperCase();
  if (component === '@authority') return authority(url, headers);
  // `new URL` never yields an empty pathname — a bare authority gives "/" — so unlike the Python
  // port there is no empty-path fallback here. One that could not fire would be a guard claiming
  // to guard something.
  if (component === '@path') return url.parsed.pathname;
  // Section 2.2.7: the whole query string including the leading "?", percent-encoding preserved,
  // and a bare "?" when the request carries no query at all.
  if (component === '@query') return `?${url.parsed.search.slice(1)}`;
  if (component.startsWith('@')) {
    throw new UnsupportedComponent(
      `fiki does not build the derived component "${component}"; it builds ${DERIVED.join(', ')}.`,
      { component, supported: DERIVED.join(', ') },
    );
  }
  const value = headers.get(component);
  if (value === undefined) {
    throw new MissingComponent(
      `The signature covers "${component}", but the request carries no value for it, so the ` +
        'signature base cannot be built.',
      { component },
    );
  }
  return value;
}

const lowerHeaders = (headers) => {
  // Header field names are case-insensitive and appear lowercased in the base (section 2.1);
  // values are stripped of leading and trailing whitespace.
  const map = new Map();
  for (const [name, value] of Object.entries(headers ?? {})) map.set(name.toLowerCase(), String(value).trim());
  return map;
};

/** Every line of the signature base except the trailing `@signature-params`.
 *
 * Split out because the verify side cannot call `signatureBase`: it must reserialize the
 * parameters exactly as they arrived, in the order they arrived, rather than in fiki's own fixed
 * order — a verifier that reorders what it received computes a different base and rejects a good
 * signature.
 */
export function componentLines({ method, url, headers, covered }) {
  const parsed = split(url);
  const lowered = lowerHeaders(headers);
  return covered.map(
    (component) => `"${component.toLowerCase()}": ${componentValue(component.toLowerCase(), method, parsed, lowered)}`,
  );
}

/** Build the RFC 9421 signature base for a request. */
export function signatureBase({ method, url, headers, covered, created, keyid, alg, expires, nonce, tag }) {
  const components = covered.map((component) => component.toLowerCase());
  const lines = componentLines({ method, url, headers, covered: components });

  const params = new Map();
  const values = { created, expires, nonce, alg, keyid, tag };
  for (const name of PARAM_ORDER) {
    if (values[name] !== undefined && values[name] !== null) params.set(name, values[name]);
  }
  lines.push(`"@signature-params": ${serializeInnerList({ items: components, params })}`);

  return utf8(lines.join('\n'));
}
