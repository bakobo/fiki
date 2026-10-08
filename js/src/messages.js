// Signing and verifying whole HTTP requests and responses (`this.i` @2hwvpm42, @7xrx5evg,
// @67shl6c5, @6g9zjsv9, @7f28p7xk, @9enyfktu).
//
// The `keyid` is the signer's raw key unless the caller names another, so "the request carries
// its own verifying key" holds for every fiki-signed request whose caller did not deliberately
// choose otherwise — and a verifier handed a resolver never falls back to reading a key out of the
// keyid. A body is always covered or the signature is refused. And a verifier states a freshness
// policy or explicitly declines one.
//
// The bound worth stating plainly: fiki cannot cover a body it was never given. The guarantee is
// "hand fiki the body and it is covered, or fiki refuses" — a caller who omits `body` gets a valid
// signature over a request whose body nothing protects, and no library can detect that from the
// inside.

import { equal, toBase64, toBase64Url, fromBase64Url, utf8 } from './bytes.js';
import {
  CONTENT_DIGEST,
  DEFAULT_COVERED,
  canonicalHeaders,
  checkCovered,
  component,
  finishBase,
  identity,
  linesFor,
  req,
  requestMessage,
  responseMessage,
  specOf,
  valueOf,
} from './base.js';
import {
  DigestMismatch,
  InsufficientCoverage,
  MalformedDigest,
  MalformedKey,
  MalformedSignature,
  MalformedSignatureInput,
  MalformedSignatureLabel,
  MalformedSignatureValue,
  MissingKey,
  MissingSignature,
  MissingSignatureInput,
  MissingSignatureLabel,
  SignatureExpired,
  SignatureMismatch,
  SignatureTooOld,
  Unauthenticated,
  UncoveredBody,
  UnknownKey,
  UnsupportedAlgorithm,
} from './errors.js';
import { checkKey, misspelledAid, toAid, verifyWithRaw, verifyingKey } from './keys.js';
import { parseDictionary, serializeByteSequence, serializeInnerList } from './sfv.js';

export const ALG = 'ed25519';

// Two hosts disagreeing by a second is ordinary; a verifier that treats it as an attack is
// unusable. Adjustable per call, because a satellite link and a rack are not the same problem.
export const DEFAULT_SKEW = 5;

// RFC 9530. sha-256 on the way out; both are accepted on the way in, because fiki is not the only
// thing that will ever have signed a request it is asked to verify. Every one of these a header
// carries must match; any other algorithm is ignored (RFC 9530 section 2).
// Maps rather than object literals, here and below, because both are keyed by names a message
// supplies, and an object literal answers "constructor" or "__proto__" from Object.prototype
// (Copilot review of PR #5, C4).
const DIGEST_ALGORITHMS = new Map([
  ['sha-256', 'SHA-256'],
  ['sha-512', 'SHA-512'],
]);
const DIGEST_OUT = 'sha-256';

// RFC 9421 section 2.3's six signature parameters and the RFC 8941 type each must have. Anything
// else is refused rather than carried: a parameter fiki does not understand could be one whose
// meaning the signer relied on (@7f28p7xk).
const SIGNATURE_PARAMS = new Map([
  ['created', 'number'],
  ['expires', 'number'],
  ['nonce', 'string'],
  ['alg', 'string'],
  ['keyid', 'string'],
  ['tag', 'string'],
]);
const SIGNATURE_LENGTH = 64;
const KEY_LENGTH = 32;
// The RFC 8037 "x" form of a raw keyid (@7xrx5evg): 32 bytes, base64url, unpadded.
const RAW_KEYID = /^[A-Za-z0-9_-]{43}$/;

// The KERI profile's minimum covered sets (section 3), for a verifier's `minimum`. A body adds
// content-digest on top, and a response to a request that had a body adds "content-digest";req.
export const REQUEST_MINIMUM = Object.freeze(['@method', '@path', '@query']);
export const RESPONSE_MINIMUM = Object.freeze(['@status', req('@method'), req('@path'), req('@query')]);

/** A body as bytes, normalized once at the boundary, or null when none was handed over.
 *
 * A Uint8Array, any other ArrayBufferView, an ArrayBuffer, or a string, which is encoded as UTF-8.
 * Anything else is a TypeError rather than "no body": a type fiki silently failed to read would be
 * a body that escapes coverage, which is the one thing the body rule exists to prevent (@2hwvpm42).
 */
export function bodyBytes(body, name = 'body') {
  if (body === null || body === undefined) return null;
  if (body instanceof Uint8Array) return body;
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (typeof body === 'string') return utf8(body);
  throw new TypeError(
    `${name} must be a Uint8Array, another ArrayBufferView, an ArrayBuffer or a string; this one is ` +
      `${Object.prototype.toString.call(body)}, which fiki cannot read as bytes.`,
  );
}

// The request a response answers, with its body as bytes and its headers canonical, once.
const normalRequest = (request) =>
  request === null || request === undefined
    ? null
    : { ...request, headers: canonicalHeaders(request.headers, 'request.headers'), body: bodyBytes(request.body, 'request.body') };

/** The RFC 9530 `Content-Digest` header value for a body. */
export async function contentDigest(body) {
  const digest = await crypto.subtle.digest(DIGEST_ALGORITHMS.get(DIGEST_OUT), bodyBytes(body));
  return `${DIGEST_OUT}=:${toBase64(new Uint8Array(digest))}:`;
}

const now = () => Math.floor(Date.now() / 1000);
// Only ever handed what bodyBytes returned, so a body is null or a Uint8Array.
const hasContent = (body) => body !== null && body.length > 0;
// Both only ever see headers canonicalHeaders has already lowercased.
const hasName = (headers, name) => Object.hasOwn(headers, name);
const lowered = (headers) => new Map(Object.entries(headers));

/** A supplied minimum selects the KERI profile's policy, so it may only add to the profile's.
 *
 * Anything smaller is the caller's mistake rather than a message's defect, so it is a TypeError,
 * thrown before any message is read (bakobo/fiki#4).
 */
function floored(minimum, floor) {
  if (minimum === null || minimum === undefined) return null;
  const given = new Set(minimum.map((spec) => identity(component(spec))));
  const missing = floor.filter((spec) => !given.has(identity(component(spec))));
  if (missing.length > 0) {
    throw new TypeError(
      `A minimum covered set must include the profile's own, ${floor.join(', ')}; this one leaves ` +
        `out ${missing.join(', ')}. Pass null to apply no minimum at all.`,
    );
  }
  return minimum;
}

const bindsRequestDigest = (items) => items.some((item) => identity(item) === identity(component(req(CONTENT_DIGEST))));
const coversBody = (items) => items.some((item) => identity(item) === identity(component(CONTENT_DIGEST)));

/** Cover a body the caller handed over, or refuse to sign (@2hwvpm42). */
async function coverBody(items, sending, body, chosen) {
  if (body === null) return;
  // Whether the caller CHOSE the covered set is the difference between fiki helping and fiki
  // overriding. On the default path a body simply gets covered; on an explicit path, silently
  // adding a component would mean the signature covers something the caller did not ask for, so
  // the same situation is a refusal instead.
  if (!coversBody(items)) {
    if (chosen) {
      throw new UncoveredBody(
        'This message carries a body, but the covered components do not include ' +
          `"${CONTENT_DIGEST}", so the signature would not bind the body. Add it to the covered ` +
          'set, or omit the body if it is genuinely not part of what you are signing.',
      );
    }
    items.push(component(CONTENT_DIGEST));
  }
  if (!hasName(sending, CONTENT_DIGEST)) sending[CONTENT_DIGEST] = await contentDigest(body);
}

async function signed(key, base, label, sending, given) {
  const signature = await key.sign(base);
  const params = new TextDecoder().decode(base).split('"@signature-params": ').at(-1);
  const out = {
    'Signature-Input': `${label}=${params}`,
    Signature: `${label}=${serializeByteSequence(signature)}`,
  };
  if (sending[CONTENT_DIGEST] !== undefined && !hasName(given, CONTENT_DIGEST)) {
    out['Content-Digest'] = sending[CONTENT_DIGEST];
  }
  return out;
}

const createdOr = (created) => (created === null || created === undefined ? now() : created);

/** Sign a request, returning the headers to add to it.
 *
 * With a `body` and no explicit `covered`, fiki computes a `Content-Digest`, returns it among the
 * headers, and covers it. With a `body` and an explicit `covered` that omits `content-digest`,
 * fiki throws UncoveredBody rather than signing a request whose body nothing binds.
 *
 * `method` is signed exactly as given (@22g0xkr8), so pass it as it will go on the wire. `keyid`
 * defaults to the key itself (@7xrx5evg); name another, such as a KERI AID, only when the verifier
 * resolves it (@6g9zjsv9). `minimum`, such as REQUEST_MINIMUM, makes the signer refuse a covered
 * list its verifier would refuse (@2f227n4r).
 */
export async function signRequest({
  key,
  method,
  url,
  headers,
  body = null,
  covered = null,
  created = null,
  label = 'sig',
  expires,
  nonce,
  tag,
  keyid = null,
  minimum = null,
}) {
  const floor = floored(minimum, REQUEST_MINIMUM);
  body = bodyBytes(body);
  headers = canonicalHeaders(headers);
  const sending = Object.assign(Object.create(null), headers);
  const chosen = covered !== null && covered !== undefined;
  const items = (chosen ? covered : DEFAULT_COVERED).map(component);
  await coverBody(items, sending, body, chosen);
  if (floor !== null) {
    checkMinimum(items, floor, { hasBody: requestHasBody(lowered(sending), body), requestHadBody: false });
  }
  checkCovered(items, { response: false });
  const base = finishBase(items, requestMessage(method, url, sending), {
    created: createdOr(created),
    expires,
    nonce,
    alg: ALG,
    keyid: keyid ?? key.keyid,
    tag,
  });
  return signed(key, base, label, sending, headers);
}

/** Sign a response, returning the headers to add to it (RFC 9421 section 2.4).
 *
 * `request` is the request it answers, `{method, url, headers, body}`. By default the signature
 * covers `@status`, a `Content-Digest` of any body, and — when the request is given — that
 * request's method, path and query, plus its `content-digest` when it carried content, each
 * marked `req`. That binds the response to what was asked. A request whose content was non-empty
 * is bound by its `Content-Digest` (its headers do not count, @7p9s3g9k), and one with no digest
 * to bind is refused as UncoveredBody rather than signed into a response every profile client
 * refuses (@2f227n4r). A digest the request body contradicts is refused the way the verifier
 * would refuse it.
 */
export async function signResponse({
  key,
  status,
  request = null,
  headers,
  body = null,
  covered = null,
  created = null,
  label = 'sig',
  expires,
  nonce,
  tag,
  keyid = null,
  minimum = null,
}) {
  const floor = floored(minimum, RESPONSE_MINIMUM);
  body = bodyBytes(body);
  request = normalRequest(request);
  headers = canonicalHeaders(headers);
  const sending = Object.assign(Object.create(null), headers);
  const chosen = covered !== null && covered !== undefined;
  // By content alone: both sides hold the whole request by now (profile section 3, @7p9s3g9k).
  const hadBody = request !== null && hasContent(request.body);
  const specs = chosen ? covered : ['@status', ...(request === null ? [] : [req('@method'), req('@path'), req('@query')])];
  const items = specs.map(component);
  await coverBody(items, sending, body, chosen);
  if (!chosen && hadBody) {
    if (!hasName(request.headers, CONTENT_DIGEST)) {
      throw new UncoveredBody(
        'The request this response answers carried a body and no Content-Digest, so the response ' +
          'has nothing to bind that body with. Sign the request with a digest first, or name the ' +
          'covered components yourself.',
      );
    }
    items.push(component(req(CONTENT_DIGEST)));
  }
  if (floor !== null) checkMinimum(items, floor, { hasBody: hasContent(body), requestHadBody: hadBody });
  // The check verifyResponse will make, made first: a signer does not vouch for a request digest
  // that the request body it was handed contradicts (bakobo/fiki#4).
  if (request !== null && request.body !== null && bindsRequestDigest(items)) {
    await compareDigest(readDigest(lowered(request.headers).get(CONTENT_DIGEST)), request.body);
  }
  checkCovered(items, { response: true });
  const base = finishBase(items, responseMessage(status, sending, request), {
    created: createdOr(created),
    expires,
    nonce,
    alg: ALG,
    keyid: keyid ?? key.keyid,
    tag,
  });
  return signed(key, base, label, sending, headers);
}

/** Verify a signed request, returning a verdict `{aid, covered, keyid}` or throwing.
 *
 * `maxAge` has no default and must be given: seconds of tolerance, or `null` to decline the
 * check. Both defaults would be wrong (@67shl6c5). An `expires` the signer declared is enforced
 * regardless. `now` is injectable so a conformance vector can pin a freshness case.
 *
 * `expectedAid` is authoritative when supplied, the preregistration case. `resolve` is the other
 * way to be authoritative (@6g9zjsv9): a function from the keyid to the 32 raw bytes of the key it
 * names, or null when it names none, returning either directly or as a promise. Pass one or
 * neither.
 *
 * `minimum` is the verifier's covered-set policy, REQUEST_MINIMUM or a superset of it: a
 * signature covering less is refused even though it verifies, and so is a body — signalled by
 * `Content-Length` above zero, any `Transfer-Encoding`, or simply arriving — without a covered
 * `content-digest` (@7f28p7xk). `null` enforces no minimum, body rule included. `expectedKeyid`
 * refuses a signature by any other keyid as UnknownKey. `authorities` is the set of `@authority`
 * values this verifier serves; a covered `@authority` outside it is a SignatureMismatch, and
 * supplying it makes `@authority` required, so a signature that does not cover it is
 * InsufficientCoverage (@605z9tnw).
 */
export async function verifyRequest({
  method,
  url,
  headers,
  maxAge,
  body = null,
  expectedAid = null,
  skew = DEFAULT_SKEW,
  now: at = null,
  resolve = null,
  minimum = null,
  expectedKeyid = null,
  authorities = null,
}) {
  requireMaxAge(maxAge, 'verifyRequest');
  const floor = floored(minimum, REQUEST_MINIMUM);
  headers = canonicalHeaders(headers);
  return verify(requestMessage(method, url, headers), headers, bodyBytes(body), {
    response: false,
    request: null,
    maxAge,
    expectedAid,
    skew,
    now: at,
    resolve,
    minimum: floor,
    expectedKeyid,
    authorities: authorities === null || authorities === undefined ? null : new Set(authorities),
  });
}

/** Verify a signed response to `request`, returning a verdict or throwing.
 *
 * The arguments are verifyRequest's, with `status` in place of the method and URL and the
 * `request` the response answers, `{method, url, headers, body}`, which its `req` components are
 * read from. Under RESPONSE_MINIMUM, a request with non-empty content obliges the response to
 * cover `"content-digest";req`. A response's body is its content, never its `Content-Length`, so a
 * HEAD or 304 response is bodiless whatever length it announces. A client should pass
 * `expectedKeyid`, the AID it is talking to (profile R1). An unsigned 401 is Unauthenticated,
 * checked before anything else, because a server that refuses before it knows the agent cannot
 * sign the refusal (@2f227n4r). A response covering `"content-digest";req` verified against a
 * request whose body is null is a TypeError: fiki cannot check a body it was not given.
 */
export async function verifyResponse({
  status,
  headers,
  maxAge,
  request = null,
  body = null,
  expectedAid = null,
  skew = DEFAULT_SKEW,
  now: at = null,
  resolve = null,
  minimum = null,
  expectedKeyid = null,
}) {
  requireMaxAge(maxAge, 'verifyResponse');
  const floor = floored(minimum, RESPONSE_MINIMUM);
  body = bodyBytes(body);
  request = normalRequest(request);
  headers = canonicalHeaders(headers);
  if (status === 401 && !hasName(headers, 'signature')) {
    throw new Unauthenticated(
      'The server answered 401 without signing the answer, so the request was not authenticated ' +
        'and the body of the refusal cannot be trusted.',
    );
  }
  return verify(responseMessage(status, headers, request), headers, body, {
    response: true,
    request,
    maxAge,
    expectedAid,
    skew,
    now: at,
    resolve,
    minimum: floor,
    expectedKeyid,
    authorities: null,
  });
}

function requireMaxAge(maxAge, name) {
  if (maxAge === undefined) {
    throw new TypeError(
      `${name} requires maxAge: seconds of tolerance, or null to decline the check. There is no ` +
        'default because both defaults are wrong.',
    );
  }
}

/** The KERI profile's section 9 order, so a message has exactly one correct refusal. */
async function verify(message, headers, body, options) {
  const { response, request, maxAge, expectedAid, skew, now: at, resolve, minimum, expectedKeyid, authorities } = options;
  if (expectedAid !== null && resolve !== null) {
    throw new TypeError('Pass expectedAid or resolve, not both; each decides the key alone.');
  }

  const found = lowered(headers);
  // keyid is REQUIRED under a minimum, which is how a caller applies the KERI profile, even when
  // expectedAid decides the key: that argument chooses the key, not whether the message is well
  // formed (the rust port's hostile review of PR #5).
  const { inner, signature } = read(found, {
    requireKeyid: expectedAid === null || minimum !== null,
    requireCreated: minimum !== null,
  });
  const { items } = inner;
  checkCovered(items, { response });
  if (minimum !== null) {
    checkMinimum(items, minimum, {
      hasBody: response ? hasContent(body) : requestHasBody(found, body),
      // By the request's content alone, as signResponse decides it (@7p9s3g9k).
      requestHadBody: request !== null && hasContent(request.body),
    });
  }
  // Served authorities bind the signature to a host only if it commits to one, so supplying
  // them makes @authority required (@605z9tnw): coverage, before the key, as section 9 orders.
  if (authorities !== null) checkMinimum(items, ['@authority'], { hasBody: false, requestHadBody: false });

  const received = inner.params.get('keyid') ?? null;
  const { raw, aid, keyid } = await resolveKey(expectedAid, received, resolve, expectedKeyid);
  const alg = inner.params.get('alg');
  if (alg !== undefined && alg !== ALG) {
    throw new UnsupportedAlgorithm(`This signature is made with "${alg}", and fiki verifies only ${ALG} signatures.`, {
      alg,
    });
  }

  const lines = linesFor(items, message);
  lines.push(`"@signature-params": ${serializeInnerList(inner)}`);
  if (!(await verifyWithRaw(raw, signature, utf8(lines.join('\n'))))) {
    throw new SignatureMismatch(
      "The signature does not match this message under the signer's key, so the message cannot be " +
        'treated as authentic.',
    );
  }

  if (authorities !== null) {
    for (const item of items) {
      if (item.value === '@authority' && !authorities.has(valueOf(item, message))) {
        throw new SignatureMismatch(
          `The signature covers the authority "${valueOf(item, message)}", which this verifier does ` +
            'not serve, so it was signed for somebody else.',
        );
      }
    }
  }

  // AFTER the signature check, deliberately. created and expires are covered by the signature, so
  // acting on them before verifying it would enforce a policy against values an attacker could
  // still have chosen — and would tell that attacker their forgery at least parsed.
  checkFreshness(inner.params, { maxAge, skew, now: at });

  const digests = [];
  if (coversBody(items)) digests.push([found.get(CONTENT_DIGEST), body]);
  // A response binding the request's digest binds a request body only if somebody hashes it
  // (bakobo/fiki#4). A verifier handed no request body cannot, and a verdict that skipped the
  // check would look like one that made it, so that is the caller's mistake, not a pass.
  if (request !== null && bindsRequestDigest(items)) {
    if (request.body === null) {
      throw new TypeError(
        'The response covers "content-digest";req, so the request body it binds must be supplied ' +
          'in request.body to be checked; it was not.',
      );
    }
    digests.push([lowered(request.headers).get(CONTENT_DIGEST), request.body]);
  }
  // Every covered digest is parsed before any is compared, so a malformed one outranks a
  // mismatched one wherever each sits (profile section 9, bakobo/fiki#4).
  const parsed = digests.map(([header, content]) => [readDigest(header), content]);
  for (const [recognized, content] of parsed) await compareDigest(recognized, content);

  return { aid, covered: items.map(specOf), keyid };
}

/** The profile's request body test: a length above zero, any transfer coding, or content.
 *
 * Requests only. A response's body is its content, since a HEAD or 304 response carries the
 * length of a representation it does not send (@2f227n4r).
 */
function requestHasBody(found, body) {
  if (hasContent(body)) return true;
  if (found.has('transfer-encoding')) return true;
  const length = found.get('content-length');
  if (length === undefined) return false;
  // Fail closed: a length that is not a plain decimal, negative ones included, is not evidence
  // that there is no body.
  // Field whitespace is SP and HTAB only (RFC 9110 section 5.5); String.prototype.trim also strips
  // NBSP, VT and the rest, which would read such a length as a plain zero (Copilot, PR #5).
  const trimmed = String(length).replace(/^[ \t]+|[ \t]+$/g, '');
  return !/^[0-9]+$/.test(trimmed) || /[1-9]/.test(trimmed);
}

function checkMinimum(items, minimum, { hasBody, requestHadBody }) {
  const have = new Set(items.map(identity));
  const required = minimum.map(component);
  if (hasBody) required.push(component(CONTENT_DIGEST));
  if (requestHadBody) required.push(component(req(CONTENT_DIGEST)));
  for (const item of required) {
    if (!have.has(identity(item))) {
      throw new InsufficientCoverage(
        `The signature does not cover ${specOf(item)}, which this verifier requires, so it is ` +
          'refused even though it may be valid: a signature over too little is a signature over ' +
          'what an intermediary is free to change.',
        { component: specOf(item) },
      );
    }
  }
}

/** Enforce the verifier's `maxAge`, then the signer's `expires` (profile section 9). */
function checkFreshness(params, { maxAge, skew, now: at }) {
  const expires = params.get('expires');
  if (expires === undefined && maxAge === null) return;
  const stamp = at === null || at === undefined ? now() : at;

  if (maxAge !== null) {
    const created = params.get('created');
    if (created === undefined) {
      throw new SignatureTooOld(
        'This signature carries no created timestamp, so its age cannot be checked against the ' +
          `${maxAge}-second limit you asked for.`,
        { created: null, now: stamp, maxAge },
      );
    }
    if (stamp - created > maxAge + skew) {
      throw new SignatureTooOld(
        `This signature was created at ${created}, which is more than ${maxAge} seconds before ` +
          `${stamp}, so it is too old to accept.`,
        { created, now: stamp, maxAge },
      );
    }
    if (created - stamp > skew) {
      throw new SignatureTooOld(
        `This signature claims to have been created at ${created}, which is in the future ` +
          `relative to ${stamp} by more than the ${skew}-second skew allowance.`,
        { created, now: stamp, maxAge },
      );
    }
  }

  if (expires !== undefined && stamp > expires + skew) {
    throw new SignatureExpired(
      `This signature expired at ${expires} and it is now ${stamp}, so the signer has already ` +
        'declared it should not be accepted.',
      { expires, now: stamp },
    );
  }
}

/** Pull one signature and its input out of the headers, or say what is wrong with them.
 *
 * In the KERI profile's section 9 order: absence before malformation, the Signature header before
 * Signature-Input, the members' shape before the label count.
 */
function read(found, { requireKeyid, requireCreated }) {
  const rawSignature = found.get('signature');
  const rawInput = found.get('signature-input');
  if (!rawSignature) {
    throw new MissingSignature('This message has no Signature header, so there is nothing to verify.');
  }
  if (!rawInput) {
    throw new MissingSignatureInput(
      'This message has no Signature-Input header, so there is no way to know which components a ' +
        'signature would cover.',
    );
  }

  const signatures = parse(rawSignature, 'Signature', MalformedSignature);
  for (const member of signatures.values()) {
    // Draft 6 of the KERI profile would call this malformed-signature, since such a header is
    // neither mode's form; the class stays the one the shared vectors pin (@2f227n4r).
    if (!(member.value instanceof Uint8Array)) {
      throw new MalformedSignatureValue(
        'RFC 9421 carries a signature as an RFC 8941 byte sequence, wrapped in colons; this ' +
          'Signature header carries something else.',
      );
    }
  }
  const inputs = parse(rawInput, 'Signature-Input', MalformedSignatureInput);
  for (const member of inputs.values()) checkInput(member, { requireKeyid, requireCreated });

  if (inputs.size !== 1 || signatures.size !== 1) {
    throw new MalformedSignatureLabel(
      'fiki verifies a message carrying exactly one signature; this one declares ' +
        `${inputs.size} in Signature-Input and ${signatures.size} in Signature.`,
    );
  }
  const [label] = inputs.keys();
  if (!signatures.has(label)) {
    throw new MissingSignatureLabel(
      `The Signature header carries no entry labelled "${label}", so the covered components ` +
        'describe a signature that is not here.',
      { label },
    );
  }

  const { value } = signatures.get(label);
  if (value.length !== SIGNATURE_LENGTH) {
    throw new MalformedSignatureValue(
      'RFC 9421 carries an Ed25519 signature as a 64-byte RFC 8941 byte sequence, wrapped in ' +
        'colons; this one is something else.',
    );
  }
  return { inner: inputs.get(label), signature: value };
}

/** Refuse a Signature-Input member fiki would otherwise have to guess about. */
function checkInput(member, { requireKeyid, requireCreated }) {
  if (member.items === undefined) {
    throw new MalformedSignatureInput(
      'A Signature-Input member is a parenthesized list of covered components; this one is a ' +
        'single value.',
    );
  }
  for (const item of member.items) {
    if (typeof item.value !== 'string') {
      throw new MalformedSignatureInput('Every covered component is named by a quoted string; one here is not.');
    }
    if (!item.value.startsWith('@') && item.value !== item.value.toLowerCase()) {
      throw new MalformedSignatureInput(
        `The covered field "${item.value}" is not lowercase, and RFC 9421 section 2.1 requires ` +
          'field names in the covered list to be lowercased by the signer.',
      );
    }
  }
  if (requireKeyid && !member.params.has('keyid')) {
    // Here rather than when the key is resolved: keyid is REQUIRED, so its absence belongs with
    // the other defects of Signature-Input, ahead of the covered list (@2f227n4r).
    throw new MissingKey(
      'This signature carries no keyid, and this verifier needs one: either no expectedAid names ' +
        'the key, or a minimum applies the KERI profile, where keyid is REQUIRED.',
    );
  }
  if (requireCreated && !member.params.has('created')) {
    // Only under a minimum, which is how a caller applies the KERI profile, where created is
    // REQUIRED. RFC 9421 makes it optional, and without a minimum it stays so (@7p9s3g9k).
    throw new MalformedSignatureInput(
      "This signature carries no created timestamp, which the verifier's policy requires.",
    );
  }
  for (const [name, value] of member.params) {
    const expected = SIGNATURE_PARAMS.get(name);
    if (expected === undefined) {
      throw new MalformedSignatureInput(
        `The signature parameter "${name}" is not one fiki understands; it accepts ` +
          `${[...SIGNATURE_PARAMS.keys()].join(', ')}.`,
      );
    }
    if (typeof value !== expected) {
      throw new MalformedSignatureInput(
        `The signature parameter "${name}" must be ${expected === 'number' ? 'an integer' : 'a quoted string'}.`,
      );
    }
  }
}

function parse(raw, name, ErrorClass) {
  try {
    return parseDictionary(raw);
  } catch {
    throw new ErrorClass(`I could not parse the ${name} header; RFC 9421 spells it as an RFC 8941 dictionary.`);
  }
}

/** The key to verify with, the identity to report, and the keyid as received.
 *
 * In section 9's order as far as fiki can see it without asking anyone (@0ekvjgsp): the keyid's
 * own spelling (malformed-key), then whether it is the one the client expected (unknown-key), and
 * only then the resolver. A keyid that is not the expected one is refused without a lookup, so
 * untrusted input never makes the verifier wait on one; the resolver's own refusals therefore
 * apply only to the expected keyid.
 */
async function resolveKey(expectedAid, keyid, resolve, expectedKeyid) {
  const expect = () => {
    if (expectedKeyid !== null && keyid !== expectedKeyid) {
      throw new UnknownKey(`This message is signed by "${keyid}", and the one expected is "${expectedKeyid}".`, {
        keyid,
      });
    }
  };
  if (expectedAid !== null) {
    const raw = verifyingKey(expectedAid);
    expect();
    return { raw, aid: toAid(raw), keyid };
  }
  if (!keyid) {
    throw new MissingKey(
      'This signature carries no keyid and no expectedAid was supplied, so there is no key to ' +
        'verify it against.',
    );
  }
  if (resolve !== null) {
    if (misspelledAid(keyid)) {
      throw new MalformedKey(
        `The keyid "${keyid}" is shaped like an AID and is not its canonical spelling, so it is ` +
          'not an AID at all.',
        { keyid },
      );
    }
    expect();
    // The resolver is authoritative: fiki never falls back to decoding the keyid, because a
    // transferable prefix that embeds a key embeds its INCEPTION key (@6g9zjsv9).
    const raw = await resolve(keyid);
    if (raw === null || raw === undefined) {
      throw new UnknownKey(`No key is known for the keyid "${keyid}", so the signature cannot be checked.`, { keyid });
    }
    if (!(raw instanceof Uint8Array) || raw.length !== KEY_LENGTH) {
      throw new MalformedKey(`The key resolved for "${keyid}" is not a ${KEY_LENGTH}-byte Ed25519 public key.`, {
        keyid,
      });
    }
    return { raw: checkKey(raw, keyid), aid: keyid, keyid };
  }
  // Strictly: a lenient decoder discards characters outside the alphabet and ignores trailing
  // bits, so a keyid that is not the key's encoding could verify as whatever key it happened to
  // decode to. Only the one canonical spelling is a key.
  const raw = RAW_KEYID.test(keyid) ? fromBase64Url(keyid) : null;
  if (raw === null || toBase64Url(raw) !== keyid) {
    throw new MalformedKey(
      `The keyid "${keyid}" is not the canonical base64url spelling of a 32-byte Ed25519 public ` +
        'key: that is exactly 43 characters from the base64url alphabet, unpadded.',
      { keyid },
    );
  }
  checkKey(raw, keyid);
  expect();
  return { raw, aid: toAid(raw), keyid };
}

/** Parse a Content-Digest into the members fiki computes, or refuse it as MalformedDigest.
 *
 * Separate from the comparison so that a verifier holding two covered digests can parse both
 * before hashing either: section 9 of the KERI profile puts malformed-digest first.
 */
function readDigest(header) {
  const parsed = parse(header ?? '', 'Content-Digest', MalformedDigest);
  const recognized = [];
  for (const [name, member] of parsed) {
    const algorithm = DIGEST_ALGORITHMS.get(name);
    if (algorithm === undefined) continue;
    if (!(member.value instanceof Uint8Array)) {
      throw new MalformedDigest(
        `The ${name} Content-Digest is not an RFC 8941 byte sequence, so it cannot be compared with anything.`,
      );
    }
    recognized.push([name, algorithm, member.value]);
  }
  if (recognized.length === 0) {
    throw new MalformedDigest(
      'The Content-Digest header names no algorithm fiki computes; it computes ' +
        `${[...DIGEST_ALGORITHMS.keys()].sort().join(' and ')}.`,
    );
  }
  return recognized;
}

/** Recompute the digest over the body actually received (@2hwvpm42).
 *
 * The header is covered by the signature, so it cannot have been tampered with — but a covered
 * digest still only attests to a body nobody hashed until somebody hashes it.
 */
async function compareDigest(recognized, body) {
  if (body === null) {
    throw new DigestMismatch(
      'The signature covers content-digest, but no body was supplied to check it against, so the ' +
        'body is unverified.',
    );
  }
  for (const [name, algorithm, expected] of recognized) {
    const digest = new Uint8Array(await crypto.subtle.digest(algorithm, body));
    if (!equal(digest, expected)) {
      throw new DigestMismatch(
        `The body does not match its ${name} Content-Digest, so the body is not the one that was signed.`,
      );
    }
  }
}
