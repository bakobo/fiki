// Signing and verifying whole HTTP requests (`this.i` @2hwvpm42, @7xrx5evg, @67shl6c5).
//
// The `keyid` is always the signer's raw key and is not overridable, so "the request carries its
// own verifying key" holds for every fiki-signed request rather than being a default somebody can
// wander off. A body is always covered or the signature is refused. And a verifier states a
// freshness policy or explicitly declines one.
//
// The bound worth stating plainly: fiki cannot cover a body it was never given. The guarantee is
// "hand fiki the body and it is covered, or fiki refuses" — a caller who omits `body` gets a valid
// signature over a request whose body nothing protects, and no library can detect that from the
// inside.

import { equal, fromBase64Url, toBase64, utf8 } from './bytes.js';
import { CONTENT_DIGEST, DEFAULT_COVERED, componentLines, signatureBase } from './base.js';
import {
  DigestMismatch,
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
  UncoveredBody,
  UnsupportedAlgorithm,
} from './errors.js';
import { toAid, verifySignature } from './keys.js';
import { parseDictionary, serializeByteSequence, serializeInnerList } from './sfv.js';

export const ALG = 'ed25519';

// Two hosts disagreeing by a second is ordinary; a verifier that treats it as an attack is
// unusable. Adjustable per call, because a satellite link and a rack are not the same problem.
export const DEFAULT_SKEW = 5;

const DIGEST_ALGORITHMS = { 'sha-256': 'SHA-256', 'sha-512': 'SHA-512' };
const DIGEST_OUT = 'sha-256';

/** The RFC 9530 `Content-Digest` header value for a body. */
export async function contentDigest(body) {
  const digest = await crypto.subtle.digest(DIGEST_ALGORITHMS[DIGEST_OUT], body);
  return `${DIGEST_OUT}=:${toBase64(new Uint8Array(digest))}:`;
}

/** Sign a request, returning the headers to add to it. */
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
}) {
  const supplied = headers ?? {};
  const sending = { ...supplied };
  // Whether the caller CHOSE the covered set is the difference between fiki helping and fiki
  // overriding. On the default path a body simply gets covered; on an explicit path, silently
  // adding a component would mean the signature covers something the caller did not ask for.
  const chosen = covered !== null;
  const components = (chosen ? covered : DEFAULT_COVERED).map((c) => c.toLowerCase());

  if (body !== null) {
    if (!components.includes(CONTENT_DIGEST)) {
      if (chosen) {
        throw new UncoveredBody(
          'This request carries a body, but the covered components do not include ' +
            `"${CONTENT_DIGEST}", so the signature would not bind the body. Add it to the ` +
            'covered set, or omit the body if it is genuinely not part of what you are signing.',
        );
      }
      components.push(CONTENT_DIGEST);
    }
    if (!Object.keys(sending).some((name) => name.toLowerCase() === CONTENT_DIGEST)) {
      sending['Content-Digest'] = await contentDigest(body);
    }
  }

  const base = signatureBase({
    method,
    url,
    headers: sending,
    covered: components,
    created: created === null ? Math.floor(Date.now() / 1000) : created,
    keyid: key.keyid,
    alg: ALG,
    expires,
    nonce,
    tag,
  });
  const signature = await key.sign(base);

  const params = new TextDecoder().decode(base).split('"@signature-params": ').at(-1);
  const out = {
    'Signature-Input': `${label}=${params}`,
    Signature: `${label}=${serializeByteSequence(signature)}`,
  };
  if (
    sending['Content-Digest'] !== undefined &&
    !Object.keys(supplied).some((name) => name.toLowerCase() === CONTENT_DIGEST)
  ) {
    out['Content-Digest'] = sending['Content-Digest'];
  }
  return out;
}

/** Verify a signed request, returning a verdict or throwing.
 *
 * `maxAge` has no default and must be given: seconds of tolerance, or `null` to decline the
 * check. Both defaults would be wrong (@67shl6c5). An `expires` the signer declared is enforced
 * regardless. `now` is injectable so a conformance vector can pin a freshness case.
 */
export async function verifyRequest({
  method,
  url,
  headers,
  maxAge,
  body = null,
  expectedAid = null,
  skew = DEFAULT_SKEW,
  now = null,
}) {
  if (maxAge === undefined) {
    throw new TypeError(
      'verifyRequest requires maxAge: seconds of tolerance, or null to decline the check. ' +
        'There is no default because both defaults are wrong.',
    );
  }
  const found = new Map();
  for (const [name, value] of Object.entries(headers ?? {})) found.set(name.toLowerCase(), value);

  const { inner, signature } = read(found);

  const alg = inner.params.get('alg');
  if (alg !== undefined && alg !== ALG) {
    throw new UnsupportedAlgorithm(
      `This signature is made with "${alg}", and fiki verifies only ${ALG} signatures.`,
      { alg },
    );
  }

  const covered = inner.items;
  const aid = resolve(expectedAid, inner.params.get('keyid'));

  const lines = componentLines({ method, url, headers, covered });
  lines.push(`"@signature-params": ${serializeInnerList(inner)}`);
  const base = utf8(lines.join('\n'));

  if (!(await verifySignature(aid, signature, base))) {
    throw new SignatureMismatch(
      "The signature does not match this request under the signer's key, so the request cannot " +
        'be treated as authentic.',
    );
  }

  // AFTER the signature check, deliberately. created and expires are covered by the signature, so
  // acting on them before verifying it would enforce a policy against values an attacker could
  // still have chosen — and would tell that attacker their forgery at least parsed.
  checkFreshness(inner.params, { maxAge, skew, now });

  if (covered.includes(CONTENT_DIGEST)) {
    await checkDigest(found.get(CONTENT_DIGEST), body);
  }

  return { aid, covered };
}

function read(found) {
  const rawInput = found.get('signature-input');
  const rawSignature = found.get('signature');
  if (!rawInput) {
    throw new MissingSignatureInput(
      'This request has no Signature-Input header, so there is no way to know which components ' +
        'a signature would cover.',
    );
  }
  if (!rawSignature) {
    throw new MissingSignature('This request has no Signature header, so there is nothing to verify.');
  }

  const inputs = parse(rawInput, 'Signature-Input', MalformedSignatureInput);
  const signatures = parse(rawSignature, 'Signature', MalformedSignature);

  const labels = [...inputs.keys()];
  if (labels.length !== 1) {
    throw new MalformedSignatureLabel(
      `fiki verifies a request carrying exactly one signature; this one declares ${labels.length}.`,
    );
  }
  const [label] = labels;
  if (!signatures.has(label) || signatures.size !== 1) {
    throw new MissingSignatureLabel(
      `The Signature header carries no entry labelled "${label}", so the covered components ` +
        'describe a signature that is not here.',
      { label },
    );
  }

  const value = signatures.get(label).value;
  if (!(value instanceof Uint8Array)) {
    throw new MalformedSignatureValue(
      'RFC 9421 carries the signature as an RFC 8941 byte sequence, wrapped in colons; this one ' +
        'is something else.',
    );
  }
  return { inner: inputs.get(label), signature: value };
}

function parse(raw, name, ErrorClass) {
  try {
    return parseDictionary(raw);
  } catch {
    throw new ErrorClass(
      `I could not parse the ${name} header; RFC 9421 spells it as an RFC 8941 dictionary.`,
    );
  }
}

function resolve(expectedAid, keyid) {
  if (expectedAid !== null && expectedAid !== undefined) return expectedAid;
  if (!keyid) {
    throw new MissingKey(
      'This signature carries no keyid and no expectedAid was supplied, so there is no key to ' +
        'verify it against.',
    );
  }
  let raw;
  try {
    raw = fromBase64Url(keyid);
  } catch {
    raw = new Uint8Array(0);
  }
  if (raw.length !== 32) {
    throw new MalformedKey(
      `The keyid "${keyid}" is not a base64url-encoded 32-byte Ed25519 public key.`,
      { keyid },
    );
  }
  return toAid(raw);
}

function checkFreshness(params, { maxAge, skew, now }) {
  const expires = params.get('expires');
  if (expires === undefined && maxAge === null) return;
  const stamp = now === null || now === undefined ? Math.floor(Date.now() / 1000) : now;

  if (expires !== undefined && stamp > expires + skew) {
    throw new SignatureExpired(
      `This signature expired at ${expires} and it is now ${stamp}, so the signer has already ` +
        'declared it should not be accepted.',
      { expires, now: stamp },
    );
  }
  if (maxAge === null) return;

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

async function checkDigest(header, body) {
  // The header is covered by the signature, so it cannot have been tampered with — but a covered
  // digest still only attests to a body nobody hashed until somebody hashes it.
  if (body === null || body === undefined) {
    throw new DigestMismatch(
      'The signature covers content-digest, but no body was supplied to check it against, so ' +
        'the body is unverified.',
    );
  }
  const parsed = parse(header, 'Content-Digest', MalformedDigest);
  for (const [name, member] of parsed) {
    const algorithm = DIGEST_ALGORITHMS[name.toLowerCase()];
    if (algorithm === undefined) continue;
    const digest = new Uint8Array(await crypto.subtle.digest(algorithm, body));
    if (!equal(digest, member.value)) {
      throw new DigestMismatch(
        `The request body does not match its ${name} Content-Digest, so the body is not the one ` +
          'that was signed.',
      );
    }
    return;
  }
  throw new MalformedDigest(
    'The Content-Digest header names no algorithm fiki computes; it computes ' +
      `${Object.keys(DIGEST_ALGORITHMS).sort().join(' and ')}.`,
  );
}
