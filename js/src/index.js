// fiki — sign and verify HTTP requests with a bare Ed25519 key as the identifier.
//
// Standard RFC 9421, with one lens: an Ed25519 public key is rendered as a non-transferable AID
// (CESR Ed25519N, a 44-character `B…` string), so the identifier is the verifying key and a
// verifier resolves nothing — unless the caller names another keyid, such as a KERI AID, and
// supplies the resolver for it (@6g9zjsv9). Zero dependencies; everything cryptographic comes
// from WebCrypto, which is why the API is async where the Python port's is not (@2q9gv70t).

// The conformance contract this port satisfies (`this.i` @4fhrre0m). Two artifacts interoperate
// when their declared vectors format matches, whatever their own version numbers say — so this is
// the number to compare, not the release. Monotonic, because a conformance contract has no
// meaningful minor: an implementation either satisfies the vectors or it does not.
export const VECTORS_FORMAT = 3;

// The KERI profile's own conformance contract, vectors/keri/ (`this.i` @8vwrexxc, @9enyfktu). A
// separate number from VECTORS_FORMAT, because the two sets answer to different authorities and
// move independently.
export const KERI_VECTORS_FORMAT = 4;

export * as errors from './errors.js';
export { FikiError } from './errors.js';
export { MAX_DICTIONARY_MEMBERS, MAX_FIELD_BYTES, MAX_INNER_LIST_ITEMS, MAX_PARAMETERS } from './sfv.js';
export { Key, toAid, verifyingKey, verifySignature } from './keys.js';
export {
  CONTENT_DIGEST,
  DEFAULT_COVERED,
  DERIVED,
  componentLines,
  req,
  responseSignatureBase,
  signatureBase,
} from './base.js';
export {
  ALG,
  DEFAULT_MINIMUM,
  DEFAULT_SKEW,
  REQUEST_MINIMUM,
  RESPONSE_MINIMUM,
  contentDigest,
  signRequest,
  signResponse,
  verifyRequest,
  verifyResponse,
} from './messages.js';
