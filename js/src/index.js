// fiki — sign and verify HTTP requests with a bare Ed25519 key as the identifier.
//
// Standard RFC 9421, with one lens: an Ed25519 public key is rendered as a non-transferable AID
// (CESR Ed25519N, a 44-character `B…` string), so the identifier is the verifying key and a
// verifier resolves nothing. Zero dependencies; everything cryptographic comes from WebCrypto,
// which is why the API is async where the Python port's is not (`this.i` @2q9gv70t).

export * as errors from './errors.js';
export { FikiError } from './errors.js';
export { Key, toAid, verifyingKey, verifySignature } from './keys.js';
export { CONTENT_DIGEST, DEFAULT_COVERED, DERIVED, componentLines, signatureBase } from './base.js';
export { ALG, DEFAULT_SKEW, contentDigest, signRequest, verifyRequest } from './messages.js';
