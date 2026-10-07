// fiki's exception taxonomy (`this.i` @8zw78n0v), one class per condition the Python port names.
//
// The class NAMES are the contract, not an implementation detail: `refusals.json` records the name
// fiki raises for each refusal, and this port's vector driver asserts on it. So a port that folds
// two conditions together fails a vector rather than passing quietly, and heti — which maps these
// onto its own codes — can be told what happened by a client in any language.
//
// The granularity comes from heti's code taxonomy, which distinguishes a missing header from an
// unparsable one, per header. That was built deliberately so a sender can be told which header to
// fix rather than handed the pair.

export class FikiError extends Error {
  constructor(message, fields = {}) {
    super(message);
    this.name = new.target.name;
    Object.assign(this, fields);
  }
}

/* --- something the request needs is absent --- */

export class MissingSignature extends FikiError {}
export class MissingSignatureInput extends FikiError {}
export class MissingSignatureLabel extends FikiError {}
export class MissingKey extends FikiError {}
export class MissingComponent extends FikiError {}

/** A resolver was supplied and does not know the signature's keyid (`this.i` @6g9zjsv9).
 *
 * Never answered by decoding the keyid as a key instead: a basic transferable prefix embeds its
 * inception key, and reading it would accept a key that has been rotated away.
 */
export class UnknownKey extends FikiError {}

/** The keyid's key state has no single key that satisfies its threshold alone (@2f227n4r).
 *
 * fiki never decides this itself, since it knows nothing of key state: a resolver throws it, and
 * fiki carries it out unchanged, so the refusal keeps its own class rather than becoming
 * UnknownKey.
 */
export class UnsupportedSigner extends FikiError {}

/** An unsigned 401 answered the request (@2f227n4r).
 *
 * A server that refuses a request before it knows which agent it is cannot sign the refusal, so
 * an unsigned 401 is an authentication failure whose body is not to be trusted, rather than a
 * response that is missing its signature.
 */
export class Unauthenticated extends FikiError {}

/* --- something the request carries cannot be read --- */

export class MalformedSignature extends FikiError {}
export class MalformedSignatureInput extends FikiError {}
export class MalformedSignatureLabel extends FikiError {}
export class MalformedSignatureValue extends FikiError {}
export class MalformedKey extends FikiError {}
export class MalformedDigest extends FikiError {}

/* --- fiki understood the request and will not handle it --- */

export class UnsupportedComponent extends FikiError {}

/** The covered list names the same component twice, whatever the order of its parameters. */
export class DuplicateComponent extends FikiError {}

/** The signature verifies, and covers less than the verifier's stated minimum (@7f28p7xk).
 *
 * Includes a message with a body whose `content-digest` is not covered. A signature over too
 * little is refused even when it is valid, because a valid signature over the wrong things is
 * exactly what an intermediary wants.
 */
export class InsufficientCoverage extends FikiError {}
export class UnsupportedAlgorithm extends FikiError {}

/** The request carries a body and the covered set does not include `content-digest`.
 *
 * Raised at signing time rather than warned about, because a verifier has no way to discover
 * after the fact that a body was never covered (@2hwvpm42).
 */
export class UncoveredBody extends FikiError {}

/* --- the request is signed and a stated policy refuses it anyway (@67shl6c5) --- */

export class SignatureExpired extends FikiError {}
export class SignatureTooOld extends FikiError {}

/* --- the request was read, and it does not hold up --- */

export class DigestMismatch extends FikiError {}
export class SignatureMismatch extends FikiError {}
