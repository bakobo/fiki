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

/* --- something the request carries cannot be read --- */

export class MalformedSignature extends FikiError {}
export class MalformedSignatureInput extends FikiError {}
export class MalformedSignatureLabel extends FikiError {}
export class MalformedSignatureValue extends FikiError {}
export class MalformedKey extends FikiError {}
export class MalformedDigest extends FikiError {}

/* --- fiki understood the request and will not handle it --- */

export class UnsupportedComponent extends FikiError {}
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
