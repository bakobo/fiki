//! fiki — sign and verify HTTP requests with a bare Ed25519 key as the identifier.
//!
//! Standard [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html), with one lens: an Ed25519
//! public key is rendered as a non-transferable AID (CESR `Ed25519N`, a 44-character `B…` string),
//! so the identifier is the verifying key and a verifier resolves nothing.
//!
//! That is the default. A caller who speaks the KERI profile of RFC 9421 (`docs/keri-profile.md`)
//! signs requests and responses under a KERI AID instead, and verifies them through a resolver it
//! supplies, against a minimum covered set, with refusals in the profile's section 9 order
//! (`this.i` @7f28p7xk, @6g9zjsv9, @5e2phpjy).
//!
//! See `this.i` @07wstqk7 in <https://github.com/bakobo/fiki> for why this is a library of its own.

/// The conformance contract this port satisfies (`this.i` @4fhrre0m).
///
/// Two artifacts interoperate when their declared vectors format matches, whatever their own
/// version numbers say — so this is the number to compare, not the release. Monotonic, because a
/// conformance contract has no meaningful minor: an implementation either satisfies the vectors or
/// it does not.
pub const VECTORS_FORMAT: u32 = 3;

/// The KERI profile's conformance contract this port satisfies, `vectors/keri/`'s
/// `keri_vectors_format` (`this.i` @8vwrexxc, @4tkkp50h, @5e2phpjy).
///
/// A separate number from [`VECTORS_FORMAT`], because the two sets answer to different authorities
/// and move independently: the shared vectors to fiki's own decisions, these to a profile fiki does
/// not own.
pub const KERI_VECTORS_FORMAT: u32 = 5;

mod base;
#[cfg(test)]
mod corpus_tests;
mod errors;
#[cfg(test)]
mod fuzz_tests;
mod keys;
#[cfg(test)]
mod linear_tests;
mod messages;
mod sfv;

pub use base::{
    req, response_signature_base, signature_base, Request, SignatureParams, CONTENT_DIGEST,
    DEFAULT_COVERED, DERIVED, MAX_FIELD_BYTES, RESPONSE_DERIVED,
};
pub use errors::{Error, Kind, Result};
pub use keys::{to_aid, verifying_key, Key};
pub use messages::{
    content_digest, sign_request, sign_response, verify_request, verify_response, Authorities,
    ExpectedKeyid, MaxAge, Minimum, Resolver, SignOptions, Verdict, VerifyOptions, ALG,
    DEFAULT_MINIMUM, DEFAULT_SKEW, MAX_DICTIONARY_MEMBERS, MAX_INNER_LIST_ITEMS, MAX_PARAMETERS,
    REQUEST_MINIMUM, RESPONSE_MINIMUM,
};
